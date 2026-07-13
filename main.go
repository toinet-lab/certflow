// Command certflow is a read-only TLS certificate inventory tool (Phase 0).
//
// It connects to each target, reads the certificate the server presents, and
// prints when it expires. It never writes to remote systems and never touches
// private keys. Use it to answer: "which certificates do I have, and when do
// they expire?" — the first problem to solve as certificate lifetimes shrink.
//
// Usage:
//
//	certflow example.com example.org:443
//	certflow smtp://mail.example.co.jp imaps://mail.example.co.jp
//	certflow -file hosts.txt -warn 21 -json
//	certflow -file hosts.txt -fail-under 14   # exit code 2 if any cert < 14 days
//
// It speaks STARTTLS for SMTP, IMAP, and POP3, so it can inventory the mail and
// directory certificates that HTTPS-only tools never look at.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/toinet-lab/certflow/scan"
)

// version is overwritten at build time by GoReleaser via -ldflags.
var version = "dev"

func main() {
	var (
		file        = flag.String("file", "", "path to a file with one host:port per line (# lines are ignored)")
		timeout     = flag.Duration("timeout", 10*time.Second, "TLS dial timeout per target")
		warn        = flag.Int("warn", 30, "days-left threshold to mark a certificate as WARN")
		concurrency = flag.Int("concurrency", 20, "number of concurrent probes")
		asJSON      = flag.Bool("json", false, "output results as JSON instead of a table")
		failUnder   = flag.Int("fail-under", 0, "exit with code 2 if any certificate expires within this many days (0 = never fail)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("certflow", version)
		return
	}

	targets, err := gatherTargets(*file, flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets given: use -file <path> or pass host:port arguments")
		flag.Usage()
		os.Exit(1)
	}

	results := probeAll(targets, *timeout, *concurrency)

	// Sort: successes first, then soonest expiry first; errors last.
	sort.Slice(results, func(i, j int) bool {
		iOK, jOK := results[i].Error == "", results[j].Error == ""
		if iOK != jOK {
			return iOK
		}
		return results[i].DaysLeft < results[j].DaysLeft
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	} else {
		printTable(os.Stdout, results, *warn)
		printSummary(os.Stdout, results, *warn)
	}

	if *failUnder > 0 {
		for _, r := range results {
			if r.Error == "" && r.DaysLeft < *failUnder {
				os.Exit(2)
			}
		}
	}
}

// usage prints the standard flag help plus a note on the limits of the
// NEGOTIATED column, which reports only the version this run agreed on.
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintln(out, "\nNote: NEGOTIATED is the TLS version certflow agreed on for this")
	fmt.Fprintln(out, "connection, not the server's full supported range. Go disables")
	fmt.Fprintln(out, "TLS 1.0/1.1 by default, so those are never negotiated here.")
}

// gatherTargets collects targets from CLI args and an optional file, skipping
// blank lines, comments (#), and duplicates.
func gatherTargets(file string, args []string) ([]string, error) {
	seen := map[string]bool{}
	var targets []string

	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			return
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	for _, a := range args {
		add(a)
	}

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	return targets, nil
}

// probeAll runs probes concurrently with a bounded worker pool.
func probeAll(targets []string, timeout time.Duration, concurrency int) []scan.Result {
	if concurrency < 1 {
		concurrency = 1
	}

	jobs := make(chan string)
	out := make(chan scan.Result)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range jobs {
				t, err := scan.ParseTarget(raw)
				if err != nil {
					out <- scan.Result{Target: raw, Error: err.Error()}
					continue
				}
				out <- scan.Probe(context.Background(), t, scan.Options{Timeout: timeout})
			}
		}()
	}

	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var results []scan.Result
	for r := range out {
		results = append(results, r)
	}
	return results
}

func printTable(w io.Writer, results []scan.Result, warn int) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tTRUST\tSERVICE\tNEGOTIATED\tTARGET\tDAYS_LEFT\tNOT_AFTER\tISSUER")
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(tw, "ERROR\t-\t%s\t-\t%s\t-\t-\t%s\n", serviceLabel(r), r.Target, r.Error)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			status(r.DaysLeft, warn),
			trustLabel(r),
			serviceLabel(r),
			r.TLSVersion,
			r.Target,
			r.DaysLeft,
			r.NotAfter.Format("2006-01-02"),
			shorten(r.Issuer, 40),
		)
	}
	tw.Flush()
}

// trustLabel renders the TRUST column: yes when a verifying client would trust
// the certificate, no otherwise. Trusted is only nil on errored results, which
// are handled separately, so nil here defensively renders as no.
func trustLabel(r scan.Result) string {
	if r.Trusted != nil && *r.Trusted {
		return "yes"
	}
	return "no"
}

// printSummary writes a one-line tally of the results, e.g.
//
//	6 targets: 3 OK, 1 WARN, 1 EXPIRED, 1 ERROR
//
// It is meant for cron and monitoring use. Errors are counted before status()
// is consulted, mirroring printTable: an errored result has DaysLeft == 0 and
// would otherwise be miscounted as WARN.
func printSummary(w io.Writer, results []scan.Result, warn int) {
	var ok, warnN, expired, errN int
	for _, r := range results {
		switch {
		case r.Error != "":
			errN++
		case status(r.DaysLeft, warn) == "EXPIRED":
			expired++
		case status(r.DaysLeft, warn) == "WARN":
			warnN++
		default:
			ok++
		}
	}
	fmt.Fprintf(w, "\n%d targets: %d OK, %d WARN, %d EXPIRED, %d ERROR\n",
		len(results), ok, warnN, expired, errN)
}

func status(daysLeft, warn int) string {
	switch {
	case daysLeft < 0:
		return "EXPIRED"
	case daysLeft < warn:
		return "WARN"
	default:
		return "OK"
	}
}

// serviceLabel renders the application protocol. This column is why certflow
// can see mail and directory certificates that HTTPS-only tools miss.
func serviceLabel(r scan.Result) string {
	if r.Service == "" {
		return "tls"
	}
	return string(r.Service)
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 1 {
		return s
	}
	return s[:n-1] + "…"
}
