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
//	certflow -file hosts.txt
//	certflow -file hosts.txt -warn 21 -json
//	certflow -file hosts.txt -fail-under 14   # exit code 2 if any cert < 14 days
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

	"github.com/toinet-lab/certflow/internal/scan"
)

func main() {
	var (
		file        = flag.String("file", "", "path to a file with one host:port per line (# lines are ignored)")
		timeout     = flag.Duration("timeout", 10*time.Second, "TLS dial timeout per target")
		warn        = flag.Int("warn", 30, "days-left threshold to mark a certificate as WARN")
		concurrency = flag.Int("concurrency", 20, "number of concurrent probes")
		asJSON      = flag.Bool("json", false, "output results as JSON instead of a table")
		failUnder   = flag.Int("fail-under", 0, "exit with code 2 if any certificate expires within this many days (0 = never fail)")
	)
	flag.Parse()

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
	}

	if *failUnder > 0 {
		for _, r := range results {
			if r.Error == "" && r.DaysLeft < *failUnder {
				os.Exit(2)
			}
		}
	}
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
			for t := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
				out <- scan.Probe(ctx, t, timeout)
				cancel()
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
	fmt.Fprintln(tw, "STATUS\tTARGET\tDAYS_LEFT\tNOT_AFTER\tISSUER\tSUBJECT")
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(tw, "ERROR\t%s\t-\t-\t-\t%s\n", r.Target, r.Error)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n",
			status(r.DaysLeft, warn),
			r.Target,
			r.DaysLeft,
			r.NotAfter.Format("2006-01-02"),
			shorten(r.Issuer, 40),
			shorten(r.Subject, 40),
		)
	}
	tw.Flush()
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

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 1 {
		return s
	}
	return s[:n-1] + "…"
}
