package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/toinet-lab/certflow/scan"
)

func boolPtr(b bool) *bool { return &b }

func TestPrintTable(t *testing.T) {
	notAfter := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	results := []scan.Result{
		{
			Target: "good.example.com", DaysLeft: 90, NotAfter: notAfter,
			Issuer: "CN=Test CA", Subject: "CN=good.example.com",
			Trusted: boolPtr(true), TLSVersion: "TLS1.3",
		},
		{
			// A mail server with a self-signed certificate: in date, but trusted
			// by nothing. This is the case certflow exists to surface.
			Target: "mail.example.co.jp:587", DaysLeft: 5, NotAfter: notAfter,
			Service: scan.ServiceSMTP,
			Issuer:  "CN=mail.example.co.jp", Subject: "CN=mail.example.co.jp",
			Trusted: boolPtr(false), UntrustedReasons: []string{"self_signed"}, TLSVersion: "TLS1.2",
		},
		{Target: "dead.example.com", Error: "connection refused"},
	}

	var buf bytes.Buffer
	printTable(&buf, results, 30)
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	header := lines[0]
	for _, col := range []string{"STATUS", "TRUST", "SERVICE", "NEGOTIATED", "TARGET", "DAYS_LEFT", "NOT_AFTER", "ISSUER"} {
		if !strings.Contains(header, col) {
			t.Errorf("header missing column %q: %q", col, header)
		}
	}
	if strings.Contains(header, "SUBJECT") {
		t.Errorf("header should not contain SUBJECT: %q", header)
	}

	// SUBJECT values must not leak into the table body.
	if strings.Contains(out, "CN=good.example.com") {
		t.Errorf("table should not render SUBJECT, got:\n%s", out)
	}

	// Columns: STATUS TRUST SERVICE NEGOTIATED TARGET DAYS_LEFT NOT_AFTER ISSUER
	if f := strings.Fields(lines[1]); f[0] != "OK" || f[1] != "yes" || f[2] != "tls" || f[3] != "TLS1.3" {
		t.Errorf("good row = %v, want STATUS=OK TRUST=yes SERVICE=tls NEGOTIATED=TLS1.3", f)
	}
	if f := strings.Fields(lines[2]); f[0] != "WARN" || f[1] != "no" || f[2] != "smtp" || f[3] != "TLS1.2" {
		t.Errorf("bad row = %v, want STATUS=WARN TRUST=no SERVICE=smtp NEGOTIATED=TLS1.2", f)
	}
	if f := strings.Fields(lines[3]); f[0] != "ERROR" || f[1] != "-" || f[3] != "-" {
		t.Errorf("error row = %v, want STATUS=ERROR TRUST=- NEGOTIATED=-", f)
	}
}

func TestPrintSummary(t *testing.T) {
	tests := []struct {
		name    string
		results []scan.Result
		warn    int
		want    string
	}{
		{
			name: "all ok",
			results: []scan.Result{
				{Target: "a", DaysLeft: 90},
				{Target: "b", DaysLeft: 40},
			},
			warn: 30,
			want: "\n2 targets: 2 OK, 0 WARN, 0 EXPIRED, 0 ERROR\n",
		},
		{
			name: "mixed",
			results: []scan.Result{
				{Target: "ok", DaysLeft: 90},
				{Target: "warn", DaysLeft: 10},
				{Target: "expired", DaysLeft: -3},
				{Target: "err", Error: "connection refused"},
			},
			warn: 30,
			want: "\n4 targets: 1 OK, 1 WARN, 1 EXPIRED, 1 ERROR\n",
		},
		{
			name: "all errors count as ERROR not WARN despite DaysLeft 0",
			results: []scan.Result{
				{Target: "a", Error: "no route to host"},
				{Target: "b", Error: "timeout"},
			},
			warn: 30,
			want: "\n2 targets: 0 OK, 0 WARN, 0 EXPIRED, 2 ERROR\n",
		},
		{
			name:    "single",
			results: []scan.Result{{Target: "only", DaysLeft: 5}},
			warn:    30,
			want:    "\n1 targets: 0 OK, 1 WARN, 0 EXPIRED, 0 ERROR\n",
		},
		{
			name:    "daysleft zero is WARN",
			results: []scan.Result{{Target: "edge", DaysLeft: 0}},
			warn:    30,
			want:    "\n1 targets: 0 OK, 1 WARN, 0 EXPIRED, 0 ERROR\n",
		},
		{
			name: "warn zero: non-negative days are OK",
			results: []scan.Result{
				{Target: "zero", DaysLeft: 0},
				{Target: "neg", DaysLeft: -1},
			},
			warn: 0,
			want: "\n2 targets: 1 OK, 0 WARN, 1 EXPIRED, 0 ERROR\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printSummary(&buf, tt.results, tt.warn)
			if got := buf.String(); got != tt.want {
				t.Errorf("printSummary()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// Inline comments (a '#' after the target on the same line) must be stripped, so
// that "host:25   # note" parses as host:25 and not as a token with a broken
// port. hosts.example.txt is written this way, so this is what makes the shipped
// example actually work.
func TestGatherTargetsStripsInlineComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := `# a whole-line comment
example.co.jp
mail.example.co.jp:25              # SMTP relay, STARTTLS
smtp://smtp.example.co.jp:587      # submission

   # indented comment
example.co.jp                      # duplicate, different trailing comment
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := gatherTargets(path, nil)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"example.co.jp",
		"mail.example.co.jp:25",
		"smtp://smtp.example.co.jp:587",
	}
	if len(targets) != len(want) {
		t.Fatalf("gatherTargets = %v, want %v", targets, want)
	}
	for i, w := range want {
		if targets[i] != w {
			t.Errorf("target[%d] = %q, want %q", i, targets[i], w)
		}
	}

	// Every gathered target must actually parse — the whole point of the fix.
	for _, tg := range targets {
		if _, err := scan.ParseTarget(tg); err != nil {
			t.Errorf("ParseTarget(%q): %v", tg, err)
		}
	}
}

// The shipped example file must work as-is: a first-time user copies it to
// hosts.txt and runs certflow. Every non-comment line has to parse.
func TestShippedHostsExampleParses(t *testing.T) {
	targets, err := gatherTargets("hosts.example.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("hosts.example.txt yielded no targets")
	}
	for _, tg := range targets {
		if _, err := scan.ParseTarget(tg); err != nil {
			t.Errorf("hosts.example.txt line %q does not parse: %v", tg, err)
		}
	}
}
