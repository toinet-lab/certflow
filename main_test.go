package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/toinet-lab/certflow/internal/scan"
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
			Target: "bad.example.com", DaysLeft: 5, NotAfter: notAfter,
			Issuer: "CN=bad.example.com", Subject: "CN=bad.example.com",
			Trusted: boolPtr(false), UntrustedReasons: []string{"self_signed"}, TLSVersion: "TLS1.2",
		},
		{Target: "dead.example.com", Error: "connection refused"},
	}

	var buf bytes.Buffer
	printTable(&buf, results, 30)
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	header := lines[0]
	for _, col := range []string{"STATUS", "TRUST", "NEGOTIATED", "TARGET", "DAYS_LEFT", "NOT_AFTER", "ISSUER"} {
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

	if fields := strings.Fields(lines[1]); fields[0] != "OK" || fields[1] != "yes" || fields[2] != "TLS1.3" {
		t.Errorf("good row = %v, want STATUS=OK TRUST=yes NEGOTIATED=TLS1.3", fields)
	}
	if fields := strings.Fields(lines[2]); fields[0] != "WARN" || fields[1] != "no" || fields[2] != "TLS1.2" {
		t.Errorf("bad row = %v, want STATUS=WARN TRUST=no NEGOTIATED=TLS1.2", fields)
	}
	if fields := strings.Fields(lines[3]); fields[0] != "ERROR" || fields[1] != "-" || fields[2] != "-" {
		t.Errorf("error row = %v, want STATUS=ERROR TRUST=- NEGOTIATED=-", fields)
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
