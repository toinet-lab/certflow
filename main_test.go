package main

import (
	"bytes"
	"testing"

	"github.com/toinet-lab/certflow/internal/scan"
)

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
