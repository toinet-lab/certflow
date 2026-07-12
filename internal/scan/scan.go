// Package scan probes TLS endpoints and reports certificate details.
//
// This is Phase 0 of certflow: read-only inventory. It never writes files,
// never handles private keys, and never modifies any remote system. It only
// opens a TLS connection, reads the certificate the server presents, and
// reports on it.
package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Result holds the certificate inventory data for a single endpoint.
type Result struct {
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	Port      string    `json:"port"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	SANs      []string  `json:"sans"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
	Serial    string    `json:"serial"`
	Error     string    `json:"error,omitempty"`
}

// Probe connects to target over TLS and returns the leaf certificate details.
//
// Verification is intentionally skipped so that expired, self-signed, or
// hostname-mismatched certificates can still be inventoried. We only inspect
// what the server presents; we never trust or act on it.
func Probe(ctx context.Context, target string, timeout time.Duration) Result {
	r := Result{Target: target}

	host, port, err := splitHostPort(target)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Host, r.Port = host, port

	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			// INTENTIONAL, and central to what this tool does.
			//
			// certflow INSPECTS certificates; it never TRUSTS them. Verification
			// must be disabled in order to inventory expired, self-signed, and
			// hostname-mismatched certificates -- which is precisely the problem
			// the tool exists to solve. Enabling verification here would make the
			// connection fail on exactly the certificates the operator most needs
			// to find.
			//
			// This is safe because the connection is read-only: we read the leaf
			// certificate the server presents, report on it, and close. Nothing is
			// sent, nothing is trusted, no action is taken on the connection.
			//
			// DO NOT copy this pattern into any code that trusts or acts on a
			// connection (e.g. Phase 1 ACME issuance). See AGENTS.md.
			InsecureSkipVerify: true, //nolint:gosec // G402: see comment above
			ServerName:         host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		r.Error = "unexpected non-TLS connection"
		return r
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		r.Error = "no certificate presented"
		return r
	}

	leaf := certs[0]
	r.Subject = leaf.Subject.String()
	r.Issuer = leaf.Issuer.String()
	r.NotBefore = leaf.NotBefore
	r.NotAfter = leaf.NotAfter
	r.Serial = leaf.SerialNumber.String()
	r.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)

	sans := append([]string{}, leaf.DNSNames...)
	sort.Strings(sans)
	r.SANs = sans

	return r
}

// splitHostPort normalises a target into host and port, defaulting to 443.
// It tolerates an optional https:// / http:// scheme and a trailing slash.
func splitHostPort(target string) (host, port string, err error) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	if target == "" {
		return "", "", fmt.Errorf("empty target")
	}

	// No colon at all -> host only, default port 443.
	if !strings.Contains(target, ":") {
		return target, "443", nil
	}

	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return "", "", fmt.Errorf("invalid target %q: %w", target, err)
	}
	return h, p, nil
}
