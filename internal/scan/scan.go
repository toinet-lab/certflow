// Package scan probes TLS endpoints and reports certificate details.
//
// This is Phase 0 of certflow: read-only inventory. It never writes files,
// never handles private keys, and never modifies any remote system. It only
// opens a TLS connection, reads the certificate the server presents, and
// reports on it.
package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

	// Trust and connection details. These describe whether a verifying client
	// would trust the certificate (an axis orthogonal to expiry) and what TLS
	// parameters certflow negotiated. They are computed from the certificate the
	// server presented; the connection itself stays unverified (see Probe).
	Trusted          *bool    `json:"trusted,omitempty"` // nil = undetermined (connection failed)
	UntrustedReasons []string `json:"untrusted_reasons,omitempty"`
	TLSVersion       string   `json:"tls_version,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	ChainLength      int      `json:"chain_length"`

	Error string `json:"error,omitempty"`
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

	// Record the negotiated TLS parameters. NEGOTIATED is the version this
	// single handshake agreed on, not the server's full supported range.
	state := tlsConn.ConnectionState()
	r.TLSVersion = tlsVersionName(state.Version)
	r.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	r.ChainLength = len(certs)

	// Assess trust against the local system root store. This is done on the
	// certificate we already fetched -- the connection stays unverified so that
	// expired/self-signed certs are still inventoried. nil roots => system pool.
	reasons := verifyTrust(leaf, certs, host, nil, time.Now())
	trusted := len(reasons) == 0
	r.Trusted = &trusted
	r.UntrustedReasons = reasons

	return r
}

// verifyTrust reports why a verifying client would not trust leaf, as a
// stable-ordered list of machine-readable reasons. An empty slice means the
// certificate is trusted. Each reason is checked independently rather than
// relying on x509.Verify (which returns only the first error), so overlapping
// problems (e.g. expired and self-signed) are all reported.
//
// roots selects the trust anchors; pass nil to use the system pool. It is a
// parameter so tests can inject a controlled root set.
func verifyTrust(leaf *x509.Certificate, chain []*x509.Certificate, host string, roots *x509.CertPool, now time.Time) []string {
	var reasons []string

	// self_signed: Issuer==Subject is not sufficient on its own (it is trivially
	// forgeable), so also require the certificate's signature to verify against
	// its own public key. We use CheckSignature rather than CheckSignatureFrom:
	// the latter additionally demands the signer be a CA (IsCA + KeyUsageCertSign),
	// but real self-signed *server leaves* are usually not CAs, so it would miss
	// exactly the certs we want to flag. When self-signed we do not additionally
	// report untrusted_chain.
	selfSigned := bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	if selfSigned {
		reasons = append(reasons, "self_signed")
	}

	if now.After(leaf.NotAfter) {
		reasons = append(reasons, "expired")
	}

	if leaf.VerifyHostname(host) != nil {
		reasons = append(reasons, "hostname_mismatch")
	}

	if !selfSigned {
		intermediates := x509.NewCertPool()
		for _, c := range chain[1:] {
			intermediates.AddCert(c)
		}
		// Verify chain reachability only. Hostname and expiry are checked above,
		// so we set CurrentTime inside the leaf's validity window -- otherwise an
		// expired leaf would mask whether the chain reaches a trusted root, which
		// is the distinction chain_length is meant to help the user make.
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   leaf.NotBefore,
		}); err != nil {
			reasons = append(reasons, "untrusted_chain")
		}
	}

	return reasons
}

// tlsVersionName renders a crypto/tls version constant as a short label.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
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
