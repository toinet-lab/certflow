// Package scan probes TLS endpoints and reports on the certificate they serve.
//
// It is read-only: it opens a connection, reads the certificate the server
// presents, evaluates it, and closes. It never writes to a remote system and
// never handles private keys.
//
// # Not just HTTPS
//
// Most certificate tooling only looks at HTTPS. This package also speaks the
// STARTTLS negotiation used by SMTP, IMAP, and POP3, because a mail server with
// an expired certificate does not show a browser warning — it just stops
// delivering mail. Those are the certificates that go unnoticed.
//
// # A deliberate InsecureSkipVerify
//
// The connection is made WITHOUT certificate verification. This is not an
// oversight and must not be "fixed". Verification on the dial would make it
// impossible to connect to — and therefore to inventory — the expired,
// self-signed, and hostname-mismatched certificates that an operator most needs
// to find. Verification is performed separately, on the certificate we
// retrieved (see Result.Trusted). Nothing is sent over the connection and no
// action is taken on it.
//
// Do not copy this pattern into code that trusts or acts on a connection.
package scan

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Service is the application protocol spoken at an endpoint. It determines
// whether TLS starts immediately or must be negotiated first.
type Service string

const (
	// ServiceAuto infers the service from the port number.
	ServiceAuto Service = ""

	// ServiceTLS is implicit TLS: the handshake begins immediately. This covers
	// HTTPS (443), SMTPS (465), IMAPS (993), POP3S (995), and LDAPS (636).
	ServiceTLS Service = "tls"

	// ServiceSMTP is SMTP with STARTTLS (25, 587).
	ServiceSMTP Service = "smtp"

	// ServiceIMAP is IMAP with STARTTLS (143).
	ServiceIMAP Service = "imap"

	// ServicePOP3 is POP3 with STLS (110).
	ServicePOP3 Service = "pop3"
)

// Target is an endpoint to probe.
type Target struct {
	Host    string
	Port    int
	Service Service

	// SNIName overrides the name sent in SNI. Needed when scanning by IP but the
	// server selects its certificate by hostname.
	SNIName string
}

func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// resolveService returns the concrete service, inferring from the port when the
// caller left it as ServiceAuto.
func (t Target) resolveService() Service {
	if t.Service != ServiceAuto {
		return t.Service
	}
	switch t.Port {
	case 25, 587, 2525:
		return ServiceSMTP
	case 143:
		return ServiceIMAP
	case 110:
		return ServicePOP3
	default:
		// 443, 465, 636, 993, 995 and anything else: assume implicit TLS.
		return ServiceTLS
	}
}

// serverName is the name to use for SNI and hostname verification.
func (t Target) serverName() string {
	if t.SNIName != "" {
		return t.SNIName
	}
	return t.Host
}

// Result is what one probe found.
type Result struct {
	Target  string  `json:"target"`
	Host    string  `json:"host"`
	Port    int     `json:"port"`
	Service Service `json:"service"`

	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	SANs      []string  `json:"sans"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
	Serial    string    `json:"serial"`

	// Fingerprint is the SHA-256 of the leaf's DER encoding, lowercase hex.
	// It is the natural identity of a certificate: the same certificate deployed
	// on many hosts produces the same fingerprint, which is how you answer
	// "which of my servers share this certificate?".
	Fingerprint string `json:"fingerprint"`

	// Trusted reports whether a verifying client would accept this certificate.
	// This is ORTHOGONAL to expiry: a certificate can be well within its validity
	// window and still untrusted (self-signed).
	//
	// nil means UNDETERMINED — the connection failed, so no judgement was made.
	// That is different from false ("we looked, and it is not trusted").
	// Collapsing the two would report a host that is simply down as a TLS trust
	// failure.
	Trusted          *bool    `json:"trusted,omitempty"`
	UntrustedReasons []string `json:"untrusted_reasons,omitempty"`

	// SelfSigned means Issuer == Subject AND the signature verifies against the
	// certificate's own public key. The string comparison alone is forgeable, so
	// the signature check is required.
	SelfSigned bool `json:"self_signed"`

	// Wildcard is true when any SAN begins with "*.".
	Wildcard bool `json:"wildcard"`

	// Key and signature details, for quality checks (weak keys, weak hashes).
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	PublicKeyBits      int    `json:"public_key_bits,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	// TLSVersion and CipherSuite are what WE negotiated — NOT the full range the
	// server supports. A server reported as TLS1.3 may also accept TLS1.0. Do not
	// present these as a security assessment of the server.
	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`

	// ChainLength is how many certificates the server presented. A length of 1
	// for a publicly-issued certificate usually means a missing intermediate.
	ChainLength int `json:"chain_length"`

	// DER is the raw leaf certificate. Not serialised to JSON (it would bloat the
	// output), but available to library callers that want to store or re-parse it.
	DER []byte `json:"-"`

	// Intermediates holds the intermediate certificates the server presented: the
	// chain minus the leaf, each as raw DER, in the order the server sent them.
	// certflow reports the wire fact and does not reorder or normalise. The leaf
	// is in DER and is deliberately NOT repeated here, so "intermediates only" is
	// literally what this holds. nil (length 0) when the server sent only a leaf
	// (ChainLength == 1).
	//
	// Provided for library callers such as certmgr, whose OCSP path needs the
	// issuer (intermediate CA) certificate. Like DER, it is not serialised to
	// JSON — raw certificate bytes would bloat the output and no JSON consumer
	// wants them.
	Intermediates [][]byte `json:"-"`

	Error string `json:"error,omitempty"`
}

// Options tunes a probe.
type Options struct {
	// Timeout applies to the whole probe: dial, STARTTLS negotiation, handshake.
	Timeout time.Duration

	// Roots is the trust anchor set used to decide Result.Trusted. nil means the
	// system pool. Set this to check against a private CA.
	Roots *x509.CertPool
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 10 * time.Second
	}
	return o.Timeout
}

// ParseTarget parses a target string.
//
// Accepted forms:
//
//	example.com                 → :443, implicit TLS
//	example.com:8443            → :8443, implicit TLS
//	mail.example.com:587        → :587, SMTP STARTTLS (inferred from the port)
//	smtp://mail.example.com     → :587, SMTP STARTTLS
//	imap://mail.example.com     → :143, IMAP STARTTLS
//	pop3://mail.example.com     → :110, POP3 STLS
//	smtps://mail.example.com    → :465, implicit TLS
//	imaps://mail.example.com    → :993, implicit TLS
//	pop3s://mail.example.com    → :995, implicit TLS
//	ldaps://dir.example.com     → :636, implicit TLS
//	https://example.com/        → :443, implicit TLS
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	var (
		service     = ServiceAuto
		defaultPort = 443
	)

	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(s[:i])
		s = s[i+3:]

		switch scheme {
		case "http", "https":
			service, defaultPort = ServiceTLS, 443
		case "smtp":
			service, defaultPort = ServiceSMTP, 587
		case "smtps":
			service, defaultPort = ServiceTLS, 465
		case "imap":
			service, defaultPort = ServiceIMAP, 143
		case "imaps":
			service, defaultPort = ServiceTLS, 993
		case "pop3":
			service, defaultPort = ServicePOP3, 110
		case "pop3s":
			service, defaultPort = ServiceTLS, 995
		case "ldaps":
			service, defaultPort = ServiceTLS, 636
		default:
			return Target{}, fmt.Errorf("unknown scheme %q", scheme)
		}
	}

	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Trim again: cutting a path/query/fragment can leave trailing whitespace,
	// e.g. "host:25   # comment" -> "host:25   ", whose spaces would otherwise be
	// taken as part of the port ("invalid port") or the host ("host:443" with a
	// trailing-space host that silently "succeeds").
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty host")
	}

	host, port := s, defaultPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, convErr := strconv.Atoi(p)
		if convErr != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("invalid port in %q", s)
		}
		host, port = h, n
	} else if strings.Count(s, ":") > 0 && !strings.Contains(s, "]") {
		// A bare IPv6 address has multiple colons and no brackets; anything else
		// with a colon that failed SplitHostPort is malformed.
		if ip := net.ParseIP(s); ip == nil {
			return Target{}, fmt.Errorf("invalid target %q", s)
		}
	}

	if host == "" {
		return Target{}, fmt.Errorf("empty host in %q", s)
	}
	return Target{Host: host, Port: port, Service: service}, nil
}

// Probe connects to the target, retrieves the certificate it serves, and
// evaluates it.
func Probe(ctx context.Context, t Target, opts Options) Result {
	svc := t.resolveService()
	r := Result{
		Target:  t.String(),
		Host:    t.Host,
		Port:    t.Port,
		Service: svc,
	}

	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.String())
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer rawConn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
	}

	// For STARTTLS services, talk the plaintext protocol until the server agrees
	// to switch. For implicit-TLS services this is a no-op.
	if err := startTLS(rawConn, svc); err != nil {
		r.Error = fmt.Sprintf("starttls (%s): %v", svc, err)
		return r
	}

	// See the package doc: verification is deliberately off HERE, and performed
	// on the retrieved certificate below.
	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: intentional; see package doc
		ServerName:         t.serverName(),
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		r.Error = err.Error()
		return r
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		r.Error = "no certificate presented"
		return r
	}

	populate(&r, state, t, opts)
	return r
}

// populate fills a Result from a completed handshake.
func populate(r *Result, state tls.ConnectionState, t Target, opts Options) {
	certs := state.PeerCertificates
	leaf := certs[0]

	r.TLSVersion = tlsVersionName(state.Version)
	r.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	r.ChainLength = len(certs)

	sum := sha256.Sum256(leaf.Raw)
	r.Fingerprint = hex.EncodeToString(sum[:])
	r.DER = leaf.Raw

	// Intermediates: the chain minus the leaf, in wire order, DER as sent. The
	// leaf lives in DER; we do not repeat it here.
	if len(certs) > 1 {
		ints := make([][]byte, 0, len(certs)-1)
		for _, c := range certs[1:] {
			ints = append(ints, c.Raw)
		}
		r.Intermediates = ints
	}

	r.Subject = leaf.Subject.String()
	r.Issuer = leaf.Issuer.String()
	r.NotBefore = leaf.NotBefore
	r.NotAfter = leaf.NotAfter
	r.Serial = leaf.SerialNumber.String()
	r.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	r.SignatureAlgorithm = leaf.SignatureAlgorithm.String()

	sans := append([]string{}, leaf.DNSNames...)
	sort.Strings(sans)
	r.SANs = sans
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			r.Wildcard = true
			break
		}
	}

	r.PublicKeyAlgorithm, r.PublicKeyBits = keyInfo(leaf)
	r.SelfSigned = isSelfSigned(leaf)

	trusted, reasons := evaluateTrust(leaf, certs[1:], t, opts, r.SelfSigned)
	r.Trusted = &trusted
	r.UntrustedReasons = reasons
}

// isSelfSigned reports whether the certificate signed itself.
//
// Issuer == Subject is NOT sufficient — those fields are attacker-controlled
// and trivially forged. The signature must actually verify against the
// certificate's own public key.
func isSelfSigned(c *x509.Certificate) bool {
	if c.Issuer.String() != c.Subject.String() {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

// evaluateTrust decides whether a verifying client would accept this
// certificate, and if not, why.
func evaluateTrust(leaf *x509.Certificate, intermediates []*x509.Certificate, t Target, opts Options, selfSigned bool) (bool, []string) {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       t.serverName(),
		Roots:         opts.Roots, // nil = system pool
		Intermediates: pool,
	})
	if err == nil {
		return true, nil
	}

	var reasons []string
	switch {
	case selfSigned:
		reasons = append(reasons, "self_signed")
	default:
		var unknown x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		var hostErr x509.HostnameError

		switch {
		case asErr(err, &hostErr):
			reasons = append(reasons, "hostname_mismatch")
		case asErr(err, &unknown):
			// We cannot reliably distinguish "the chain is incomplete" from "the
			// root is genuinely unknown" without fetching AIA URLs — which we do
			// not do, because following URLs embedded in a scanned certificate is
			// an SSRF risk and outside a read-only tool's remit. Report the honest,
			// combined fact.
			reasons = append(reasons, "untrusted_chain")
		case asErr(err, &invalid):
			if invalid.Reason == x509.Expired {
				reasons = append(reasons, "expired")
			} else {
				reasons = append(reasons, "invalid")
			}
		default:
			reasons = append(reasons, "untrusted")
		}
	}

	// Expiry is worth reporting even when another reason already fired.
	if time.Now().After(leaf.NotAfter) && !contains(reasons, "expired") {
		reasons = append(reasons, "expired")
	}
	return false, reasons
}

func keyInfo(c *x509.Certificate) (algorithm string, bits int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return c.PublicKeyAlgorithm.String(), 0
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// asErr is errors.As, kept local to avoid importing errors just for one call
// while remaining explicit about intent.
func asErr(err error, target any) bool {
	switch t := target.(type) {
	case *x509.UnknownAuthorityError:
		if e, ok := err.(x509.UnknownAuthorityError); ok {
			*t = e
			return true
		}
	case *x509.CertificateInvalidError:
		if e, ok := err.(x509.CertificateInvalidError); ok {
			*t = e
			return true
		}
	case *x509.HostnameError:
		if e, ok := err.(x509.HostnameError); ok {
			*t = e
			return true
		}
	}
	return false
}

// --- STARTTLS ---------------------------------------------------------------

// startTLS performs the plaintext negotiation that must precede the TLS
// handshake for SMTP, IMAP, and POP3. For implicit-TLS services it does nothing.
//
// This is the part almost no certificate tool implements, and it is why mail and
// directory certificates go unmonitored.
func startTLS(conn net.Conn, svc Service) error {
	switch svc {
	case ServiceSMTP:
		return startTLSSMTP(conn)
	case ServiceIMAP:
		return startTLSIMAP(conn)
	case ServicePOP3:
		return startTLSPOP3(conn)
	default:
		return nil // implicit TLS: handshake starts immediately
	}
}

// startTLSSMTP: read the greeting, EHLO, then STARTTLS.
//
//	S: 220 mail.example.co.jp ESMTP
//	C: EHLO certflow
//	S: 250-mail.example.co.jp
//	S: 250 STARTTLS
//	C: STARTTLS
//	S: 220 Ready to start TLS
func startTLSSMTP(conn net.Conn) error {
	br := bufio.NewReader(conn)

	if err := expectSMTP(br, "220"); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "EHLO certflow\r\n"); err != nil {
		return err
	}
	if err := expectSMTP(br, "250"); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if err := expectSMTP(br, "220"); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}
	return nil
}

// expectSMTP reads an SMTP reply, handling multi-line replies ("250-" continues,
// "250 " ends), and checks the status code.
func expectSMTP(br *bufio.Reader, want string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return fmt.Errorf("malformed reply %q", line)
		}
		code := line[:3]
		if code != want {
			return fmt.Errorf("got %q, want %s", line, want)
		}
		// A hyphen after the code means more lines follow.
		if len(line) > 3 && line[3] == '-' {
			continue
		}
		return nil
	}
}

// startTLSIMAP: read the greeting, then issue a tagged STARTTLS.
//
//	S: * OK IMAP4rev1 ready
//	C: a1 STARTTLS
//	S: a1 OK Begin TLS negotiation now
func startTLSIMAP(conn net.Conn) error {
	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if !strings.HasPrefix(line, "* OK") {
		return fmt.Errorf("greeting: %q", strings.TrimSpace(line))
	}

	if _, err := fmt.Fprintf(conn, "a1 STARTTLS\r\n"); err != nil {
		return err
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			continue // untagged response; keep reading
		}
		if strings.HasPrefix(line, "a1 OK") {
			return nil
		}
		return fmt.Errorf("STARTTLS: %q", line)
	}
}

// startTLSPOP3: read the greeting, then STLS (POP3's name for STARTTLS).
//
//	S: +OK POP3 ready
//	C: STLS
//	S: +OK Begin TLS negotiation
func startTLSPOP3(conn net.Conn) error {
	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("greeting: %q", strings.TrimSpace(line))
	}

	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return err
	}
	line, err = br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("STLS: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("STLS: %q", strings.TrimSpace(line))
	}
	return nil
}
