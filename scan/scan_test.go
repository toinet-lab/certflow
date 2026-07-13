package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		port    int
		service Service
		wantErr bool
	}{
		{in: "example.com", host: "example.com", port: 443, service: ServiceAuto},
		{in: "example.com:8443", host: "example.com", port: 8443, service: ServiceAuto},
		{in: "https://example.com/", host: "example.com", port: 443, service: ServiceTLS},
		{in: "https://example.com:9443/path", host: "example.com", port: 9443, service: ServiceTLS},

		// The whole point of the tool: mail and directory endpoints.
		{in: "smtp://mail.example.co.jp", host: "mail.example.co.jp", port: 587, service: ServiceSMTP},
		{in: "smtps://mail.example.co.jp", host: "mail.example.co.jp", port: 465, service: ServiceTLS},
		{in: "imap://mail.example.co.jp", host: "mail.example.co.jp", port: 143, service: ServiceIMAP},
		{in: "imaps://mail.example.co.jp", host: "mail.example.co.jp", port: 993, service: ServiceTLS},
		{in: "pop3://mail.example.co.jp", host: "mail.example.co.jp", port: 110, service: ServicePOP3},
		{in: "pop3s://mail.example.co.jp", host: "mail.example.co.jp", port: 995, service: ServiceTLS},
		{in: "ldaps://dir.example.co.jp", host: "dir.example.co.jp", port: 636, service: ServiceTLS},

		{in: "smtp://mail.example.co.jp:2525", host: "mail.example.co.jp", port: 2525, service: ServiceSMTP},
		{in: "  example.com  ", host: "example.com", port: 443, service: ServiceAuto},

		{in: "", wantErr: true},
		{in: "gopher://example.com", wantErr: true},
		{in: "example.com:99999", wantErr: true},
		{in: "example.com:abc", wantErr: true},
	}

	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseTarget(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if got.Host != c.host || got.Port != c.port || got.Service != c.service {
			t.Errorf("ParseTarget(%q) = {%s %d %s}, want {%s %d %s}",
				c.in, got.Host, got.Port, got.Service, c.host, c.port, c.service)
		}
	}
}

// A bare host:port must infer the right service from the port, so that
// "certflow mail.example.co.jp:587" does the STARTTLS dance without the user
// having to know to ask for it.
func TestServiceInferredFromPort(t *testing.T) {
	cases := []struct {
		port int
		want Service
	}{
		{25, ServiceSMTP},
		{587, ServiceSMTP},
		{2525, ServiceSMTP},
		{143, ServiceIMAP},
		{110, ServicePOP3},
		{443, ServiceTLS},
		{465, ServiceTLS}, // SMTPS is implicit TLS, not STARTTLS
		{993, ServiceTLS},
		{995, ServiceTLS},
		{636, ServiceTLS}, // LDAPS is implicit TLS
	}
	for _, c := range cases {
		got := Target{Host: "h", Port: c.port}.resolveService()
		if got != c.want {
			t.Errorf("port %d inferred %q, want %q", c.port, got, c.want)
		}
	}
}

// An explicit service must override port inference.
func TestExplicitServiceOverridesPort(t *testing.T) {
	// SMTP on a non-standard port that would otherwise infer implicit TLS.
	got := Target{Host: "h", Port: 10025, Service: ServiceSMTP}.resolveService()
	if got != ServiceSMTP {
		t.Errorf("explicit service was overridden by port inference: got %q", got)
	}
}

// --- STARTTLS negotiation --------------------------------------------------
//
// These drive the negotiation against a fake server, so they test the protocol
// handling itself rather than needing a real mail server.

func TestStartTLSSMTP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		// Greeting.
		_, _ = server.Write([]byte("220 mail.example.co.jp ESMTP Postfix\r\n"))
		// EHLO -> multi-line reply, which is the part that trips naive parsers.
		line, _ := br.ReadString('\n')
		if !strings.HasPrefix(line, "EHLO") {
			t.Errorf("expected EHLO, got %q", line)
		}
		_, _ = server.Write([]byte("250-mail.example.co.jp\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n"))
		// STARTTLS.
		line, _ = br.ReadString('\n')
		if !strings.HasPrefix(line, "STARTTLS") {
			t.Errorf("expected STARTTLS, got %q", line)
		}
		_, _ = server.Write([]byte("220 2.0.0 Ready to start TLS\r\n"))
	}()

	if err := startTLS(client, ServiceSMTP); err != nil {
		t.Fatalf("SMTP STARTTLS negotiation failed: %v", err)
	}
}

// A server that does not offer STARTTLS must produce a clear error, not a hang
// or a confusing TLS handshake failure.
func TestStartTLSSMTPRefused(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		_, _ = server.Write([]byte("220 mail.example.co.jp ESMTP\r\n"))
		_, _ = br.ReadString('\n') // EHLO
		_, _ = server.Write([]byte("250 mail.example.co.jp\r\n"))
		_, _ = br.ReadString('\n') // STARTTLS
		_, _ = server.Write([]byte("502 5.5.1 Command not implemented\r\n"))
	}()

	err := startTLS(client, ServiceSMTP)
	if err == nil {
		t.Fatal("expected an error when the server refuses STARTTLS")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("error should name the failed step, got: %v", err)
	}
}

func TestStartTLSIMAP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		_, _ = server.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n"))
		line, _ := br.ReadString('\n')
		if !strings.Contains(line, "STARTTLS") {
			t.Errorf("expected STARTTLS, got %q", line)
		}
		_, _ = server.Write([]byte("a1 OK Begin TLS negotiation now.\r\n"))
	}()

	if err := startTLS(client, ServiceIMAP); err != nil {
		t.Fatalf("IMAP STARTTLS negotiation failed: %v", err)
	}
}

// IMAP servers may emit untagged (*) responses before the tagged reply.
func TestStartTLSIMAPSkipsUntaggedResponses(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		_, _ = server.Write([]byte("* OK Dovecot ready.\r\n"))
		_, _ = br.ReadString('\n')
		_, _ = server.Write([]byte("* SOMETHING else\r\na1 OK Begin TLS negotiation now.\r\n"))
	}()

	if err := startTLS(client, ServiceIMAP); err != nil {
		t.Fatalf("should have skipped the untagged response: %v", err)
	}
}

func TestStartTLSPOP3(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		_, _ = server.Write([]byte("+OK Dovecot ready.\r\n"))
		line, _ := br.ReadString('\n')
		if !strings.HasPrefix(line, "STLS") {
			t.Errorf("POP3 uses STLS, not STARTTLS; got %q", line)
		}
		_, _ = server.Write([]byte("+OK Begin TLS negotiation.\r\n"))
	}()

	if err := startTLS(client, ServicePOP3); err != nil {
		t.Fatalf("POP3 STLS negotiation failed: %v", err)
	}
}

// Implicit-TLS services must not send anything before the handshake.
func TestStartTLSIsNoOpForImplicitTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- startTLS(client, ServiceTLS) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("implicit TLS should be a no-op, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startTLS blocked for an implicit-TLS service — it must not read or write")
	}
}

// --- Trust evaluation -------------------------------------------------------

// The core claim of the tool: a self-signed certificate is inventoried
// successfully (we can still connect and read it), reported as valid on expiry,
// and reported as NOT trusted. Those are separate axes.
func TestSelfSignedIsScannableButUntrusted(t *testing.T) {
	srv := newTestTLSServer(t)
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr().String())
	target := Target{Host: host, Port: atoi(portStr), Service: ServiceTLS, SNIName: "test.example.co.jp"}

	r := Probe(context.Background(), target, Options{Timeout: 5 * time.Second})

	if r.Error != "" {
		t.Fatalf("a self-signed cert must still be scannable; got error: %s", r.Error)
	}
	if !r.SelfSigned {
		t.Error("SelfSigned should be true")
	}
	if r.Trusted == nil {
		t.Fatal("Trusted must not be nil when the connection succeeded")
	}
	if *r.Trusted {
		t.Error("a self-signed certificate must not be trusted")
	}
	if !contains(r.UntrustedReasons, "self_signed") {
		t.Errorf("expected reason self_signed, got %v", r.UntrustedReasons)
	}
	if r.Fingerprint == "" || len(r.Fingerprint) != 64 {
		t.Errorf("expected a 64-char SHA-256 fingerprint, got %q", r.Fingerprint)
	}
	if len(r.DER) == 0 {
		t.Error("DER should be populated for library callers")
	}
	if r.PublicKeyAlgorithm == "" {
		t.Error("PublicKeyAlgorithm should be populated")
	}
}

// An unreachable host must leave Trusted nil — "undetermined", not "untrusted".
// Reporting a down host as a TLS trust failure would be a false alarm.
func TestUnreachableLeavesTrustUndetermined(t *testing.T) {
	// Port 1 on localhost: reliably refused, no DNS needed.
	r := Probe(context.Background(),
		Target{Host: "127.0.0.1", Port: 1, Service: ServiceTLS},
		Options{Timeout: 2 * time.Second})

	if r.Error == "" {
		t.Fatal("expected a connection error")
	}
	if r.Trusted != nil {
		t.Error("Trusted must be nil (undetermined) when the connection fails, not false")
	}
}

func TestIsSelfSignedRequiresSignatureCheck(t *testing.T) {
	// A real self-signed cert: Issuer == Subject AND the signature verifies.
	cert := testCert(t)
	if !isSelfSigned(cert) {
		t.Error("a genuinely self-signed certificate should be detected")
	}
}

// --- helpers ----------------------------------------------------------------

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// newTestTLSServer starts a TLS listener with a self-signed certificate.
func newTestTLSServer(t *testing.T) net.Listener {
	t.Helper()

	cert := testTLSCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}()
		}
	}()
	return ln
}

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	tc := testTLSCert(t)
	c, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}
