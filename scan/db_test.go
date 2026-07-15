package scan

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// --- PostgreSQL -------------------------------------------------------------

// The SSLRequest is a fixed 8-byte message; getting a byte wrong means no
// PostgreSQL server will ever switch to TLS. Pin the exact bytes.
func TestPostgresSSLRequestBytes(t *testing.T) {
	want := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	if got := pgSSLRequest(); !bytes.Equal(got, want) {
		t.Errorf("pgSSLRequest() = % x, want % x", got, want)
	}
}

func TestStartTLSPostgresAccepted(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		var req [8]byte
		if _, err := io.ReadFull(server, req[:]); err != nil {
			t.Errorf("reading SSLRequest: %v", err)
			return
		}
		if !bytes.Equal(req[:], pgSSLRequest()) {
			t.Errorf("client sent % x, want % x", req[:], pgSSLRequest())
		}
		_, _ = server.Write([]byte{'S'})
		// Stay silent afterwards: a well-behaved server waits for the ClientHello.
	}()

	if err := startTLS(client, ServicePostgres); err != nil {
		t.Fatalf("PostgreSQL SSLRequest negotiation failed: %v", err)
	}
}

// 'N' means the server has TLS disabled — a determinate answer, reported with a
// clear message rather than a confusing handshake failure.
func TestStartTLSPostgresDeclined(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		var req [8]byte
		_, _ = io.ReadFull(server, req[:])
		_, _ = server.Write([]byte{'N'})
	}()

	err := startTLS(client, ServicePostgres)
	if err == nil {
		t.Fatal("expected an error when the server declines TLS")
	}
	if !strings.Contains(err.Error(), "does not support TLS") {
		t.Errorf("error should say TLS is unsupported, got: %v", err)
	}
}

// An 'E' (ErrorResponse) reply from a pre-3.0 server must be a clear error.
func TestStartTLSPostgresErrorReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		var req [8]byte
		_, _ = io.ReadFull(server, req[:])
		_, _ = server.Write([]byte{'E'})
	}()

	if err := startTLS(client, ServicePostgres); err == nil {
		t.Fatal("expected an error for an 'E' reply")
	}
}

// The buffer-stuffing defence (CVE-2021-23222): a server (or man-in-the-middle)
// that sends bytes after 'S', before the TLS handshake, must be detected and the
// probe aborted — those bytes would otherwise be smuggled into the TLS layer.
func TestStartTLSPostgresRejectsBufferStuffing(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		var req [8]byte
		_, _ = io.ReadFull(server, req[:])
		// 'S' immediately followed by stuffed plaintext.
		_, _ = server.Write([]byte{'S'})
		_, _ = server.Write([]byte("injected"))
	}()

	err := startTLS(client, ServicePostgres)
	if err == nil {
		t.Fatal("expected an error when extra bytes follow 'S' (buffer-stuffing)")
	}
	if !strings.Contains(err.Error(), "buffer-stuffing") {
		t.Errorf("error should flag buffer-stuffing, got: %v", err)
	}
}

// A quiet socket after 'S' must NOT be mistaken for stuffing.
func TestAssertNoPendingBytesAllowsQuietSocket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- assertNoPendingBytes(client) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a quiet socket must pass the pending-bytes check, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("assertNoPendingBytes blocked far longer than its own deadline")
	}
}
