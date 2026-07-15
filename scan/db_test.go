package scan

import (
	"bytes"
	"encoding/binary"
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

// --- MySQL / MariaDB --------------------------------------------------------

// buildTestHandshake assembles a HandshakeV10 payload with the given capability
// flags and server version, exercising the split capability layout (lower 16
// bits before the charset/status fields, upper 16 bits after).
func buildTestHandshake(caps uint32, version string) []byte {
	var b []byte
	b = append(b, 0x0A) // protocol version 10
	b = append(b, version...)
	b = append(b, 0x00)                                          // NUL terminator
	b = append(b, 0, 0, 0, 0)                                    // connection id
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)                        // auth-plugin-data part 1
	b = append(b, 0x00)                                          // filler
	b = binary.LittleEndian.AppendUint16(b, uint16(caps&0xFFFF)) // capability_flags_1
	b = append(b, 0x21)                                          // character set
	b = append(b, 0x00, 0x00)                                    // status flags
	b = binary.LittleEndian.AppendUint16(b, uint16(caps>>16))    // capability_flags_2
	b = append(b, 0x15)                                          // auth-plugin-data length
	b = append(b, make([]byte, 10)...)                           // reserved
	return b
}

func TestParseHandshakeCapabilities(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		want    uint32
		wantErr bool
	}{
		{
			name:    "CLIENT_SSL set, MySQL",
			payload: buildTestHandshake(clientProtocol41|clientSSL, "8.0.36"),
			want:    clientProtocol41 | clientSSL,
		},
		{
			name:    "CLIENT_SSL clear",
			payload: buildTestHandshake(clientProtocol41, "8.0.36"),
			want:    clientProtocol41,
		},
		{
			// The flag split across the two halves must be reassembled: a bit in
			// the upper 16 bits (here 0x80000000) plus CLIENT_SSL in the lower.
			name:    "capability split across halves",
			payload: buildTestHandshake(0x80000000|clientSSL, "8.0.36"),
			want:    0x80000000 | clientSSL,
		},
		{
			name:    "MariaDB version prefix is skipped",
			payload: buildTestHandshake(clientProtocol41|clientSSL, "5.5.5-10.11.2-MariaDB"),
			want:    clientProtocol41 | clientSSL,
		},
		{
			name:    "error packet",
			payload: []byte{0xFF, 0x10, 0x04},
			wantErr: true,
		},
		{
			name:    "empty payload",
			payload: []byte{},
			wantErr: true,
		},
		{
			name:    "unterminated version",
			payload: []byte{0x0A, 'x', 'y', 'z'},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseHandshakeCapabilities(c.payload)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if got != c.want {
				t.Errorf("capabilities = 0x%08x, want 0x%08x", got, c.want)
			}
			if (got&clientSSL != 0) != (c.want&clientSSL != 0) {
				t.Errorf("CLIENT_SSL verdict wrong for 0x%08x", got)
			}
		})
	}
}

// The SSLRequest packet must carry a valid header (length 32, the given
// sequence id) and set CLIENT_SSL and CLIENT_PROTOCOL_41 in its capabilities.
func TestMySQLSSLRequestBytes(t *testing.T) {
	pkt := mysqlSSLRequest(1)
	if len(pkt) != 36 {
		t.Fatalf("packet length = %d, want 36 (4 header + 32 payload)", len(pkt))
	}
	length := uint32(pkt[0]) | uint32(pkt[1])<<8 | uint32(pkt[2])<<16
	if length != 32 {
		t.Errorf("header length = %d, want 32", length)
	}
	if pkt[3] != 1 {
		t.Errorf("sequence id = %d, want 1", pkt[3])
	}
	caps := binary.LittleEndian.Uint32(pkt[4:8])
	if caps&clientSSL == 0 {
		t.Error("CLIENT_SSL must be set in the SSLRequest")
	}
	if caps&clientProtocol41 == 0 {
		t.Error("CLIENT_PROTOCOL_41 must be set in the SSLRequest")
	}
}

func TestStartTLSMySQLAdvertisesTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	got := make(chan []byte, 1)
	go func() {
		defer server.Close()
		// Server speaks first: send the framed Initial Handshake.
		payload := buildTestHandshake(clientProtocol41|clientSSL, "8.0.36")
		_, _ = server.Write(frameMySQLPacket(payload, 0))
		// Read the client's SSLRequest packet (4-byte header + 32-byte payload).
		var buf [36]byte
		_, _ = io.ReadFull(server, buf[:])
		got <- buf[:]
	}()

	if err := startTLS(client, ServiceMySQL); err != nil {
		t.Fatalf("MySQL SSLRequest negotiation failed: %v", err)
	}

	reply := <-got
	if reply[3] != 1 {
		t.Errorf("SSLRequest sequence id = %d, want 1 (server seq 0 + 1)", reply[3])
	}
	if caps := binary.LittleEndian.Uint32(reply[4:8]); caps&clientSSL == 0 {
		t.Error("client SSLRequest did not set CLIENT_SSL")
	}
}

// A server that does not advertise CLIENT_SSL must be reported as not supporting
// TLS, not left to fail confusingly in the handshake.
func TestStartTLSMySQLNoTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		payload := buildTestHandshake(clientProtocol41, "8.0.36") // no CLIENT_SSL
		_, _ = server.Write(frameMySQLPacket(payload, 0))
	}()

	err := startTLS(client, ServiceMySQL)
	if err == nil {
		t.Fatal("expected an error when the server does not advertise CLIENT_SSL")
	}
	if !strings.Contains(err.Error(), "does not support TLS") {
		t.Errorf("error should say TLS is unsupported, got: %v", err)
	}
}

// An ERR packet in place of a handshake must be a clear error, not a panic.
func TestStartTLSMySQLErrorPacket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		_, _ = server.Write(frameMySQLPacket([]byte{0xFF, 0x10, 0x04, 'n', 'o'}, 0))
	}()

	if err := startTLS(client, ServiceMySQL); err == nil {
		t.Fatal("expected an error for an ERR packet")
	}
}

// frameMySQLPacket wraps a payload in the 4-byte MySQL packet header.
func frameMySQLPacket(payload []byte, seq uint8) []byte {
	hdr := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		seq,
	}
	return append(hdr, payload...)
}
