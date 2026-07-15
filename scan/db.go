package scan

// Database TLS dialects: PostgreSQL and MySQL/MariaDB negotiate TLS with a
// protocol-specific preamble rather than the line-based STARTTLS commands of
// SMTP/IMAP/POP3. certflow speaks just enough of each to reach the TLS handshake
// and read the certificate — it never authenticates, sends a query, or transmits
// a password. Both protocols switch to TLS before authentication, so no database
// credentials are needed.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// --- PostgreSQL -------------------------------------------------------------

// pgSSLRequestCode is the magic number in a PostgreSQL SSLRequest message. It is
// (1234 << 16) | 5678 by the frontend/backend protocol, i.e. 0x04D2162F.
const pgSSLRequestCode = 80877103

// pgSSLRequest is the fixed 8-byte SSLRequest a client sends to ask a PostgreSQL
// server to switch to TLS: int32 length (8) followed by int32 code, both in
// network byte order (big-endian).
func pgSSLRequest() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], 8)
	binary.BigEndian.PutUint32(buf[4:8], pgSSLRequestCode)
	return buf
}

// startTLSPostgres performs the PostgreSQL in-band SSLRequest negotiation.
//
// The client sends the 8-byte SSLRequest; the server answers with a SINGLE byte:
// 'S' (accept), 'N' (TLS unavailable), or 'E' (an ErrorResponse from a pre-3.0
// server). On 'S' the caller starts the TLS handshake on the same connection.
//
// Security (CVE-2021-23222): the reply must be read as exactly one byte, and no
// further bytes may be buffered before TLS begins. Extra bytes after 'S' are the
// buffer-stuffing signature of a man-in-the-middle injecting plaintext that would
// otherwise be taken as post-handshake data. Two structural defences:
//   - read the reply with io.ReadFull into a one-byte array — never a
//     bufio.Reader, which could pre-read subsequent bytes; and
//   - after 'S', assert that nothing is already pending (assertNoPendingBytes)
//     before handing the raw connection to the TLS layer.
func startTLSPostgres(conn net.Conn) error {
	if _, err := conn.Write(pgSSLRequest()); err != nil {
		return fmt.Errorf("SSLRequest: %w", err)
	}

	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("SSLRequest reply: %w", err)
	}

	switch reply[0] {
	case 'S':
		// Accepted — fall through to the buffer-stuffing check.
	case 'N':
		return fmt.Errorf("server does not support TLS (SSLRequest declined, 'N')")
	case 'E':
		return fmt.Errorf("server returned an error to SSLRequest (pre-3.0 server?)")
	default:
		return fmt.Errorf("unexpected SSLRequest reply byte 0x%02x", reply[0])
	}

	return assertNoPendingBytes(conn)
}

// assertNoPendingBytes verifies the peer has not already sent data that would be
// waiting in the socket when the TLS handshake begins. After the single 'S'
// reply a well-behaved PostgreSQL server stays silent until it receives our
// ClientHello, so any immediately-available byte is a protocol violation and the
// buffer-stuffing pattern CVE-2021-23222 warns about.
//
// It gives the connection a short read deadline and attempts a one-byte read: a
// timeout (the expected case) means the socket is quiet; any byte actually
// returned means the peer stuffed extra data, and the probe is aborted. The
// caller must reset the deadline before real I/O — Probe does this after
// startTLS returns.
func assertNoPendingBytes(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		return err
	}
	var b [1]byte
	n, err := conn.Read(b[:])
	if n > 0 {
		// Data was already waiting: the peer stuffed bytes after 'S'.
		return fmt.Errorf("unexpected data after SSLRequest 'S' (possible buffer-stuffing, CVE-2021-23222)")
	}
	switch {
	case err == nil:
		return nil // no bytes, no error: nothing pending
	case err == io.EOF:
		return nil // peer closed with nothing buffered; TLS will fail on its own
	default:
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil // quiet socket: the expected, safe case
		}
		return fmt.Errorf("checking for pending bytes: %w", err)
	}
}
