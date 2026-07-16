package scan

// Database TLS dialects: PostgreSQL and MySQL/MariaDB negotiate TLS with a
// protocol-specific preamble rather than the line-based STARTTLS commands of
// SMTP/IMAP/POP3. CertRenova Probe speaks just enough of each to reach the TLS handshake
// and read the certificate — it never authenticates, sends a query, or transmits
// a password. Both protocols switch to TLS before authentication, so no database
// credentials are needed.

import (
	"bytes"
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

// --- MySQL / MariaDB --------------------------------------------------------

// MySQL capability flags we care about. CLIENT_SSL advertises TLS support;
// CLIENT_PROTOCOL_41 selects the modern handshake and must be echoed in our
// SSLRequest. See the MySQL client/server protocol documentation.
const (
	clientProtocol41 = 0x00000200
	clientSSL        = 0x00000800
)

// startTLSMySQL performs the MySQL/MariaDB capability-flag TLS negotiation.
//
// Unlike PostgreSQL, the server speaks first: it sends an Initial Handshake
// (HandshakeV10) advertising its capabilities. If the CLIENT_SSL bit is clear
// the server cannot do TLS. Otherwise the client replies with an SSLRequest
// packet — the first 32 bytes of a HandshakeResponse41, with CLIENT_SSL set and
// nothing from the username onward — and the TLS handshake begins immediately.
//
// CertRenova Probe never authenticates, so it parses only the capability flags and sends
// no credentials.
func startTLSMySQL(conn net.Conn) error {
	payload, seq, err := readMySQLPacket(conn)
	if err != nil {
		return fmt.Errorf("initial handshake: %w", err)
	}
	caps, err := parseHandshakeCapabilities(payload)
	if err != nil {
		return err
	}
	if caps&clientSSL == 0 {
		return fmt.Errorf("server does not support TLS (CLIENT_SSL not advertised)")
	}
	// The SSLRequest's sequence id is the server handshake's id + 1.
	if _, err := conn.Write(mysqlSSLRequest(seq + 1)); err != nil {
		return fmt.Errorf("SSLRequest: %w", err)
	}
	return nil
}

// readMySQLPacket reads exactly one MySQL protocol packet. The 4-byte header is a
// 3-byte little-endian payload length plus a 1-byte sequence id. Reading exactly
// the framed length with io.ReadFull means we never over-read into bytes that
// will belong to the TLS handshake.
func readMySQLPacket(conn net.Conn) (payload []byte, seq uint8, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return nil, 0, fmt.Errorf("packet header: %w", err)
	}
	length := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16
	seq = hdr[3]
	if length == 0 {
		return nil, seq, fmt.Errorf("empty packet")
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return nil, seq, fmt.Errorf("packet payload: %w", err)
	}
	return payload, seq, nil
}

// parseHandshakeCapabilities extracts the 32-bit capability flag set from a
// HandshakeV10 payload. It parses ONLY as far as the capability flags — CertRenova Probe
// never authenticates, so auth-plugin data, plugin names, and the rest are
// irrelevant.
//
// The 32-bit capability set is split by protocol history: the lower 16 bits sit
// before the character-set/status fields, the upper 16 bits after. Both halves
// are reassembled. CLIENT_SSL happens to live in the lower half, but the full
// value is returned so the caller can echo a correct capability set.
//
// The MariaDB "5.5.5-" version prefix lives in the NUL-terminated server version
// string, which is skipped, so it does not affect the result.
func parseHandshakeCapabilities(payload []byte) (uint32, error) {
	if len(payload) < 1 {
		return 0, fmt.Errorf("handshake too short")
	}
	switch payload[0] {
	case 0x0A:
		// HandshakeV10 — the modern handshake we support.
	case 0xFF:
		return 0, fmt.Errorf("server returned an error packet instead of a handshake")
	default:
		return 0, fmt.Errorf("unsupported handshake protocol version 0x%02x", payload[0])
	}

	// server version: a NUL-terminated string starting at offset 1.
	i := bytes.IndexByte(payload[1:], 0x00)
	if i < 0 {
		return 0, fmt.Errorf("handshake: unterminated server version")
	}
	off := 1 + i + 1 // move past the NUL

	// connection id (4) + auth-plugin-data-part-1 (8) + filler (1) = 13 bytes.
	off += 13
	if off+2 > len(payload) {
		return 0, fmt.Errorf("handshake: truncated before capability flags")
	}
	lower := binary.LittleEndian.Uint16(payload[off : off+2])
	off += 2

	// The upper 16 bits follow character set (1) + status flags (2). Older or
	// minimal servers may stop after the lower half; then CLIENT_SSL (lower half)
	// is still decidable.
	var upper uint16
	if off+5 <= len(payload) {
		upper = binary.LittleEndian.Uint16(payload[off+3 : off+5])
	}

	return uint32(lower) | uint32(upper)<<16, nil
}

// mysqlSSLRequest builds the SSLRequest packet: the first 32 bytes of a
// HandshakeResponse41 (client capabilities, max packet size, character set, 23
// reserved zero bytes) framed with a 4-byte header. It sets CLIENT_SSL and
// CLIENT_PROTOCOL_41 and stops before the username, so the server switches to
// TLS without any authentication data.
func mysqlSSLRequest(seq uint8) []byte {
	const (
		payloadLen    = 32
		maxPacketSize = 16 * 1024 * 1024 // 16 MiB, a conventional client value
		charsetUTF8   = 0x21             // utf8_general_ci; any valid id works
	)
	pkt := make([]byte, 4+payloadLen)
	// Header: 3-byte little-endian payload length + sequence id.
	pkt[0] = byte(payloadLen)
	pkt[3] = seq
	// Payload:
	binary.LittleEndian.PutUint32(pkt[4:8], clientProtocol41|clientSSL)
	binary.LittleEndian.PutUint32(pkt[8:12], maxPacketSize)
	pkt[12] = charsetUTF8
	// pkt[13:36] are the 23 reserved bytes, already zero.
	return pkt
}
