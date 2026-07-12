package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"example.com", "example.com", "443", false},
		{"example.com:8443", "example.com", "8443", false},
		{"https://example.com", "example.com", "443", false},
		{"https://example.com:9443/", "example.com", "9443", false},
		{"  example.org  ", "example.org", "443", false},
		{"", "", "", true},
	}

	for _, c := range cases {
		host, port, err := splitHostPort(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("splitHostPort(%q) err = %v, wantErr = %v", c.in, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

// testCert bundles a parsed certificate with the key that signed it, so it can
// act as a signing parent for the next certificate in a chain.
type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue creates a certificate from tmpl. When parent is nil the certificate is
// self-signed (signed by its own fresh key); otherwise it is signed by parent.
func issue(t *testing.T, tmpl *x509.Certificate, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &testCert{cert: cert, key: key}
}

func caTemplate(cn string, notBefore, notAfter time.Time, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
}

func leafTemplate(cn string, dnsNames []string, notBefore, notAfter time.Time, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func TestVerifyTrust(t *testing.T) {
	now := time.Now()
	valid := func(d time.Duration) time.Time { return now.Add(d) }

	root := issue(t, caTemplate("Test Root CA", valid(-48*time.Hour), valid(10*365*24*time.Hour), 1), nil)
	inter := issue(t, caTemplate("Test Intermediate CA", valid(-48*time.Hour), valid(5*365*24*time.Hour), 2), root)

	roots := x509.NewCertPool()
	roots.AddCert(root.cert)

	// A normal, trusted leaf: root -> intermediate -> leaf.
	goodLeaf := issue(t, leafTemplate("example.com", []string{"example.com"}, valid(-1*time.Hour), valid(90*24*time.Hour), 10), inter)

	// Self-signed leaf (its own key signs it), valid time window.
	selfSigned := issue(t, leafTemplate("self.example.com", []string{"self.example.com"}, valid(-1*time.Hour), valid(90*24*time.Hour), 11), nil)

	// Self-signed AND expired.
	selfExpired := issue(t, leafTemplate("old.example.com", []string{"old.example.com"}, valid(-72*time.Hour), valid(-24*time.Hour), 12), nil)

	// Chain-valid but expired (signed by root, NotAfter in the past). NotBefore
	// stays within the root's validity so the chain still verifies at that time.
	expiredLeaf := issue(t, leafTemplate("expired.example.com", []string{"expired.example.com"}, valid(-24*time.Hour), valid(-1*time.Hour), 13), root)

	// Chain-valid leaf, used with a mismatched hostname.
	mismatchLeaf := issue(t, leafTemplate("real.example.com", []string{"real.example.com"}, valid(-1*time.Hour), valid(90*24*time.Hour), 14), root)

	// Leaf signed by an unknown root (root not in the pool).
	unknownRoot := issue(t, caTemplate("Rogue Root CA", valid(-48*time.Hour), valid(10*365*24*time.Hour), 3), nil)
	unknownLeaf := issue(t, leafTemplate("unknown.example.com", []string{"unknown.example.com"}, valid(-1*time.Hour), valid(90*24*time.Hour), 15), unknownRoot)

	// Forged: Issuer==Subject but signed by a different key (not truly
	// self-signed). CheckSignatureFrom must reject it as self_signed.
	forgeIssuer := issue(t, caTemplate("forged.example.com", valid(-48*time.Hour), valid(10*365*24*time.Hour), 4), nil)
	forgedLeaf := issue(t, leafTemplate("forged.example.com", []string{"forged.example.com"}, valid(-1*time.Hour), valid(90*24*time.Hour), 16), forgeIssuer)

	cases := []struct {
		name  string
		leaf  *x509.Certificate
		chain []*x509.Certificate
		host  string
		want  []string
	}{
		{"trusted chain", goodLeaf.cert, []*x509.Certificate{goodLeaf.cert, inter.cert}, "example.com", nil},
		{"self signed", selfSigned.cert, []*x509.Certificate{selfSigned.cert}, "self.example.com", []string{"self_signed"}},
		{"self signed and expired", selfExpired.cert, []*x509.Certificate{selfExpired.cert}, "old.example.com", []string{"self_signed", "expired"}},
		{"expired but chain valid", expiredLeaf.cert, []*x509.Certificate{expiredLeaf.cert}, "expired.example.com", []string{"expired"}},
		{"hostname mismatch", mismatchLeaf.cert, []*x509.Certificate{mismatchLeaf.cert}, "wrong.example.com", []string{"hostname_mismatch"}},
		{"leaf only missing intermediate", goodLeaf.cert, []*x509.Certificate{goodLeaf.cert}, "example.com", []string{"untrusted_chain"}},
		{"unknown root", unknownLeaf.cert, []*x509.Certificate{unknownLeaf.cert, unknownRoot.cert}, "unknown.example.com", []string{"untrusted_chain"}},
		{"forged issuer equals subject", forgedLeaf.cert, []*x509.Certificate{forgedLeaf.cert}, "forged.example.com", []string{"untrusted_chain"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := verifyTrust(c.leaf, c.chain, c.host, roots, now)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("verifyTrust() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		in   uint16
		want string
	}{
		{tls.VersionTLS13, "TLS1.3"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS10, "TLS1.0"},
		{0x0300, "0x0300"},
	}
	for _, c := range cases {
		if got := tlsVersionName(c.in); got != c.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProbeConnectionDetails(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	// httptest serves a self-signed cert, so we exercise the fields we care
	// about here (negotiated params, chain length, trust set) rather than
	// asserting a trusted result.
	r := Probe(context.Background(), srv.Listener.Addr().String(), 5*time.Second)
	if r.Error != "" {
		t.Fatalf("Probe error: %s", r.Error)
	}
	if r.TLSVersion == "" {
		t.Errorf("TLSVersion is empty")
	}
	if r.CipherSuite == "" {
		t.Errorf("CipherSuite is empty")
	}
	if r.ChainLength != 1 {
		t.Errorf("ChainLength = %d, want 1", r.ChainLength)
	}
	if r.Trusted == nil {
		t.Errorf("Trusted is nil, want a non-nil determination")
	}
}
