package scan

import "testing"

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
