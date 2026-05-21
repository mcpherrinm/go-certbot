package nginx

import (
	"strings"
	"testing"

	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

func parseOrFatal(t *testing.T, src string) *parser.Config {
	t.Helper()
	cfg, err := parser.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestFindMatchingServersExact(t *testing.T) {
	src := `http {
    server {
        listen 80;
        server_name a.example;
    }
    server {
        listen 80;
        server_name b.example c.example;
    }
}
`
	cfg := parseOrFatal(t, src)
	got := findMatchingServers(cfg, []string{"c.example"})
	if len(got) != 1 {
		t.Fatalf("expected 1 server, got %d", len(got))
	}
}

// TestFindMatchingServersCaseInsensitive mirrors certbot's
// parser._exact_match / _wildcard_match which lowercase both sides
// (parser.py:525-565). DNS names are case-insensitive per RFC 4343.
func TestFindMatchingServersCaseInsensitive(t *testing.T) {
	src := `http {
    server {
        listen 80;
        server_name Example.COM www.Example.COM;
    }
    server {
        listen 80;
        server_name *.WILDCARD.example;
    }
}
`
	cfg := parseOrFatal(t, src)
	for _, dom := range []string{"example.com", "EXAMPLE.com", "www.example.com"} {
		got := findMatchingServers(cfg, []string{dom})
		if len(got) == 0 {
			t.Errorf("expected a match for %q (server_name Example.COM)", dom)
		}
	}
	got := findMatchingServers(cfg, []string{"sub.wildcard.example"})
	if len(got) == 0 {
		t.Errorf("expected wildcard match for sub.wildcard.example")
	}
}

func TestFindMatchingServersWildcard(t *testing.T) {
	src := `http {
    server {
        listen 80;
        server_name *.example.com;
    }
}
`
	cfg := parseOrFatal(t, src)
	got := findMatchingServers(cfg, []string{"sub.example.com"})
	if len(got) != 1 {
		t.Errorf("wildcard match failed")
	}
	none := findMatchingServers(cfg, []string{"example.org"})
	if len(none) != 0 {
		t.Errorf("non-matching domain still matched")
	}
}

func TestInsertSSLDirectivesIdempotent(t *testing.T) {
	src := `server {
    listen 80;
    server_name example.com;
    root /var/www;
}
`
	cfg := parseOrFatal(t, src)
	srv := cfg.Nodes[0].(*parser.Block)
	insertSSLDirectives(srv, "/fc.pem", "/key.pem", 80, 443)
	insertSSLDirectives(srv, "/fc.pem", "/key.pem", 80, 443) // second call shouldn't double
	out := cfg.String()
	if strings.Count(out, "ssl_certificate ") != 1 {
		t.Errorf("ssl_certificate inserted %d times:\n%s", strings.Count(out, "ssl_certificate "), out)
	}
	if !strings.Contains(out, "listen 443 ssl;") {
		t.Errorf("listen 443 ssl missing:\n%s", out)
	}
}

func TestInsertSSLOnExistingListen443(t *testing.T) {
	src := `server {
    listen 443;
    server_name example.com;
}
`
	cfg := parseOrFatal(t, src)
	srv := cfg.Nodes[0].(*parser.Block)
	insertSSLDirectives(srv, "/fc.pem", "/key.pem", 80, 443)
	out := cfg.String()
	if !strings.Contains(out, "listen 443 ssl;") {
		t.Errorf("should upgrade existing listen 443:\n%s", out)
	}
	if strings.Count(out, "listen") != 1 {
		t.Errorf("should not add a second listen line:\n%s", out)
	}
}

// TestInsertSSLPreservesIPHost mirrors certbot#9978 fix: when the existing
// http listen has an IP host (e.g. `listen 127.0.0.1:80;`), the new SSL
// listen must keep the same host on the HTTPS port.
func TestInsertSSLPreservesIPHost(t *testing.T) {
	src := `server {
    listen 127.0.0.1:80;
    server_name example.com;
}
`
	cfg := parseOrFatal(t, src)
	srv := cfg.Nodes[0].(*parser.Block)
	insertSSLDirectives(srv, "/fc.pem", "/key.pem", 80, 443)
	out := cfg.String()
	if !strings.Contains(out, "listen 127.0.0.1:443 ssl;") {
		t.Errorf("expected 127.0.0.1:443 ssl listen:\n%s", out)
	}
	// The original http listen must NOT be modified.
	if !strings.Contains(out, "listen 127.0.0.1:80;") {
		t.Errorf("expected original http listen preserved:\n%s", out)
	}
}

func TestAddRedirectIfHTTPOnly(t *testing.T) {
	src := `server {
    listen 80;
    server_name example.com;
    root /var/www;
}
`
	cfg := parseOrFatal(t, src)
	srv := cfg.Nodes[0].(*parser.Block)
	addRedirectIfHTTPOnly(srv, []string{"example.com"})
	out := cfg.String()
	if !strings.Contains(out, "return 301 https://$host$request_uri") {
		t.Errorf("redirect not added:\n%s", out)
	}
	if !strings.Contains(out, "if ($host = example.com)") {
		t.Errorf("expected per-host `if` guard:\n%s", out)
	}
}

func TestAddRedirectSkipsHTTPSServer(t *testing.T) {
	src := `server {
    listen 443 ssl;
    server_name example.com;
}
`
	cfg := parseOrFatal(t, src)
	srv := cfg.Nodes[0].(*parser.Block)
	addRedirectIfHTTPOnly(srv, []string{"example.com"})
	out := cfg.String()
	if strings.Contains(out, "return 301") {
		t.Errorf("should not add redirect to https-only server:\n%s", out)
	}
}

func TestSplitListenAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
		wantOK   bool
	}{
		{"80", "", "80", true},
		{"127.0.0.1:80", "127.0.0.1", "80", true},
		{"[::]:443", "[::]", "443", true},
		{"[::]", "", "", false},
	}
	for _, tc := range cases {
		h, p, ok := splitListenAddr(tc.in)
		if h != tc.wantHost || p != tc.wantPort || ok != tc.wantOK {
			t.Errorf("splitListenAddr(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, h, p, ok, tc.wantHost, tc.wantPort, tc.wantOK)
		}
	}
}
