package apache

import (
	"strings"
	"testing"

	"github.com/letsencrypt/go-certbot/internal/plugins/apache/parser"
)

func parseOrFatal(t *testing.T, src string) *parser.Config {
	t.Helper()
	cfg, err := parser.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestFindMatchingVHostsByServerName(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName a.example
</VirtualHost>
<VirtualHost *:80>
    ServerName b.example
    ServerAlias c.example
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	if got := findMatchingVHosts(cfg, []string{"c.example"}, "80"); len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	if got := findMatchingVHosts(cfg, []string{"a.example"}, "443"); len(got) != 0 {
		t.Errorf("expected no :443 matches, got %d", len(got))
	}
}

// TestFindMatchingVHostsCaseInsensitive mirrors certbot domain_in_names
// (configurator.py:773-794): both ServerName and the request are lowercased.
func TestFindMatchingVHostsCaseInsensitive(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName Example.COM
    ServerAlias WWW.Example.COM
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	for _, dom := range []string{"example.com", "www.example.com", "EXAMPLE.COM"} {
		if got := findMatchingVHosts(cfg, []string{dom}, "80"); len(got) != 1 {
			t.Errorf("expected match for %q, got %d", dom, len(got))
		}
	}
}

// TestServerNameSchemeStripped: Apache accepts `scheme://name:port` on
// ServerName per obj.py:127 — strip both before matching.
func TestServerNameSchemeStripped(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName https://example.com:8080
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	if got := findMatchingVHosts(cfg, []string{"example.com"}, "80"); len(got) != 1 {
		t.Errorf("scheme://host:port ServerName should match bare host")
	}
}

// TestRepeatedServerNameUsesLast: when a vhost has multiple ServerName
// directives, Apache uses the last one (the second overrides the first).
// We should match the LAST, not the first.
func TestRepeatedServerNameUsesLast(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName first.example
    ServerName second.example
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	if got := findMatchingVHosts(cfg, []string{"second.example"}, "80"); len(got) != 1 {
		t.Errorf("second.example should match (last ServerName wins)")
	}
	if got := findMatchingVHosts(cfg, []string{"first.example"}, "80"); len(got) != 0 {
		t.Errorf("first.example should NOT match (overridden by later ServerName)")
	}
}

func TestFindMatchingVHostsWildcard(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName *.example.com
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	if got := findMatchingVHosts(cfg, []string{"sub.example.com"}, ""); len(got) != 1 {
		t.Errorf("wildcard match should hit")
	}
}

func TestApplySSLDirectivesIdempotent(t *testing.T) {
	src := `<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	sec := cfg.Nodes[0].(*parser.Section)
	applySSLDirectives(sec, "/fc.pem", "/key.pem", "", "")
	applySSLDirectives(sec, "/fc.pem", "/key.pem", "", "")
	out := cfg.String()
	if strings.Count(out, "SSLCertificateFile") != 1 {
		t.Errorf("SSLCertificateFile appeared %d times:\n%s", strings.Count(out, "SSLCertificateFile"), out)
	}
	if !strings.Contains(out, "SSLEngine on") {
		t.Errorf("missing SSLEngine on:\n%s", out)
	}
}

// TestApplySSLDedupesStaleCertDirectives mirrors certbot _clean_vhost
// (configurator.py:1654-1675): when a vhost already has a stale
// SSLCertificateFile pointing at an old path, apply must drop the
// stale line so Apache's last-wins semantics serve the new cert.
func TestApplySSLDedupesStaleCertDirectives(t *testing.T) {
	src := `<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /old/path/cert.pem
    SSLCertificateKeyFile /old/path/key.pem
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	sec := cfg.Nodes[0].(*parser.Section)
	applySSLDirectives(sec, "/new/fullchain.pem", "/new/privkey.pem", "", "")
	out := cfg.String()
	if strings.Contains(out, "/old/path/cert.pem") {
		t.Errorf("stale SSLCertificateFile not removed:\n%s", out)
	}
	if strings.Count(out, "SSLCertificateFile") != 1 {
		t.Errorf("expected exactly one SSLCertificateFile, got %d:\n%s",
			strings.Count(out, "SSLCertificateFile"), out)
	}
	if !strings.Contains(out, "/new/fullchain.pem") {
		t.Errorf("new fullchain missing:\n%s", out)
	}
}

func TestCloneAsSSLVHostRewritesPort(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/example
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	src80 := cfg.Nodes[0].(*parser.Section)
	clone := cloneAsSSLVHost(src80, "/fc.pem", "/key.pem", "", "")
	if len(clone.Args) == 0 || !strings.HasSuffix(clone.Args[0], ":443") {
		t.Errorf("clone should listen on :443, got %v", clone.Args)
	}
	// Original is untouched.
	if !strings.HasSuffix(src80.Args[0], ":80") {
		t.Errorf("original modified: %v", src80.Args)
	}
	// New vhost contains the SSL trio.
	combined := nodesText(clone.Body)
	for _, want := range []string{"SSLEngine", "SSLCertificateFile", "SSLCertificateKeyFile"} {
		if !strings.Contains(combined, want) {
			t.Errorf("clone missing %s:\n%s", want, combined)
		}
	}
}

func TestRewriteArgsTo443(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"*:80", "*:443"},
		{"_default_:80", "_default_:443"},
		{"1.2.3.4:80", "1.2.3.4:443"},
		{`"1.2.3.4:80"`, `"1.2.3.4:443"`},
		{"NameVirtualHost", "NameVirtualHost"},
	}
	for _, tc := range cases {
		out := rewriteArgsTo443([]string{tc.in})
		if out[0] != tc.want {
			t.Errorf("rewriteArgsTo443(%q): got %q want %q", tc.in, out[0], tc.want)
		}
	}
}

func TestInjectAndStripChallengeMarkers(t *testing.T) {
	src := `<VirtualHost *:80>
    ServerName example.com
</VirtualHost>
`
	cfg := parseOrFatal(t, src)
	sec := cfg.Nodes[0].(*parser.Section)
	indent := childIndent(sec)
	sec.Body = append(sec.Body,
		&parser.CommentLine{Verbatim: indent + "# go-certbot acme-challenge (auto-cleaned)", Newline: "\n"},
		&parser.Directive{Indent: indent, Name: "Alias", Args: []string{"/.well-known/acme-challenge/", "/tmp/x/"}, Newline: "\n"},
		&parser.Section{
			OpenIndent: indent, Name: "Directory", Args: []string{`"/tmp/x/"`},
			OpenNewline: "\n",
			Body: []parser.Node{
				&parser.Directive{Indent: indent + "    ", Name: "Require", Args: []string{"all", "granted"}, Newline: "\n"},
			},
			CloseIndent: indent, CloseNewline: "\n",
		},
	)
	stripChallengeMarkers(cfg.Nodes)
	out := cfg.String()
	if strings.Contains(out, "go-certbot acme-challenge") || strings.Contains(out, "Alias") || strings.Contains(out, "Require") {
		t.Errorf("strip didn't remove the inserted block:\n%s", out)
	}
}

func nodesText(nodes []parser.Node) string {
	return (&parser.Config{Nodes: nodes}).String()
}
