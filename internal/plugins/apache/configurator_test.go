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
	applySSLDirectives(sec, "/fc.pem", "/key.pem")
	applySSLDirectives(sec, "/fc.pem", "/key.pem")
	out := cfg.String()
	if strings.Count(out, "SSLCertificateFile") != 1 {
		t.Errorf("SSLCertificateFile appeared %d times:\n%s", strings.Count(out, "SSLCertificateFile"), out)
	}
	if !strings.Contains(out, "SSLEngine on") {
		t.Errorf("missing SSLEngine on:\n%s", out)
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
	clone := cloneAsSSLVHost(src80, "/fc.pem", "/key.pem")
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
