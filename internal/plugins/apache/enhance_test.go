package apache

import (
	"strings"
	"testing"

	"github.com/letsencrypt/go-certbot/internal/plugins/apache/parser"
)

func TestApacheHSTSIdempotent(t *testing.T) {
	src := `<VirtualHost *:443>
    ServerName example.com
</VirtualHost>
`
	cfg, _ := parser.Parse(src)
	sec := cfg.Nodes[0].(*parser.Section)
	addHSTS(sec)
	addHSTS(sec)
	out := cfg.String()
	if strings.Count(out, "Strict-Transport-Security") != 1 {
		t.Errorf("HSTS appeared %d times:\n%s", strings.Count(out, "Strict-Transport-Security"), out)
	}
	if !strings.Contains(out, `Header always set Strict-Transport-Security "max-age=31536000"`) {
		t.Errorf("HSTS line malformed:\n%s", out)
	}
}

func TestApacheStaple(t *testing.T) {
	src := `<VirtualHost *:443>
    ServerName example.com
</VirtualHost>
`
	cfg, _ := parser.Parse(src)
	sec := cfg.Nodes[0].(*parser.Section)
	addStaple(sec)
	out := cfg.String()
	for _, want := range []string{"SSLUseStapling on", "SSLStaplingCache"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestApacheUIRIdempotent(t *testing.T) {
	src := `<VirtualHost *:443>
    ServerName example.com
</VirtualHost>
`
	cfg, _ := parser.Parse(src)
	sec := cfg.Nodes[0].(*parser.Section)
	addUIR(sec)
	addUIR(sec)
	out := cfg.String()
	if strings.Count(out, "upgrade-insecure-requests") != 1 {
		t.Errorf("UIR appeared %d times:\n%s", strings.Count(out, "upgrade-insecure-requests"), out)
	}
}
