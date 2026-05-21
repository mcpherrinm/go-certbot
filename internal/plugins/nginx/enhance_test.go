package nginx

import (
	"strings"
	"testing"

	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

func TestAddHSTS(t *testing.T) {
	src := `server {
    listen 443 ssl;
    server_name example.com;
}
`
	cfg, _ := parser.Parse(src)
	srv := cfg.Nodes[0].(*parser.Block)
	addHSTS(srv)
	addHSTS(srv) // idempotent
	out := cfg.String()
	if strings.Count(out, "Strict-Transport-Security") != 1 {
		t.Errorf("HSTS inserted %d times:\n%s", strings.Count(out, "Strict-Transport-Security"), out)
	}
	if !strings.Contains(out, "max-age=31536000") {
		t.Errorf("expected max-age=31536000 in:\n%s", out)
	}
}

func TestAddStaple(t *testing.T) {
	src := `server {
    listen 443 ssl;
    server_name example.com;
}
`
	cfg, _ := parser.Parse(src)
	srv := cfg.Nodes[0].(*parser.Block)
	addStaple(srv)
	out := cfg.String()
	if !strings.Contains(out, "ssl_stapling on") || !strings.Contains(out, "ssl_stapling_verify on") {
		t.Errorf("missing ssl_stapling pair:\n%s", out)
	}
}

func TestServerIsHTTPS(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{`server { listen 443 ssl; }`, true},
		{`server { listen 443; }`, true},
		{`server { listen 80 ssl; }`, true}, // any `ssl` keyword
		{`server { listen 80; }`, false},
		{`server { }`, false},
	}
	for _, tc := range cases {
		cfg, err := parser.Parse(tc.src + "\n")
		if err != nil {
			t.Fatal(err)
		}
		srv := cfg.Nodes[0].(*parser.Block)
		if got := serverIsHTTPS(srv); got != tc.want {
			t.Errorf("serverIsHTTPS(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}
