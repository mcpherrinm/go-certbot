package parser

import (
	"strings"
	"testing"
)

func TestRoundTripPreservesFormatting(t *testing.T) {
	src := `# leading comment
worker_processes auto;

http {
    # nested
    server {
        listen 80;
        server_name example.com www.example.com;
        root /var/www/example;
        location / {
            try_files $uri /index.html;
        }
    }
    upstream backend {
        server 10.0.0.1:8080;
        server 10.0.0.2:8080 backup;
    }
}
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.String()
	if got != src {
		t.Errorf("round-trip diverged:\n--- got\n%s\n--- want\n%s", got, src)
	}
}

func TestQuotedAndCommentsPreserved(t *testing.T) {
	src := `server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate "/etc/ssl/example.crt"; # cert
    ssl_certificate_key '/etc/ssl/example.key';
}
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.String()
	if got != src {
		t.Errorf("round-trip diverged:\n--- got\n%s\n--- want\n%s", got, src)
	}
}

func TestServerBlockDiscovery(t *testing.T) {
	src := `http {
    server { server_name a.test; listen 80; }
    server { server_name b.test c.test; listen 80; }
}
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	var servers []*Block
	for _, n := range cfg.Nodes {
		http, ok := n.(*Block)
		if !ok || http.Name != "http" {
			continue
		}
		for _, child := range http.Body {
			if b, ok := child.(*Block); ok && b.Name == "server" {
				servers = append(servers, b)
			}
		}
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 server blocks, got %d", len(servers))
	}
	if names := serverNames(servers[1]); !strings.Contains(strings.Join(names, " "), "c.test") {
		t.Errorf("second server should include c.test: %v", names)
	}
}

func serverNames(b *Block) []string {
	for _, n := range b.Body {
		if d, ok := n.(*Directive); ok && d.Name == "server_name" {
			return d.Args
		}
	}
	return nil
}

// TestServerNameInternalComments mirrors certbot 6fd6a541d (#10147): a
// directive with comments interleaved between args must parse, with the
// comment NOT becoming an arg.
func TestServerNameInternalComments(t *testing.T) {
	src := `server {
    server_name *.goo.far
        # commented
        baz.com;
}
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	srv := cfg.Nodes[0].(*Block)
	names := serverNames(srv)
	if len(names) != 2 || names[0] != "*.goo.far" || names[1] != "baz.com" {
		t.Errorf("server_name args = %v, want [*.goo.far baz.com]", names)
	}
	// Round-trip must preserve the comment.
	if got := cfg.String(); got != src {
		t.Errorf("round-trip diverged:\n--- got\n%s\n--- want\n%s", got, src)
	}
}

// TestNBSPWhitespace mirrors certbot 3.2.0 fix: U+00A0 (NBSP) between
// tokens must be treated as whitespace, not silently glued into the
// adjacent word.
func TestNBSPWhitespace(t *testing.T) {
	// "server_name" + NBSP + "example.com;"
	src := "server {\n    server_name example.com;\n}\n"
	cfg, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	srv := cfg.Nodes[0].(*Block)
	if srv.Name != "server" {
		t.Errorf("block name = %q, want server", srv.Name)
	}
	names := serverNames(srv)
	if len(names) != 1 || names[0] != "example.com" {
		t.Errorf("server_name args = %v, want [example.com]", names)
	}
}
