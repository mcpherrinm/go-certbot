package parser

import "testing"

func TestRoundTrip(t *testing.T) {
	src := `# Apache vhost
ServerRoot /etc/apache2

<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example
    # the access log
    CustomLog /var/log/apache2/example.log combined
</VirtualHost>

<IfModule mod_ssl.c>
    Listen 443
</IfModule>
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

func TestQuotedArgs(t *testing.T) {
	src := `<Directory "/var/www/html">
    Options "Indexes FollowSymLinks"
    AllowOverride None
</Directory>
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.String(); got != src {
		t.Errorf("round-trip diverged:\n--- got\n%s\n--- want\n%s", got, src)
	}
}

func TestNestedSections(t *testing.T) {
	src := `<VirtualHost *:80>
    <Directory /var/www>
        Require all granted
    </Directory>
</VirtualHost>
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.String(); got != src {
		t.Errorf("round-trip diverged:\n--- got\n%s", got)
	}
}

func TestLineContinuation(t *testing.T) {
	src := "SetEnvIf User-Agent \"Mozilla.*\" \\\n    is_browser\n"
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	// After parse, the line was joined; we don't try to preserve the
	// backslash for now. Just verify it parsed cleanly.
	d, ok := cfg.Nodes[0].(*Directive)
	if !ok {
		t.Fatalf("expected directive, got %T", cfg.Nodes[0])
	}
	if d.Name != "SetEnvIf" || len(d.Args) != 3 {
		t.Errorf("unexpected parse: %#v", d)
	}
}

func TestMissingCloseTagErrors(t *testing.T) {
	if _, err := Parse("<VirtualHost *:80>\n    ServerName x\n"); err == nil {
		t.Errorf("expected EOF error for missing close tag")
	}
}
