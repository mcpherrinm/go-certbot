package renewalconf

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sample = `cert = /etc/letsencrypt/live/example.com/cert.pem
privkey = /etc/letsencrypt/live/example.com/privkey.pem
chain = /etc/letsencrypt/live/example.com/chain.pem
fullchain = /etc/letsencrypt/live/example.com/fullchain.pem

# Options used in the renewal process
[renewalparams]
account = abc123
authenticator = standalone
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
elliptic_curve = secp256r1
must_staple = False
autorenew = True
http01_port = 80
domains = example.com,www.example.com,
`

func TestParseTopAndParams(t *testing.T) {
	f, err := parse([]byte(sample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Top["cert"] != "/etc/letsencrypt/live/example.com/cert.pem" {
		t.Errorf("cert: %q", f.Top["cert"])
	}
	if f.RenewalParams["authenticator"] != "standalone" {
		t.Errorf("authenticator: %q", f.RenewalParams["authenticator"])
	}
}

func TestBoolHelpers(t *testing.T) {
	f, _ := parse([]byte(sample))
	if v, ok := f.Bool("must_staple"); !ok || v != false {
		t.Errorf("must_staple: got (%v, %v)", v, ok)
	}
	if v, ok := f.Bool("autorenew"); !ok || v != true {
		t.Errorf("autorenew: got (%v, %v)", v, ok)
	}
}

func TestIntHelper(t *testing.T) {
	f, _ := parse([]byte(sample))
	n, ok, err := f.Int("http01_port")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || n != 80 {
		t.Errorf("http01_port: (%d, %v)", n, ok)
	}
}

func TestListHelper(t *testing.T) {
	f, _ := parse([]byte(sample))
	got, ok := f.List("domains")
	if !ok {
		t.Fatal("domains missing")
	}
	want := []string{"example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("domains: got %v want %v", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.conf")
	f, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Top, f.Top) {
		t.Errorf("top differs:\n  got %v\n want %v", got.Top, f.Top)
	}
	// Compare semantically: scalars equal, lists equal (configobj normalizes
	// list separators on write, so the raw map value is allowed to differ).
	wantDomains, _ := f.List("domains")
	gotDomains, _ := got.List("domains")
	if !reflect.DeepEqual(wantDomains, gotDomains) {
		t.Errorf("domains differ:\n  got %v\n want %v", gotDomains, wantDomains)
	}
	for k := range f.RenewalParams {
		if k == "domains" {
			continue
		}
		if got.RenewalParams[k] != f.RenewalParams[k] {
			t.Errorf("param %s differs: got %q want %q", k, got.RenewalParams[k], f.RenewalParams[k])
		}
	}
}

func TestFormatValueListSemantics(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"a=b", "a=b"},   // bare = is fine for configobj
		{"a.com,b.com", "a.com, b.com"},
		{"a.com,", "a.com,"}, // single-element keeps trailing comma
		{"a.com, b.com,c.com", "a.com, b.com, c.com"},
		{"foo bar", "foo bar"}, // internal space allowed bare
		{"\"already quoted\"", "\"already quoted\""},
		{"'sq'", "'sq'"},
		{"has#hash", "\"has#hash\""},
		{" leading", "\" leading\""},
	} {
		if got := formatValue(tc.in); got != tc.want {
			t.Errorf("formatValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPreservesInsertionOrder(t *testing.T) {
	f := New()
	f.SetTop("cert", "/a")
	f.SetTop("privkey", "/b")
	f.SetParam("authenticator", "standalone")
	f.SetParam("server", "https://x")
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b, "cert = /a\nprivkey = /b\n") {
		t.Errorf("top order not preserved:\n%s", b)
	}
	if !strings.Contains(b, "authenticator = standalone\nserver = https://x\n") {
		t.Errorf("param order not preserved:\n%s", b)
	}
}
