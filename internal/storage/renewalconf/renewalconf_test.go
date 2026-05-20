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
	if !reflect.DeepEqual(got.RenewalParams, f.RenewalParams) {
		t.Errorf("params differ:\n  got %v\n want %v", got.RenewalParams, f.RenewalParams)
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
