package renewalconf

import (
	"os"
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
		{"a=b", "a=b"}, // bare = is fine for configobj
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

// TestStripInlineComment exercises the configobj-compatible inline-comment
// stripping. Mirrors certbot/_internal/tests/storage_test.py:749-780 which
// asserts `useful = value # A useful value` round-trips to a value of just
// "value".
func TestStripInlineComment(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"foo", "foo"},
		{"foo # bar", "foo"},
		{"foo  # bar", "foo"},
		{`"foo # bar"`, `"foo # bar"`},
		{`'foo # bar'`, `'foo # bar'`},
		{"# all-comment", ""},
		{"value # configobj inline", "value"},
	} {
		if got := stripInlineComment(tc.in); got != tc.want {
			t.Errorf("stripInlineComment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLoadStripsInlineComment is the end-to-end version: a conf line
// `useful = value # comment` should parse with value == "value".
func TestLoadStripsInlineComment(t *testing.T) {
	src := `[renewalparams]
authenticator = standalone # set by certbot
key_type = ecdsa
`
	f, err := parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.RenewalParams["authenticator"]; got != "standalone" {
		t.Errorf("authenticator = %q, want \"standalone\"", got)
	}
}

// TestLoadPreservesUnknownSections asserts that a renewal conf with an
// [acme_renewal_info] section can be loaded, mutated, and saved without
// losing the section. Mirrors the ARI Retry-After persistence contract:
// Certbot writes [acme_renewal_info] and expects go-certbot to leave it
// alone on subsequent renewals, and vice versa.
func TestLoadPreservesUnknownSections(t *testing.T) {
	src := `version = 1.4.0
archive_dir = /etc/letsencrypt/archive/example.com
cert = /etc/letsencrypt/live/example.com/cert.pem
privkey = /etc/letsencrypt/live/example.com/privkey.pem

[renewalparams]
authenticator = standalone
server = https://acme-v02.api.letsencrypt.org/directory

[acme_renewal_info]
ari_retry_after = 2026-05-21T12:34:56
`
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.conf")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate a known [renewalparams] key.
	f.SetParam("server", "https://acme-staging-v02.api.letsencrypt.org/directory")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "[acme_renewal_info]") {
		t.Errorf("[acme_renewal_info] section dropped on round-trip:\n%s", got)
	}
	if !strings.Contains(got, "ari_retry_after = 2026-05-21T12:34:56") {
		t.Errorf("ari_retry_after value dropped on round-trip:\n%s", got)
	}
	if !strings.Contains(got, "server = https://acme-staging-v02.api.letsencrypt.org/directory") {
		t.Errorf("server param not updated:\n%s", got)
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

func TestSavePreservesMode(t *testing.T) {
	if testing.Short() {
		t.Skip("perm test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "example.conf")
	if err := os.WriteFile(path, []byte("version = 5.6.0\ncert = /a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f.SetTop("cert", "/changed")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Errorf("perm after rewrite: got %o want 0640 (mirrors certbot test_atomic_rewrite)", got)
	}
}
