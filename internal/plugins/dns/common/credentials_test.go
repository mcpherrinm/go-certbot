package common

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCredentialsFiltersByPrefix(t *testing.T) {
	dir := t.TempDir()
	body := `
dns_cloudflare_api_token = abc
dns_cloudflare_email = foo@example.com
unrelated_key = nope
dns_route53_access_key_id = AKIA...
`
	p := write(t, dir, "cf.ini", body)
	cred, err := LoadCredentials(p, "dns_cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Get("api_token") != "abc" {
		t.Errorf("api_token: %q", cred.Get("api_token"))
	}
	if cred.Get("email") != "foo@example.com" {
		t.Errorf("email: %q", cred.Get("email"))
	}
	if cred.Get("access_key_id") != "" {
		t.Errorf("route53 keys should have been filtered out")
	}
	if cred.Get("unrelated_key") != "" {
		t.Errorf("non-prefixed keys should have been filtered out")
	}
}

func TestRequiredErrorsOnMissing(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.ini", "dns_test_present = yes\n")
	cred, err := LoadCredentials(p, "dns_test")
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.Required("present"); err != nil {
		t.Errorf("present should not error: %v", err)
	}
	if err := cred.Required("missing"); err == nil {
		t.Errorf("missing should error")
	}
}

func TestAnyOf(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.ini", "dns_test_b = yes\n")
	cred, _ := LoadCredentials(p, "dns_test")
	if got := cred.AnyOf("a", "b", "c"); got != "b" {
		t.Errorf("AnyOf: %q", got)
	}
	if got := cred.AnyOf("a", "c"); got != "" {
		t.Errorf("AnyOf no match: %q", got)
	}
}

func TestSetEnv(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.ini", "dns_test_token = tok\n")
	cred, _ := LoadCredentials(p, "dns_test")
	t.Setenv("X_TOKEN", "")
	if err := cred.SetEnv("token", "X_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("X_TOKEN") != "tok" {
		t.Errorf("env not set: %q", os.Getenv("X_TOKEN"))
	}
}

func TestLoadCredentialsMissingFile(t *testing.T) {
	if _, err := LoadCredentials("/nonexistent/path.ini", "dns_test"); err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestLoadCredentialsEmptyPath(t *testing.T) {
	if _, err := LoadCredentials("", "dns_cloudflare"); err == nil {
		t.Errorf("expected error for empty path")
	}
}
