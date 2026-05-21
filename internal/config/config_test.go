package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestServerPath(t *testing.T) {
	c := NewDefault()
	c.Server = "https://acme-v02.api.letsencrypt.org/directory"
	got, err := c.ServerPath()
	if err != nil {
		t.Fatal(err)
	}
	want := "acme-v02.api.letsencrypt.org" + string(filepath.Separator) + "directory"
	if got != want {
		t.Errorf("ServerPath: got %q want %q", got, want)
	}
}

func TestStagingOverride(t *testing.T) {
	c := NewDefault()
	c.Staging = true
	if got := c.EffectiveServer(); got != StagingDirectory {
		t.Errorf("EffectiveServer with --staging: got %q", got)
	}
	c.Server = "https://example.test/dir"
	if got := c.EffectiveServer(); got != "https://example.test/dir" {
		t.Errorf("--server should win over --staging when set: got %q", got)
	}
}

func TestAccountsDir(t *testing.T) {
	c := NewDefault()
	c.ConfigDir = "/etc/letsencrypt"
	d, err := c.AccountsDir()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // sep different
	}
	if d != "/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("AccountsDir: %q", d)
	}
}

func TestSetByUser(t *testing.T) {
	c := NewDefault()
	if c.SetByUser("server") {
		t.Errorf("freshly created config should not report server as user-set")
	}
	c.MarkSet("server", SourceCommandLine)
	if !c.SetByUser("server") {
		t.Errorf("expected server to be user-set")
	}
}
