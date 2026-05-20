package webroot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v5/challenge/http01"

	"github.com/letsencrypt/go-certbot/internal/config"
)

func TestPresentWritesChallenge(t *testing.T) {
	dir := t.TempDir()
	auth := New()
	cfg := config.NewDefault()
	cfg.WebrootPath = []string{dir}
	if _, err := auth.PrepareHTTP01(context.Background(), cfg, []string{"example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.Present(context.Background(), "example.test", "tok", "keyAuth"); err != nil {
		t.Fatal(err)
	}
	wanted := filepath.Join(dir, http01.ChallengePath("tok"))
	b, err := os.ReadFile(wanted)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "keyAuth" {
		t.Errorf("file body = %q", string(b))
	}
	if err := auth.CleanUp(context.Background(), "example.test", "tok", "keyAuth"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wanted); !os.IsNotExist(err) {
		t.Errorf("challenge file should have been removed: %v", err)
	}
}

func TestPerDomainMap(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	auth := New()
	cfg := config.NewDefault()
	cfg.WebrootPath = []string{dirA, dirB}
	if _, err := auth.PrepareHTTP01(context.Background(), cfg, []string{"a.test", "b.test"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.Present(context.Background(), "a.test", "ta", "ka"); err != nil {
		t.Fatal(err)
	}
	if err := auth.Present(context.Background(), "b.test", "tb", "kb"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dirA, http01.ChallengePath("ta"))); err != nil {
		t.Errorf("dirA didn't receive its token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirB, http01.ChallengePath("tb"))); err != nil {
		t.Errorf("dirB didn't receive its token: %v", err)
	}
}

func TestMissingWebrootPath(t *testing.T) {
	auth := New()
	cfg := config.NewDefault()
	if _, err := auth.PrepareHTTP01(context.Background(), cfg, []string{"x.test"}); err == nil {
		t.Errorf("expected error when no webroot path is given")
	}
}
