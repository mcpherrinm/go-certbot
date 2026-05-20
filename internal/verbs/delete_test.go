package verbs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/letsencrypt/go-certbot/internal/config"
)

func TestDeleteRemovesAllArtifacts(t *testing.T) {
	root := t.TempDir()
	cfg := config.NewDefault()
	cfg.ConfigDir = root
	cfg.CertName = "example.test"
	cfg.NonInteractive = true

	live := filepath.Join(root, "live", "example.test")
	arch := filepath.Join(root, "archive", "example.test")
	renew := filepath.Join(root, "renewal", "example.test.conf")
	for _, d := range []string{live, arch, filepath.Dir(renew)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{filepath.Join(live, "cert.pem"), filepath.Join(arch, "cert1.pem"), renew} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := Delete(context.Background(), cfg, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{live, arch, renew} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should be gone: err=%v", p, err)
		}
	}
}

func TestDeleteWithoutCertNameErrors(t *testing.T) {
	cfg := config.NewDefault()
	cfg.NonInteractive = true
	if err := Delete(context.Background(), cfg, nil); err == nil {
		t.Errorf("expected error without --cert-name")
	}
}

func TestDeleteMissingLineageErrors(t *testing.T) {
	cfg := config.NewDefault()
	cfg.ConfigDir = t.TempDir()
	cfg.CertName = "nope.test"
	cfg.NonInteractive = true
	if err := Delete(context.Background(), cfg, nil); err == nil {
		t.Errorf("expected error for unknown cert-name")
	}
}
