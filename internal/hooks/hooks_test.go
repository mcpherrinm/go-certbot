package hooks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunSucceeds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh required")
	}
	ctx := context.Background()
	if err := Run(ctx, "true", nil); err != nil {
		t.Fatal(err)
	}
}

func TestRunFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh required")
	}
	ctx := context.Background()
	if err := Run(ctx, "false", nil); err == nil {
		t.Fatal("expected failure")
	}
}

func TestRunCapturePassesEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh required")
	}
	ctx := context.Background()
	got, err := RunCapture(ctx, `printf "%s|%s" "$CERTBOT_DOMAIN" "$CERTBOT_VALIDATION"`,
		[]string{"CERTBOT_DOMAIN=example.test", "CERTBOT_VALIDATION=hello"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.test|hello" {
		t.Errorf("got %q", got)
	}
}

func TestRunDirRunsExecutables(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh + chmod required")
	}
	dir := t.TempDir()
	stamp := filepath.Join(dir, "ran")
	script := filepath.Join(dir, "01-write")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi > "+stamp+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Also write a non-executable file that should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "02-skip"), []byte("not me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunDir(context.Background(), dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stamp); err != nil {
		t.Errorf("script didn't run: %v", err)
	}
}

func TestDeployEnv(t *testing.T) {
	env := DeployEnv("/etc/letsencrypt/live/example.com", []string{"example.com", "www.example.com"})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "RENEWED_LINEAGE=/etc/letsencrypt/live/example.com") {
		t.Errorf("missing lineage var:\n%s", joined)
	}
	if !strings.Contains(joined, "RENEWED_DOMAINS=example.com www.example.com") {
		t.Errorf("missing domains var:\n%s", joined)
	}
}

func TestValidate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH semantics differ")
	}
	if err := Validate("true", "pre"); err != nil {
		t.Errorf("expected `true` to validate: %v", err)
	}
	if err := Validate("definitely-not-on-path-12345", "pre"); err == nil {
		t.Errorf("expected error for missing command")
	}
	if err := Validate("", "pre"); err != nil {
		t.Errorf("empty command should be ok: %v", err)
	}
}
