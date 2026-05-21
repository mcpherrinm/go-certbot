package manual

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// TestPresentRunsAuthHook verifies the manual plugin invokes the auth hook
// with Certbot's documented env vars and that cleanup receives the captured
// AUTH_OUTPUT.
func TestPresentRunsAuthHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh-based hook")
	}
	dir := t.TempDir()
	authOut := filepath.Join(dir, "auth.out")
	cleanupOut := filepath.Join(dir, "cleanup.out")

	authScript := filepath.Join(dir, "auth.sh")
	cleanupScript := filepath.Join(dir, "cleanup.sh")

	const auth = `#!/bin/sh
echo "$CERTBOT_DOMAIN $CERTBOT_VALIDATION $CERTBOT_TOKEN" > AUTHFILE
echo "captured-stdout"
`
	const cleanup = `#!/bin/sh
echo "$CERTBOT_DOMAIN $CERTBOT_AUTH_OUTPUT" > CLEANFILE
`
	if err := os.WriteFile(authScript, []byte(strings.ReplaceAll(auth, "AUTHFILE", authOut)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cleanupScript, []byte(strings.ReplaceAll(cleanup, "CLEANFILE", cleanupOut)), 0o755); err != nil {
		t.Fatal(err)
	}

	a := New()
	cfg := config.NewDefault()
	cfg.ManualAuthHook = authScript
	cfg.ManualCleanupHook = cleanupScript
	if _, err := a.PrepareHTTP01(context.Background(), cfg, []string{"example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Present(context.Background(), "example.test", "thetoken", "thekeyauth"); err != nil {
		t.Fatal(err)
	}
	if err := a.CleanUp(context.Background(), "example.test", "thetoken", "thekeyauth"); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(authOut)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "example.test thekeyauth thetoken" {
		t.Errorf("auth env: got %q", got)
	}
	c, err := os.ReadFile(cleanupOut)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(c)); got != "example.test captured-stdout" {
		t.Errorf("cleanup env: got %q (expected CERTBOT_AUTH_OUTPUT to carry over)", got)
	}
}

func TestPrepareWithoutAuthHookErrors(t *testing.T) {
	a := New()
	cfg := config.NewDefault()
	if _, err := a.PrepareHTTP01(context.Background(), cfg, []string{"x"}); err == nil {
		t.Errorf("expected error without --manual-auth-hook")
	}
}
