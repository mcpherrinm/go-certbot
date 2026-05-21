package checkpoint

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndRestoreRoundTrip(t *testing.T) {
	work := t.TempDir()
	target := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(target, []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(work, "test-1", []string{target}); err != nil {
		t.Fatal(err)
	}
	MarkClean()
	// Mutate.
	if err := os.WriteFile(target, []byte("server { listen 443 ssl; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Restore(work, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != target {
		t.Errorf("changed = %v", changed)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "server { listen 80; }\n" {
		t.Errorf("restored content = %q", got)
	}
}

func TestRestoreNothingErrors(t *testing.T) {
	work := t.TempDir()
	if _, err := Restore(work, 1); err == nil {
		t.Errorf("expected error when no checkpoints exist")
	}
}

func TestRestoreUndoesCheckpoints(t *testing.T) {
	work := t.TempDir()
	target := filepath.Join(t.TempDir(), "x.conf")
	os.WriteFile(target, []byte("v1\n"), 0o644)
	if _, err := Save(work, "c1", []string{target}); err != nil {
		t.Fatal(err)
	}
	MarkClean()
	os.WriteFile(target, []byte("v2\n"), 0o644)
	// Sleep briefly to ensure the next checkpoint gets a strictly-later
	// timestamp (Certbot's monotonicity tiebreaker depends on this).
	time.Sleep(2 * time.Millisecond)
	if _, err := Save(work, "c2", []string{target}); err != nil {
		t.Fatal(err)
	}
	MarkClean()
	os.WriteFile(target, []byte("v3\n"), 0o644)

	// Roll back 1 → should restore v2.
	if _, err := Restore(work, 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "v2\n" {
		t.Errorf("after 1 rollback, content = %q (want v2)", got)
	}
	// Roll back 1 more → restore v1.
	if _, err := Restore(work, 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "v1\n" {
		t.Errorf("after 2nd rollback, content = %q (want v1)", got)
	}
	// No more checkpoints.
	if _, err := Restore(work, 1); err == nil {
		t.Errorf("expected error after exhausting checkpoints")
	}
}

func TestSaveSkipsMissingFiles(t *testing.T) {
	work := t.TempDir()
	dir, err := Save(work, "no-such", []string{filepath.Join(t.TempDir(), "does-not-exist")})
	if err != nil {
		t.Fatal(err)
	}
	if dir != "" {
		t.Errorf("expected empty dir for no-file-to-snapshot, got %q", dir)
	}
}
