// Package hooks runs the pre/post/deploy commands and directory-based
// renewal-hooks/{pre,post,deploy}/* scripts. Mirrors certbot/_internal/hooks.py
// behavior:
//
//   - pre_hook runs before any challenge work for any cert.
//   - post_hook runs after all work for all certs, regardless of outcome.
//   - deploy_hook runs only after a successful issuance/renewal, once per
//     cert lineage, with CERTBOT_DOMAIN/CERTBOT_VALIDATION-style env.
//   - renewal-hooks/{pre,post,deploy}/* are run alongside the matching flag
//     hook.
//
// Hook commands are executed with the system shell ("sh -c" on Unix, "cmd /c"
// on Windows) to support Certbot's "pre-hook = systemctl stop nginx" style.
package hooks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Env is the deploy-hook environment that mirrors Certbot's contract.
type Env struct {
	// RenewedLineage is the absolute path to live/<certname>/.
	RenewedLineage string
	// RenewedDomains is a space-separated list of SANs.
	RenewedDomains string
}

// Run executes `command` via the system shell, streaming stdout/stderr to the
// caller's process. Extra env entries are passed as "KEY=VAL". Returns a
// non-nil error if the command exits non-zero.
func Run(ctx context.Context, command string, extraEnv []string) error {
	if command == "" {
		return nil
	}
	cmd := shellCommand(ctx, command)
	cmd.Env = append(os.Environ(), extraEnv...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Certbot's contract: hook stderr is surfaced verbatim.
		if stderr.Len() > 0 {
			fmt.Fprint(os.Stderr, stderr.String())
		}
		return fmt.Errorf("hook %q: %w", command, err)
	}
	if stderr.Len() > 0 {
		fmt.Fprint(os.Stderr, stderr.String())
	}
	return nil
}

// RunCapture runs the command and returns its trimmed stdout.
// Used by the manual plugin to surface auth-script output as $CERTBOT_AUTH_OUTPUT.
func RunCapture(ctx context.Context, command string, extraEnv []string) (string, error) {
	if command == "" {
		return "", nil
	}
	cmd := shellCommand(ctx, command)
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			fmt.Fprint(os.Stderr, stderr.String())
		}
		return "", fmt.Errorf("hook %q: %w", command, err)
	}
	if stderr.Len() > 0 {
		fmt.Fprint(os.Stderr, stderr.String())
	}
	return strings.TrimRight(stdout.String(), "\r\n"), nil
}

// RunDir executes every executable file under dir, in lexicographic order.
// Missing dir is not an error. dedupAgainst is the flag-hook command (if
// any) — if a directory hook resolves to the same path (e.g. via symlink)
// it's skipped so users who symlink their --deploy-hook into
// renewal-hooks/deploy/ don't see it run twice.
func RunDir(ctx context.Context, dir string, extraEnv []string, dedupAgainst ...string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hooks: read %s: %w", dir, err)
	}
	skip := map[string]bool{}
	for _, h := range dedupAgainst {
		if h == "" {
			continue
		}
		// dedup on absolute path of the command's first word.
		first := strings.Fields(h)[0]
		if abs, err := filepath.Abs(first); err == nil {
			if real, err := filepath.EvalSymlinks(abs); err == nil {
				skip[real] = true
			} else {
				skip[abs] = true
			}
		}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Skip editor backup files. Matches Certbot's list_hooks
		// (hooks.py:276) `not path.endswith('~')`.
		if strings.HasSuffix(e.Name(), "~") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		full := filepath.Join(dir, name)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if !isExecutable(info) {
			slog.Warn("skipping non-executable hook", "path", full)
			continue
		}
		// Check dedup match against the resolved target (the entry may be a
		// symlink into ../../<somewhere-else>/<hook>).
		resolved := full
		if r, err := filepath.EvalSymlinks(full); err == nil {
			resolved = r
		}
		if skip[resolved] {
			slog.Info("skipping directory hook duplicating flag hook", "path", full)
			continue
		}
		slog.Info("running hook", "path", full)
		cmd := exec.CommandContext(ctx, full)
		cmd.Env = append(os.Environ(), extraEnv...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("hooks: %s: %w", full, err)
		}
	}
	return nil
}

// Validate checks that the given hook command's first word is executable in
// PATH. Empty commands return nil.
func Validate(command, label string) error {
	if command == "" {
		return nil
	}
	prog := strings.Fields(command)[0]
	if _, err := exec.LookPath(prog); err != nil {
		// Allow absolute paths that exist but aren't on PATH.
		if filepath.IsAbs(prog) {
			if info, statErr := os.Stat(prog); statErr == nil && isExecutable(info) {
				return nil
			}
		}
		return fmt.Errorf("%s-hook command %q is not executable", label, prog)
	}
	return nil
}

func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/c", command)
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

func isExecutable(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0
}

// DeployEnv builds the env slice for a deploy-hook invocation. Certbot
// guarantees these vars (see hooks.py:243-244):
//
//	RENEWED_LINEAGE=<live/<certname>>
//	RENEWED_DOMAINS=<space-separated SANs>
func DeployEnv(lineagePath string, domains []string) []string {
	return []string{
		"RENEWED_LINEAGE=" + lineagePath,
		"RENEWED_DOMAINS=" + strings.Join(domains, " "),
	}
}

// PostEnv builds the env slice for a post-hook invocation:
//
//	RENEWED_DOMAINS=<space-separated SANs of newly renewed certs>
//	FAILED_DOMAINS=<space-separated SANs of certs that failed>
//
// Matches certbot/_internal/hooks.py:run_saved_post_hooks. Per Certbot,
// non-renew verbs (run/certonly) pass FAILED_DOMAINS="". The combined
// limit is 32 KiB on Windows-friendly envs (Certbot caps each at 16k for
// the renew path, 32k for non-renew). Beyond that we truncate and log,
// matching hooks.py:173-179.
func PostEnv(renewed, failed []string) []string {
	const max = 16 * 1024
	rJoined := truncatedJoin(renewed, max, "RENEWED_DOMAINS")
	fJoined := truncatedJoin(failed, max, "FAILED_DOMAINS")
	return []string{
		"RENEWED_DOMAINS=" + rJoined,
		"FAILED_DOMAINS=" + fJoined,
	}
}

// truncatedJoin space-joins items and truncates to maxBytes, emitting a
// warning to stderr matching Certbot's wording.
func truncatedJoin(items []string, maxBytes int, name string) string {
	s := strings.Join(items, " ")
	if len(s) > maxBytes {
		fmt.Fprintf(os.Stderr, "Limiting %s environment variable to %dk characters\n", name, maxBytes/1024)
		s = s[:maxBytes]
	}
	return s
}

// PreRunner deduplicates pre-hook commands so identical pre-hooks (e.g. one
// per lineage from a multi-cert renew) only fire once per process. Mirrors
// certbot/_internal/hooks.py:executed_pre_hooks.
type PreRunner struct {
	ran map[string]bool
}

// NewPreRunner returns a fresh PreRunner.
func NewPreRunner() *PreRunner { return &PreRunner{ran: map[string]bool{}} }

// Run executes cmd once. Subsequent calls with the same command string are
// no-ops.
func (p *PreRunner) Run(ctx context.Context, cmd string) error {
	if cmd == "" || p.ran[cmd] {
		return nil
	}
	p.ran[cmd] = true
	return Run(ctx, cmd, nil)
}

// RunDirIf is RunDir gated by enabled. The shorter syntax centralizes the
// --directory-hooks/--no-directory-hooks toggle at call sites.
func RunDirIf(ctx context.Context, enabled bool, dir string, env []string, dedup ...string) error {
	if !enabled {
		return nil
	}
	return RunDir(ctx, dir, env, dedup...)
}
