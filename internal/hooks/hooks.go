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
// Missing dir is not an error.
func RunDir(ctx context.Context, dir string, extraEnv []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hooks: read %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
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
