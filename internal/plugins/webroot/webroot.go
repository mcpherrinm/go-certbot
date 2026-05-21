// Package webroot writes http-01 challenge files into one or more webroot
// directories. Honors Certbot's --webroot-path / -w semantics:
//
//   - A pre-built cfg.WebrootMap (domain → path) is used when present
//     (built by the CLI from `-w`/`-d` argv interleaving).
//   - Otherwise a single --webroot-path applies to every domain.
//   - N paths for N domains is rejected (use the map form via interleaved
//     `-w` / `-d`).
package webroot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/http01"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Authenticator implements the webroot HTTP-01 provider.
type Authenticator struct {
	mu           sync.Mutex
	domainPaths  map[string]string
	writtenFiles []string
	// createdDirs tracks directories we created so Cleanup can rmdir them.
	createdDirs []string
}

func New() *Authenticator { return &Authenticator{} }

func (a *Authenticator) Name() string { return "webroot" }
func (a *Authenticator) Description() string {
	return "Place files in a server's webroot folder for authentication."
}

// Prepare resolves the domain→webroot map. Uses cfg.WebrootMap when set (the
// CLI builds it from -w/-d interleaving) and falls back to --webroot-path
// applied to every domain. When a map is set but some domains are unmapped,
// the LAST --webroot-path entry is used as the fallback (matches Certbot's
// webroot.py:_set_webroot — `self.conf("path")[-1]`).
func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, domains []string) (plugins.ChallengeKind, challenge.Provider, error) {
	// fallback path for unmapped domains. Certbot uses the last `-w` from the
	// command line (webroot.py:_set_webroot 117-122).
	var fallback string
	if n := len(cfg.WebrootPath); n > 0 {
		fallback = cfg.WebrootPath[n-1]
	}

	if len(cfg.WebrootMap) > 0 {
		a.domainPaths = map[string]string{}
		for d, p := range cfg.WebrootMap {
			abs, err := absPath(p)
			if err != nil {
				return 0, nil, err
			}
			a.domainPaths[d] = abs
			if fallback == "" {
				fallback = abs
			}
		}
		for _, d := range domains {
			if _, ok := a.domainPaths[d]; !ok {
				if fallback == "" {
					return 0, nil, fmt.Errorf("webroot: no webroot configured for domain %q", d)
				}
				if abs, err := absPath(fallback); err == nil {
					a.domainPaths[d] = abs
				} else {
					return 0, nil, err
				}
			}
		}
		return plugins.HTTP01, a, nil
	}

	if fallback == "" {
		return 0, nil, errors.New("webroot: at least one --webroot-path is required")
	}
	abs, err := absPath(fallback)
	if err != nil {
		return 0, nil, err
	}
	a.domainPaths = map[string]string{}
	for _, d := range domains {
		a.domainPaths[d] = abs
	}
	return plugins.HTTP01, a, nil
}

// absPath resolves p to an absolute path and verifies it's an existing dir.
// Certbot's _validate_webroot stores the abspath so renewal.conf survives a
// working-directory change (webroot.py:_validate_webroot).
func absPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("webroot: abspath %s: %w", p, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("webroot: %s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("webroot: %s is not a directory", abs)
	}
	return abs, nil
}

func (a *Authenticator) Cleanup(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Best-effort removal of leftover challenge files.
	for _, f := range a.writtenFiles {
		_ = os.Remove(f)
	}
	a.writtenFiles = nil
	// Remove `.well-known/acme-challenge/` and `.well-known/` if we
	// created them and they're now empty. Matches Certbot's
	// webroot.py:cleanup (_created_dirs).
	for i := len(a.createdDirs) - 1; i >= 0; i-- {
		_ = os.Remove(a.createdDirs[i])
	}
	a.createdDirs = nil
	return nil
}

// Present implements lego's challenge.Provider for HTTP-01.
func (a *Authenticator) Present(_ context.Context, domain, token, keyAuth string) error {
	path, ok := a.domainPaths[domain]
	if !ok {
		return fmt.Errorf("webroot: no webroot configured for domain %q", domain)
	}
	challengePath := filepath.Join(path, http01.ChallengePath(token))
	challengeDir := filepath.Dir(challengePath)

	// Determine which prefix dirs we'll need to create so Cleanup can rmdir
	// them later. Walks every prefix between `path` (exclusive) and
	// `challengeDir` (inclusive), recording those that don't yet exist.
	// Matches Certbot's webroot.py:_create_challenge_dirs which uses
	// util.get_prefixes(full_root)[:-1].
	var toCreate []string
	for dir := challengeDir; dir != path && dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			toCreate = append([]string{dir}, toCreate...)
		}
	}
	if err := os.MkdirAll(challengeDir, 0o755); err != nil {
		return fmt.Errorf("webroot: mkdir %s: %w", challengeDir, err)
	}
	if err := os.WriteFile(challengePath, []byte(keyAuth), 0o644); err != nil {
		return fmt.Errorf("webroot: write %s: %w", challengePath, err)
	}
	a.mu.Lock()
	a.writtenFiles = append(a.writtenFiles, challengePath)
	a.createdDirs = append(a.createdDirs, toCreate...)
	a.mu.Unlock()
	return nil
}

// CleanUp implements lego's challenge.Provider (per-challenge cleanup).
func (a *Authenticator) CleanUp(_ context.Context, domain, token, _ string) error {
	path, ok := a.domainPaths[domain]
	if !ok {
		return nil
	}
	return os.Remove(filepath.Join(path, http01.ChallengePath(token)))
}
