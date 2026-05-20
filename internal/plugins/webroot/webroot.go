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

// PrepareHTTP01 resolves the domain→webroot map.
func (a *Authenticator) PrepareHTTP01(_ context.Context, cfg *config.Config, domains []string) (challenge.Provider, error) {
	if len(cfg.WebrootMap) > 0 {
		a.domainPaths = map[string]string{}
		for d, p := range cfg.WebrootMap {
			if _, err := os.Stat(p); err != nil {
				return nil, fmt.Errorf("webroot: %s: %w", p, err)
			}
			a.domainPaths[d] = p
		}
		// Ensure every requested domain has an entry. If not, fall back to
		// the first webroot path for unmapped domains (matches Certbot's
		// _set_webroot_for_unmapped behavior).
		var fallback string
		for _, p := range a.domainPaths {
			fallback = p
			break
		}
		for _, d := range domains {
			if _, ok := a.domainPaths[d]; !ok {
				a.domainPaths[d] = fallback
			}
		}
		return a, nil
	}
	if len(cfg.WebrootPath) == 0 {
		return nil, errors.New("webroot: at least one --webroot-path is required")
	}
	if len(cfg.WebrootPath) != 1 {
		return nil, errors.New("webroot: multiple --webroot-path values require interleaving with -d to form a per-domain map")
	}
	path := cfg.WebrootPath[0]
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("webroot: %s: %w", path, err)
	}
	a.domainPaths = map[string]string{}
	for _, d := range domains {
		a.domainPaths[d] = path
	}
	return a, nil
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
	a.mu.Lock()
	// Track each directory we have to create so Cleanup can rmdir them.
	for _, dir := range []string{
		filepath.Join(path, ".well-known"),
		filepath.Join(path, ".well-known", "acme-challenge"),
	} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			a.createdDirs = append(a.createdDirs, dir)
		}
	}
	a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(challengePath), 0o755); err != nil {
		return fmt.Errorf("webroot: mkdir %s: %w", challengePath, err)
	}
	if err := os.WriteFile(challengePath, []byte(keyAuth), 0o644); err != nil {
		return fmt.Errorf("webroot: write %s: %w", challengePath, err)
	}
	a.mu.Lock()
	a.writtenFiles = append(a.writtenFiles, challengePath)
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
