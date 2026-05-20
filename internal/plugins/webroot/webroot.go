// Package webroot writes http-01 challenge files into one or more webroot
// directories. Honors Certbot's --webroot-path / -w semantics: a single path
// applies to every domain in the request, while multiple paths interleaved
// with -d flags produce a per-domain map (resolved by the CLI before getting
// here). For Phase 2 we accept either a single path used for all domains, or
// a pre-built domain→path map.
package webroot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/http01"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// Authenticator implements the webroot HTTP-01 provider.
type Authenticator struct {
	// DomainPaths maps domain → webroot path. Populated in PrepareHTTP01.
	domainPaths map[string]string
	// Files written, for CleanUp.
	writtenFiles []string
}

func New() *Authenticator { return &Authenticator{} }

func (a *Authenticator) Name() string { return "webroot" }
func (a *Authenticator) Description() string {
	return "Place files in a server's webroot folder for authentication."
}

// PrepareHTTP01 builds the domain→path map from cfg.WebrootPath (single path
// applied to all domains, or one-per-domain in argv order — Certbot allows
// both).
func (a *Authenticator) PrepareHTTP01(_ context.Context, cfg *config.Config, domains []string) (challenge.Provider, error) {
	if len(cfg.WebrootPath) == 0 {
		return nil, errors.New("webroot: at least one --webroot-path is required")
	}
	a.domainPaths = map[string]string{}
	switch {
	case len(cfg.WebrootPath) == 1:
		// Single path for every domain. Certbot's most common usage.
		path := cfg.WebrootPath[0]
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("webroot: %s: %w", path, err)
		}
		for _, d := range domains {
			a.domainPaths[d] = path
		}
	case len(cfg.WebrootPath) == len(domains):
		// One-to-one: argv positions are interpreted as a per-domain map.
		// This matches `-w /var/www/a -d a.example.com -w /var/www/b -d b.example.com`
		// after the CLI flattens the interleaving.
		for i, d := range domains {
			path := cfg.WebrootPath[i]
			if _, err := os.Stat(path); err != nil {
				return nil, fmt.Errorf("webroot: %s: %w", path, err)
			}
			a.domainPaths[d] = path
		}
	default:
		return nil, fmt.Errorf("webroot: %d --webroot-path values for %d domains; expected 1 or %d",
			len(cfg.WebrootPath), len(domains), len(domains))
	}
	return a, nil
}

func (a *Authenticator) Cleanup(_ context.Context) error {
	// Best-effort removal of anything still left behind.
	for _, f := range a.writtenFiles {
		_ = os.Remove(f)
	}
	a.writtenFiles = nil
	return nil
}

// Present implements lego's challenge.Provider for HTTP-01.
func (a *Authenticator) Present(_ context.Context, domain, token, keyAuth string) error {
	path, ok := a.domainPaths[domain]
	if !ok {
		return fmt.Errorf("webroot: no webroot configured for domain %q", domain)
	}
	challengePath := filepath.Join(path, http01.ChallengePath(token))
	if err := os.MkdirAll(filepath.Dir(challengePath), 0o755); err != nil {
		return fmt.Errorf("webroot: mkdir %s: %w", challengePath, err)
	}
	if err := os.WriteFile(challengePath, []byte(keyAuth), 0o644); err != nil {
		return fmt.Errorf("webroot: write %s: %w", challengePath, err)
	}
	a.writtenFiles = append(a.writtenFiles, challengePath)
	return nil
}

// CleanUp implements lego's challenge.Provider.
func (a *Authenticator) CleanUp(_ context.Context, domain, token, _ string) error {
	path, ok := a.domainPaths[domain]
	if !ok {
		return nil
	}
	return os.Remove(filepath.Join(path, http01.ChallengePath(token)))
}
