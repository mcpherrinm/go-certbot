// Package manual implements Certbot's --manual plugin. Users supply
// --manual-auth-hook and --manual-cleanup-hook scripts that publish/remove the
// http-01 file or dns-01 TXT record. The plugin is the bridge that lets a
// third-party DNS provider keep working with go-certbot — write a hook script
// that calls your favorite tool.
//
// Environment passed to hooks (matches certbot/_internal/plugins/manual.py:188):
//
//	CERTBOT_DOMAIN               the domain being authenticated
//	CERTBOT_VALIDATION           keyAuth (http-01) / base64url(sha256(keyAuth)) (dns-01)
//	CERTBOT_TOKEN                http-01 challenge token (http-01 only)
//	CERTBOT_AUTH_OUTPUT          stdout of the auth script, passed to cleanup
//	CERTBOT_ALL_DOMAINS          comma-separated list of all domains in order
//	CERTBOT_REMAINING_CHALLENGES challenges that follow the current one
//	CERTBOT_IDENTIFIER           alias for CERTBOT_DOMAIN (RFC 8738 IP-friendly)
//	CERTBOT_ALL_IDENTIFIERS      alias for CERTBOT_ALL_DOMAINS
package manual

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/hooks"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Authenticator backs --manual.
type Authenticator struct {
	authHook    string
	cleanupHook string
	allDomains  []string
	kind        plugins.ChallengeKind
	// presented counts Present calls; the N-th call (0-indexed) gets
	// CERTBOT_REMAINING_CHALLENGES = len(allDomains) - N - 1, matching
	// Certbot's manual.py:195.
	presented atomic.Int64

	mu sync.Mutex
	// perDomainEnv holds the env we passed at Present time so CleanUp
	// replays the same REMAINING_CHALLENGES + CERTBOT_VALIDATION values.
	perDomainEnv map[string][]string
	authOutputs  map[string]string
}

func New() *Authenticator {
	return &Authenticator{
		perDomainEnv: map[string][]string{},
		authOutputs:  map[string]string{},
	}
}

func (a *Authenticator) Name() string { return "manual" }
func (a *Authenticator) Description() string {
	return "Manual configuration or running of shell scripts to fulfill ACME challenges."
}

// Prepare returns the plugin acting as a lego challenge.Provider for whichever
// challenge type the user picked. Defaults to http-01 unless
// --preferred-challenges=dns-01 is set, matching Certbot's behavior for
// --manual. The domain list is captured so Present/CleanUp can emit
// CERTBOT_ALL_DOMAINS / CERTBOT_REMAINING_CHALLENGES.
func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, domains []string) (plugins.ChallengeKind, challenge.Provider, error) {
	if cfg.ManualAuthHook == "" {
		return 0, nil, errors.New("manual: --manual-auth-hook is required (interactive mode is not yet implemented)")
	}
	a.authHook = cfg.ManualAuthHook
	a.cleanupHook = cfg.ManualCleanupHook
	a.allDomains = append([]string(nil), domains...)
	a.presented.Store(0)
	a.kind = plugins.HTTP01
	for _, c := range cfg.PreferredChallenges {
		if c == "dns-01" || c == "dns" {
			a.kind = plugins.DNS01
			break
		}
	}
	return a.kind, a, nil
}

func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

// Present runs the auth hook for the given domain. The hook publishes the
// challenge response somewhere reachable by the CA (e.g. drop the http-01
// file in a webroot, or update a DNS TXT record).
func (a *Authenticator) Present(ctx context.Context, domain, token, keyAuth string) error {
	idx := int(a.presented.Add(1) - 1)
	remaining := len(a.allDomains) - idx - 1
	if remaining < 0 {
		remaining = 0
	}
	env := a.baseEnv(domain, keyAuth, token, remaining)

	out, err := hooks.RunCapture(ctx, a.authHook, env)
	if err != nil {
		return fmt.Errorf("manual: auth hook for %s: %w", domain, err)
	}
	a.mu.Lock()
	a.perDomainEnv[domain] = env
	a.authOutputs[domain] = strings.TrimSpace(out)
	a.mu.Unlock()
	return nil
}

// CleanUp runs the cleanup hook for the given domain.
func (a *Authenticator) CleanUp(ctx context.Context, domain, _, _ string) error {
	if a.cleanupHook == "" {
		return nil
	}
	a.mu.Lock()
	env := a.perDomainEnv[domain]
	authOutput := a.authOutputs[domain]
	delete(a.perDomainEnv, domain)
	delete(a.authOutputs, domain)
	a.mu.Unlock()

	env = append(env, "CERTBOT_AUTH_OUTPUT="+authOutput)
	if err := hooks.Run(ctx, a.cleanupHook, env); err != nil {
		fmt.Fprintf(os.Stderr, "manual: cleanup hook for %s failed: %v\n", domain, err)
	}
	return nil
}

func (a *Authenticator) baseEnv(domain, keyAuth, token string, remaining int) []string {
	// CERTBOT_ALL_DOMAINS / _ALL_IDENTIFIERS are comma-separated to match
	// certbot/_internal/plugins/manual.py:192. Hooks parsing this var on
	// space will be broken by a single space-delimited form.
	all := strings.Join(a.allDomains, ",")
	// CERTBOT_VALIDATION for DNS-01 is base64url(sha256(keyAuth)) — the
	// value of the TXT record. lego passes the raw keyAuth; we compute the
	// TXT value here so the env mirrors Certbot's achall.validation().
	validation := keyAuth
	if a.kind == plugins.DNS01 {
		sum := sha256.Sum256([]byte(keyAuth))
		validation = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	env := []string{
		"CERTBOT_DOMAIN=" + domain,
		"CERTBOT_IDENTIFIER=" + domain,
		"CERTBOT_VALIDATION=" + validation,
		"CERTBOT_ALL_DOMAINS=" + all,
		"CERTBOT_ALL_IDENTIFIERS=" + all,
		"CERTBOT_REMAINING_CHALLENGES=" + strconv.Itoa(remaining),
	}
	// For DNS-01, Certbot deliberately pops CERTBOT_TOKEN
	// (manual.py:200) so leftover env from a prior HTTP-01 call doesn't
	// leak. We never inherit it (we build env from scratch), so we just
	// omit the key for DNS-01.
	if a.kind == plugins.HTTP01 && token != "" {
		env = append(env, "CERTBOT_TOKEN="+token)
	}
	return env
}
