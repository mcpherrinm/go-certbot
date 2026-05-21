package verbs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/hooks"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// defaultRenewBefore is the window during which we consider a cert "near
// expiry" if the renewal conf doesn't specify renew_before_expiry. Certbot's
// default is "30 days" (renewal.py:480).
const defaultRenewBefore = 30 * 24 * time.Hour

// Renew implements `go-certbot renew`. Iterates renewal/*.conf, restores the
// recorded params (with CLI overrides winning), checks expiry, and runs
// obtain. Hooks are honored at the right boundaries:
//
//   - pre_hook runs once per invocation, before any renewal attempts
//   - post_hook runs once per invocation, after all attempts (success or failure)
//   - deploy_hook runs after each successful issuance, with RENEWED_LINEAGE/RENEWED_DOMAINS
//   - renewal-hooks/{pre,post,deploy}/* directories are run alongside the flag hooks
func Renew(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	dir := cfg.RenewalConfigsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No renewal configs found in", dir)
			return nil
		}
		return fmt.Errorf("renew: read %s: %w", dir, err)
	}
	if !cfg.DisableHookValidation {
		for _, h := range []struct{ cmd, label string }{
			{cfg.PreHook, "pre"},
			{cfg.PostHook, "post"},
			{cfg.DeployHook, "deploy"},
		} {
			if err := hooks.Validate(h.cmd, h.label); err != nil {
				return err
			}
		}
	}

	// Run pre_hook once per invocation.
	if err := hooks.Run(ctx, cfg.PreHook, nil); err != nil {
		return err
	}
	if err := hooks.RunDir(ctx, cfg.HookDir("pre"), nil); err != nil {
		return err
	}
	defer func() {
		// post_hook always runs.
		_ = hooks.Run(ctx, cfg.PostHook, nil)
		_ = hooks.RunDir(ctx, cfg.HookDir("post"), nil)
	}()

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var failures int
	for _, name := range names {
		confPath := filepath.Join(dir, name)
		certName := strings.TrimSuffix(name, ".conf")
		if cfg.CertName != "" && cfg.CertName != certName {
			continue
		}
		if err := renewOne(ctx, cfg, reg, confPath, certName); err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "renew %s: %v\n", certName, err)
		}
	}
	if failures > 0 {
		return fmt.Errorf("renew: %d certificate(s) failed", failures)
	}
	return nil
}

func renewOne(ctx context.Context, cli *config.Config, reg *plugins.Registry, confPath, certName string) error {
	conf, err := renewalconf.Load(confPath)
	if err != nil {
		return err
	}

	// Merge: start from cli (which has user overrides), then fill in any
	// renewalparam that wasn't user-set. This matches Certbot's
	// set_by_user-gated restore in renewal.reconstitute.
	merged := *cli // shallow copy is fine; we mutate only scalar fields below
	merged.CertName = certName
	mergeFromRenewalConf(&merged, conf)

	// Decide whether renewal is needed by reading the leaf NotAfter.
	leafPath := conf.Top["cert"]
	if leafPath == "" {
		return fmt.Errorf("renew: missing 'cert' key in %s", confPath)
	}
	needs, expiresAt, err := needsRenewal(leafPath, conf)
	if err != nil {
		return err
	}
	if !needs && !cli.ForceRenewal {
		slog.Info("skipping renewal (not yet due)",
			"cert_name", certName,
			"expires_at", expiresAt.Format(time.RFC3339))
		return nil
	}
	// If the ACME server supports ARI and the suggested window is in the
	// future, respect it. This mirrors RFC 9773 §4.1: clients should use the
	// server's hint when available.
	if !cli.ForceRenewal {
		if dueAt, err := ariDecision(ctx, &merged, leafPath); err == nil && dueAt != nil && dueAt.After(time.Now()) {
			slog.Info("ARI says wait", "cert_name", certName, "due_at", dueAt.Format(time.RFC3339))
			return nil
		}
	}
	slog.Info("renewing certificate",
		"cert_name", certName,
		"domains", merged.Domains,
		"expires_at", expiresAt.Format(time.RFC3339))

	// Run obtain through the same path as certonly. We reuse loadOrCreateAccount
	// from certonly.go.
	accountsDir, err := merged.AccountsDir()
	if err != nil {
		return err
	}
	store := &account.FileStorage{
		AccountsDir:       accountsDir,
		StrictPermissions: merged.StrictPermissions,
	}
	acc, err := loadOrCreateAccount(&merged, store)
	if err != nil {
		return err
	}
	c, err := client.New(&merged, acc)
	if err != nil {
		return err
	}
	if err := c.EnsureRegistered(ctx, store); err != nil {
		return err
	}

	authName := merged.Authenticator
	if authName == "" {
		authName = "standalone"
	}
	auth, err := reg.Authenticator(authName)
	if err != nil {
		return err
	}
	lineage, err := c.Obtain(ctx, auth, merged.Domains, certName)
	if err != nil {
		return err
	}

	// deploy_hook + renewal-hooks/deploy/* — only on success.
	env := hooks.DeployEnv(filepath.Dir(lineage.Live.Cert), merged.Domains)
	if err := hooks.Run(ctx, merged.DeployHook, env); err != nil {
		slog.Warn("deploy_hook failed", "err", err)
	}
	if err := hooks.RunDir(ctx, merged.HookDir("deploy"), env); err != nil {
		slog.Warn("deploy-hook directory failed", "err", err)
	}
	return nil
}

// mergeFromRenewalConf fills cfg fields with values from the renewal .conf
// where cfg's value is the default. Matches Certbot's set_by_user gating.
func mergeFromRenewalConf(cfg *config.Config, conf *renewalconf.File) {
	rp := conf.RenewalParams

	if v := rp["server"]; v != "" && !cfg.SetByUser("server") {
		cfg.Server = v
	}
	if v := rp["account"]; v != "" && !cfg.SetByUser("account") {
		cfg.Account = v
	}
	if v := rp["authenticator"]; v != "" && !cfg.SetByUser("authenticator") {
		cfg.Authenticator = v
		switch v {
		case "standalone":
			cfg.Standalone = true
		case "webroot":
			cfg.Webroot = true
		case "manual":
			cfg.Manual = true
		}
	}
	if v := rp["installer"]; v != "" && v != "None" && !cfg.SetByUser("installer") {
		cfg.Installer = v
	}
	if v := rp["key_type"]; v != "" && !cfg.SetByUser("key-type") {
		cfg.KeyType = v
	}
	if v := rp["elliptic_curve"]; v != "" && !cfg.SetByUser("elliptic-curve") {
		cfg.EllipticCurve = v
	}
	if v, ok, err := conf.Int("rsa_key_size"); err == nil && ok && !cfg.SetByUser("rsa-key-size") {
		cfg.RSAKeySize = v
	}
	if v, ok := conf.Bool("must_staple"); ok && !cfg.SetByUser("must-staple") {
		cfg.MustStaple = v
	}
	if v, ok := conf.Bool("reuse_key"); ok && !cfg.SetByUser("reuse-key") {
		cfg.ReuseKey = v
	}
	if v := rp["preferred_chain"]; v != "" && !cfg.SetByUser("preferred-chain") {
		cfg.PreferredChain = v
	}
	if v := rp["preferred_profile"]; v != "" && !cfg.SetByUser("preferred-profile") {
		cfg.PreferredProfile = v
	}
	if v := rp["required_profile"]; v != "" && !cfg.SetByUser("required-profile") {
		cfg.RequiredProfile = v
	}
	if v, ok, err := conf.Int("http01_port"); err == nil && ok && !cfg.SetByUser("http-01-port") {
		cfg.HTTP01Port = v
	}
	if v := rp["http01_address"]; v != "" && !cfg.SetByUser("http-01-address") {
		cfg.HTTP01Address = v
	}
	if v := rp["pre_hook"]; v != "" && !cfg.SetByUser("pre-hook") {
		cfg.PreHook = v
	}
	if v := rp["post_hook"]; v != "" && !cfg.SetByUser("post-hook") {
		cfg.PostHook = v
	}
	if v := rp["deploy_hook"]; v != "" && !cfg.SetByUser("deploy-hook") {
		cfg.DeployHook = v
	}
	// Certbot writes the deploy hook on disk under `renew_hook` (the
	// historical name). Accept either spelling on read.
	if v := rp["renew_hook"]; v != "" && cfg.DeployHook == "" {
		cfg.DeployHook = v
	}
	if v := rp["user_agent"]; v != "" && !cfg.SetByUser("user-agent") {
		cfg.UserAgent = v
	}
	if v, ok := conf.Bool("allow_subset_of_names"); ok && !cfg.SetByUser("allow-subset-of-names") {
		cfg.AllowSubsetOfNames = v
	}
	if !cfg.SetByUser("preferred-challenges") {
		if list, ok := conf.List("pref_challs"); ok {
			cfg.PreferredChallenges = list
		}
	}
	// Domains: prefer the conf-recorded list unless cli set them.
	if !cfg.SetByUser("domain") {
		if list, ok := conf.List("domains"); ok {
			cfg.Domains = list
		}
	}
	// Webroot path + per-domain map.
	if !cfg.SetByUser("webroot-path") {
		if list, ok := conf.List("webroot_path"); ok {
			cfg.WebrootPath = list
		}
	}
	if m := conf.NestedMap("webroot_map"); len(m) > 0 && len(cfg.WebrootMap) == 0 {
		cfg.WebrootMap = map[string]string{}
		for k, v := range m {
			cfg.WebrootMap[k] = v
		}
	}
	// Ancient lineages from pre-Certbot-1.25 don't have key_type — Certbot
	// defaults to RSA in that case (renewal.py:135).
	if rp["key_type"] == "" && cfg.KeyType == "" {
		cfg.KeyType = "rsa"
	}
	// Strip deprecated keys so a downstream restore doesn't act on them
	// (renewal.py:139, :250-260).
	for _, k := range deprecatedRenewalParams {
		delete(rp, k)
	}
}

// deprecatedRenewalParams mirrors the keys Certbot strips on load
// (cli_constants.DEPRECATED_OPTIONS).
var deprecatedRenewalParams = []string{
	"manual_public_ip_logging_ok",
	"os_packages_only",
	"no_self_upgrade",
	"no_bootstrap",
	"no_permissions_check",
	"dns_route53_propagation_seconds",
	"certbot_route53:auth_propagation_seconds",
}

// needsRenewal returns true if the cert is near expiry, with the cert's
// NotAfter for logging. Uses renew_before_expiry from the conf if present;
// otherwise falls back to Certbot's 1/3-of-lifetime rule (renewal.py:413-431)
// for short-lived certs and defaultRenewBefore for standard ones.
func needsRenewal(certPath string, conf *renewalconf.File) (bool, time.Time, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("renew: read %s: %w", certPath, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return false, time.Time{}, errors.New("renew: empty cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("renew: parse cert: %w", err)
	}
	var window time.Duration
	if raw := conf.Top["renew_before_expiry"]; raw != "" {
		if d, perr := parseRenewBefore(raw); perr == nil {
			window = d
		}
	}
	if window == 0 {
		// Fallback per Certbot _default_renewal_time: 1/3 of the cert's
		// lifetime, capped by the 30-day default. For short-lived certs
		// (< 90 days) this picks a sensible window instead of "30 days"
		// which would be longer than the cert itself.
		lifetime := cert.NotAfter.Sub(cert.NotBefore)
		oneThird := lifetime / 3
		window = defaultRenewBefore
		if oneThird < window {
			window = oneThird
		}
	}
	return time.Now().Add(window).After(cert.NotAfter), cert.NotAfter, nil
}

// parseRenewBefore parses Certbot's English-language interval, including
// concatenated sequences like "6 months 1 week" (storage.add_time_interval).
// Bare integers mean days.
func parseRenewBefore(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, errors.New("empty interval")
	}
	// Bare integer (no unit) = days.
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * 24 * time.Hour, nil
	}
	tokens := strings.Fields(s)
	var total time.Duration
	for i := 0; i < len(tokens)-1; i += 2 {
		n, err := strconv.Atoi(tokens[i])
		if err != nil {
			return 0, fmt.Errorf("expected integer at %q: %w", tokens[i], err)
		}
		unit := strings.TrimSuffix(tokens[i+1], "s")
		var step time.Duration
		switch unit {
		case "second", "sec":
			step = time.Second
		case "minute", "min":
			step = time.Minute
		case "hour", "hr":
			step = time.Hour
		case "day":
			step = 24 * time.Hour
		case "week":
			step = 7 * 24 * time.Hour
		case "month":
			step = 30 * 24 * time.Hour
		case "year":
			step = 365 * 24 * time.Hour
		default:
			return 0, fmt.Errorf("unknown unit %q", unit)
		}
		total += time.Duration(n) * step
	}
	if total == 0 {
		return 0, fmt.Errorf("could not parse interval %q", s)
	}
	return total, nil
}
