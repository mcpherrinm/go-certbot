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
// obtain. Hooks follow Certbot's ordering (hooks.py:75-189):
//
//   - pre_hook fires once per lineage that actually needs renewal, deduped
//     across the whole invocation by command string
//   - deploy_hook fires per successful renewal with RENEWED_LINEAGE/_DOMAINS
//   - post_hook is queued and runs once at the end with
//     RENEWED_DOMAINS/FAILED_DOMAINS env, regardless of outcome
//   - renewal-hooks/{pre,post,deploy}/* dirs alongside the flag hooks,
//     gated by --directory-hooks (default on)
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
	if !cfg.DisableHookValidation && cfg.ValidateHooks {
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

	// Pre-hooks are deduplicated across lineages (multiple lineages with
	// identical pre-hook commands fire it once total). Mirrors
	// hooks.py:executed_pre_hooks.
	preRunner := hooks.NewPreRunner()
	var renewedDomains, failedDomains []string
	defer func() {
		env := hooks.PostEnv(renewedDomains, failedDomains)
		_ = hooks.Run(ctx, cfg.PostHook, env)
		_ = hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("post"), env, cfg.PostHook)
	}()

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var renewedCount, parseFailures, renewFailures int
	for _, name := range names {
		confPath := filepath.Join(dir, name)
		certName := strings.TrimSuffix(name, ".conf")
		if cfg.CertName != "" && cfg.CertName != certName {
			continue
		}
		fmt.Println()
		fmt.Println("Processing", confPath)
		outcome, err := renewOne(ctx, cfg, reg, confPath, certName, preRunner)
		switch outcome.kind {
		case outcomeRenewed:
			renewedCount++
			renewedDomains = append(renewedDomains, outcome.sans...)
		case outcomeSkipped:
			// not due — no action
		case outcomeFailed:
			renewFailures++
			failedDomains = append(failedDomains, outcome.sans...)
			fmt.Fprintf(os.Stderr, "renew %s: %v\n", certName, err)
		case outcomeParseError:
			parseFailures++
			fmt.Fprintf(os.Stderr, "renew %s: %v\n", certName, err)
		}
	}

	// Certbot's render_renewal_status (renewal.py:render_renewal_status)
	// equivalent: print SIDE_FRAME banner + summary.
	fmt.Println()
	fmt.Println(strings.Repeat("-", 72))
	if renewedCount == 0 && renewFailures == 0 {
		fmt.Println("No renewals were attempted.")
	} else if renewFailures == 0 {
		fmt.Println("Congratulations, all renewals succeeded:")
	}
	if renewFailures > 0 {
		fmt.Printf("%d renew failure(s), %d parse failure(s)\n", renewFailures, parseFailures)
	}
	fmt.Println(strings.Repeat("-", 72))

	if renewFailures > 0 {
		return fmt.Errorf("renew: %d certificate(s) failed", renewFailures)
	}
	return nil
}

// renewOutcome is the per-lineage outcome of a renew attempt.
type renewOutcome struct {
	kind int
	sans []string
}

const (
	outcomeSkipped    = 0
	outcomeRenewed    = 1
	outcomeFailed     = 2
	outcomeParseError = 3
)

func renewOne(ctx context.Context, cli *config.Config, reg *plugins.Registry, confPath, certName string, pre *hooks.PreRunner) (renewOutcome, error) {
	conf, err := renewalconf.Load(confPath)
	if err != nil {
		return renewOutcome{kind: outcomeParseError}, err
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
		return renewOutcome{kind: outcomeParseError}, fmt.Errorf("renew: missing 'cert' key in %s", confPath)
	}
	needs, expiresAt, err := needsRenewal(leafPath, conf)
	if err != nil {
		return renewOutcome{kind: outcomeParseError}, err
	}
	// Lineages flagged `autorenew = False` are skipped per
	// renewal.py:140. cli.ForceRenewal overrides.
	if !merged.Autorenew && !cli.ForceRenewal {
		fmt.Println("Certificate is configured with autorenew=False; skipping.")
		return renewOutcome{kind: outcomeSkipped, sans: append([]string(nil), merged.Domains...)}, nil
	}
	if !needs && !cli.ForceRenewal {
		fmt.Println("Certificate not yet due for renewal")
		return renewOutcome{kind: outcomeSkipped, sans: append([]string(nil), merged.Domains...)}, nil
	}
	// If the ACME server supports ARI and the suggested window is in the
	// future, respect it. This mirrors RFC 9773 §4.1: clients should use the
	// server's hint when available.
	if !cli.ForceRenewal {
		if dueAt, err := ariDecision(ctx, &merged, leafPath); err == nil && dueAt != nil && dueAt.After(time.Now()) {
			fmt.Printf("ARI says wait until %s; skipping renewal.\n", dueAt.Format(time.RFC3339))
			return renewOutcome{kind: outcomeSkipped, sans: append([]string(nil), merged.Domains...)}, nil
		}
	}

	// Now that we know this lineage needs renewing, run pre-hooks. Deduped
	// across multiple lineages in this invocation.
	if err := pre.Run(ctx, merged.PreHook); err != nil {
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}
	if merged.DirectoryHooks {
		if err := hooks.RunDir(ctx, merged.HookDir("pre"), nil, merged.PreHook); err != nil {
			return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
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
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}
	store := &account.FileStorage{
		AccountsDir:       accountsDir,
		StrictPermissions: merged.StrictPermissions,
	}
	acc, err := loadOrCreateAccount(&merged, store)
	if err != nil {
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}
	c, err := client.New(&merged, acc)
	if err != nil {
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}
	if err := c.EnsureRegistered(ctx, store); err != nil {
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}

	authName := merged.Authenticator
	if authName == "" {
		authName = "standalone"
	}
	auth, err := reg.Authenticator(authName)
	if err != nil {
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}
	lineage, err := c.Obtain(ctx, auth, merged.Domains, certName)
	if err != nil {
		return renewOutcome{kind: outcomeFailed, sans: append([]string(nil), merged.Domains...)}, err
	}

	// deploy_hook + renewal-hooks/deploy/* — only on success.
	env := hooks.DeployEnv(filepath.Dir(lineage.Live.Cert), merged.Domains)
	if err := hooks.Run(ctx, merged.DeployHook, env); err != nil {
		slog.Warn("deploy_hook failed", "err", err)
	}
	if err := hooks.RunDirIf(ctx, merged.DirectoryHooks, merged.HookDir("deploy"), env, merged.DeployHook); err != nil {
		slog.Warn("deploy-hook directory failed", "err", err)
	}
	return renewOutcome{kind: outcomeRenewed, sans: append([]string(nil), merged.Domains...)}, nil
}

// mergeFromRenewalConf fills cfg fields with values from the renewal .conf
// where cfg's value is the default. Matches Certbot's set_by_user gating
// (renewal.py:_restore_required_config_elements) and the VAR_MODIFIERS table
// (cli_constants.py:VAR_MODIFIERS) — e.g. user-supplied --server invalidates
// the conf-recorded account so we don't talk to a new CA with an account
// registered on a different one.
func mergeFromRenewalConf(cfg *config.Config, conf *renewalconf.File) {
	rp := conf.RenewalParams
	// VAR_MODIFIERS: server → account, webroot-path → webroot-map, staging
	// → server, dry-run → staging → server.
	serverSetByUser := cfg.SetByUser("server") || cfg.SetByUser("staging") || cfg.SetByUser("dry-run") || cfg.SetByUser("test-cert")
	accountSetByUser := cfg.SetByUser("account") || serverSetByUser
	webrootMapSetByUser := cfg.SetByUser("webroot-map") || cfg.SetByUser("webroot-path")

	if v := rp["server"]; v != "" && !serverSetByUser {
		cfg.Server = v
	}
	if v := rp["account"]; v != "" && !accountSetByUser {
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
	// Honor `autorenew = False` from the conf so lineages flagged for
	// no-autorenew are skipped by `renew`. Certbot reads this via
	// BOOL_CONFIG_ITEMS (renewal.py:55) and the renew loop bypasses the
	// lineage entirely. We mirror by setting Autorenew=false on the merged
	// config; renewOne consults it.
	if v, ok := conf.Bool("autorenew"); ok && !cfg.SetByUser("autorenew") {
		cfg.Autorenew = v
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
	// Certbot doesn't write `domains` to renewal.conf at all (it derives
	// SANs from the cert at renew time — renewal.py:151-152). When the
	// merged Domains is still empty, read the cert and pull DNS names +
	// IP SANs out so go-certbot can renew lineages issued by Certbot.
	if !cfg.SetByUser("domain") && len(cfg.Domains) == 0 {
		if certPath := conf.Top["cert"]; certPath != "" {
			if dns, ips, err := sansFromCert(certPath); err == nil {
				cfg.Domains = dns
				if len(cfg.IPAddresses) == 0 {
					cfg.IPAddresses = ips
				}
			}
		}
	}
	// Webroot path + per-domain map (skipped when user passed
	// --webroot-path / --webroot-map per VAR_MODIFIERS).
	if !webrootMapSetByUser {
		if list, ok := conf.List("webroot_path"); ok {
			cfg.WebrootPath = list
		}
		if m := conf.NestedMap("webroot_map"); len(m) > 0 && len(cfg.WebrootMap) == 0 {
			cfg.WebrootMap = map[string]string{}
			for k, v := range m {
				cfg.WebrootMap[k] = v
			}
		}
	}
	// IP-address SANs (RFC 8738). Without this, IP-bearing lineages renew
	// without their IPs and the new cert loses the IP SAN.
	if !cfg.SetByUser("ip-address") {
		if list, ok := conf.List("ip_addresses"); ok && len(list) > 0 {
			cfg.IPAddresses = list
		}
	}
	// Plugin-prefixed flat keys (dns_cloudflare_credentials,
	// dns_<plugin>_propagation_seconds, etc.). Certbot stores these flat in
	// [renewalparams] (dns_common.py + each plugin's add_parser_arguments);
	// restore them so DNS-plugin lineages can renew non-interactively.
	for k, v := range rp {
		if v == "" {
			continue
		}
		// dns_<plugin>_credentials → cfg.DNSCredentials[<plugin>]
		if rest, ok := strings.CutPrefix(k, "dns_"); ok {
			if creds, ok := strings.CutSuffix(rest, "_credentials"); ok && creds != "" {
				if cfg.DNSCredentials == nil {
					cfg.DNSCredentials = map[string]string{}
				}
				if cfg.DNSCredentials[creds] == "" {
					cfg.DNSCredentials[creds] = v
				}
				continue
			}
			if plugin, ok := strings.CutSuffix(rest, "_propagation_seconds"); ok && plugin != "" {
				if cfg.DNSPropagationSeconds == nil {
					cfg.DNSPropagationSeconds = map[string]int{}
				}
				if _, set := cfg.DNSPropagationSeconds[plugin]; !set {
					if n, err := strconv.Atoi(v); err == nil {
						cfg.DNSPropagationSeconds[plugin] = n
					}
				}
				continue
			}
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

// sansFromCert parses the PEM-encoded cert at path and returns its DNS
// names and IP-address SANs separately. Used when a renewal.conf doesn't
// list `domains` (Certbot omits this key and derives SANs from the cert).
func sansFromCert(path string) ([]string, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil, errors.New("renew: empty cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	dns := append([]string(nil), cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		seen := false
		for _, n := range dns {
			if n == cert.Subject.CommonName {
				seen = true
				break
			}
		}
		if !seen {
			dns = append(dns, cert.Subject.CommonName)
		}
	}
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return dns, ips, nil
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
	// Match Certbot's _default_renewal_time (renewal.py:_default_renewal_time):
	//   - User-set renew_before_expiry wins.
	//   - For certs with lifetime <= 10 days, renew at NotBefore + lifetime/2
	//     (half-life). This is the threshold Certbot uses for short-lived
	//     ACME certs.
	//   - Otherwise renew with a `min(L/3, 30 days)` remaining-time window.
	const shortCertCutoff = 10 * 24 * time.Hour
	if raw := conf.Top["renew_before_expiry"]; raw != "" {
		if d, perr := parseRenewBefore(raw); perr == nil {
			return time.Now().Add(d).After(cert.NotAfter), cert.NotAfter, nil
		}
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime > 0 && lifetime <= shortCertCutoff {
		dueAt := cert.NotBefore.Add(lifetime / 2)
		return !time.Now().Before(dueAt), cert.NotAfter, nil
	}
	window := defaultRenewBefore
	if oneThird := lifetime / 3; oneThird > 0 && oneThird < window {
		window = oneThird
	}
	return time.Now().Add(window).After(cert.NotAfter), cert.NotAfter, nil
}

// parseRenewBefore parses Certbot's English-language interval, including
// concatenated sequences like "6 months 1 week" (storage.add_time_interval).
// Bare integers mean days. Zero-valued intervals like "0 days" are accepted
// and mean "always renew" (Certbot via parsedatetime).
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
	if len(tokens) < 2 {
		return 0, fmt.Errorf("could not parse interval %q", s)
	}
	var total time.Duration
	saw := false
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
		saw = true
	}
	if !saw {
		return 0, fmt.Errorf("could not parse interval %q", s)
	}
	return total, nil
}
