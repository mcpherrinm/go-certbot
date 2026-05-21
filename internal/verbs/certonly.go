// Package verbs implements Certbot's subcommand handlers.
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
	"strings"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/display"
	"github.com/letsencrypt/go-certbot/internal/eff"
	"github.com/letsencrypt/go-certbot/internal/hooks"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// Certonly obtains a new certificate (no installation).
func Certonly(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	if len(cfg.Domains) == 0 && cfg.CSR.Path == "" {
		return errors.New("certonly: at least one -d/--domain is required")
	}
	if cfg.CSR.Path != "" {
		return errors.New("certonly: --csr issuance is not yet implemented")
	}
	if cfg.Apache || cfg.Nginx {
		return errors.New("certonly: --apache and --nginx installers are not yet implemented")
	}

	authName, err := resolveAuthenticatorName(cfg)
	if err != nil {
		return err
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

	certName := cfg.CertName
	if certName == "" {
		certName = cfg.Domains[0]
	}

	// _find_cert dispatch: before issuing, look for an existing lineage
	// that already covers the requested SANs and decide whether to reissue,
	// renew, or skip with a "you already have this cert" notice. Mirrors
	// main.py:_find_cert (and main.py:1590-1598 / storage.find_duplicative_certs).
	if reuse, err := findCertDispatch(cfg, certName); err != nil {
		return err
	} else if reuse != "" {
		switch reuse {
		case "skip":
			fmt.Println("Certificate not yet due for renewal; the existing certificate covers the requested domains.")
			return nil
		case "renew":
			cfg.ForceRenewal = true
		case "expand":
			// proceed to issuance, but record cert-name to existing lineage
		case "newcert":
			// proceed to issuance under a fresh cert-name suffix
			certName = nextDuplicateCertName(cfg, certName)
		}
		// When reissuing an existing lineage, keep the existing
		// key_type if the user didn't explicitly pass --key-type.
		// Mirrors certbot integration test
		// test_certonly_non_default_key_size_kept: `certonly
		// --force-renewal -d existing` without --key-type preserves
		// the lineage's key_type but resets key SIZE to the default
		// (i.e. we do NOT also restore rsa_key_size; that uses the
		// CLI default 2048).
		//
		// If --key-type is set AND it differs from the lineage's
		// current key_type AND --cert-name isn't pinned, error out.
		// Mirrors certbot _handle_key_type_change: an accidental
		// `certonly -d X --key-type rsa` on a domain that happens to
		// match an existing ecdsa lineage shouldn't silently flip
		// the key type. The user must opt in via --cert-name to
		// confirm they meant THIS specific lineage. test_renew_with
		// _ec_keys asserts the exact error wording.
		if reuse != "newcert" {
			if reuse != "" && cfg.SetByUser("key-type") && cfg.CertName == "" {
				if prior := lineageKeyType(cfg, certName); prior != "" && prior != cfg.KeyType {
					return fmt.Errorf("Please provide both --cert-name and --key-type to change the type of the existing %q lineage from %s to %s", certName, prior, cfg.KeyType)
				}
			}
			mergeExistingKeyType(cfg, certName)
		}
	}

	// pre_hook runs before challenge work; post_hook always runs after.
	if err := hooks.Run(ctx, cfg.PreHook, nil); err != nil {
		return err
	}
	if err := hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("pre"), nil, cfg.PreHook); err != nil {
		return err
	}
	var renewedDomains []string
	defer func() {
		env := hooks.PostEnv(renewedDomains, nil)
		_ = hooks.Run(ctx, cfg.PostHook, env)
		_ = hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("post"), env, cfg.PostHook)
	}()

	// Load or create an account.
	accountsDir, err := cfg.AccountsDir()
	if err != nil {
		return err
	}
	storage := &account.FileStorage{
		AccountsDir:       accountsDir,
		StrictPermissions: cfg.StrictPermissions,
	}
	acc, err := loadOrCreateAccount(cfg, storage)
	if err != nil {
		return err
	}

	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.EnsureRegistered(ctx, storage); err != nil {
		return err
	}

	auth, err := reg.Authenticator(authName)
	if err != nil {
		return err
	}

	slog.Info("requesting certificate",
		"domains", cfg.Domains,
		"cert_name", certName,
		"server", cfg.EffectiveServer())

	lineage, err := c.Obtain(ctx, auth, cfg.Domains, certName)
	if err != nil {
		return err
	}
	renewedDomains = append([]string(nil), cfg.Domains...)

	// Certbot's _report_new_cert (main.py:_report_new_cert) format:
	// "Successfully received certificate.\nCertificate is saved at:
	// <fullchain>\nKey is saved at:         <privkey>\nThis certificate
	// expires on <not_after>."
	expiry := ""
	if data, err := os.ReadFile(lineage.Live.Fullchain); err == nil {
		if t, lerr := client.LeafExpiry(data); lerr == nil {
			expiry = t.Format("2006-01-02")
		}
	}
	fmt.Println()
	fmt.Println("Successfully received certificate.")
	fmt.Printf("Certificate is saved at: %s\n", lineage.Live.Fullchain)
	fmt.Printf("Key is saved at:         %s\n", lineage.Live.Privkey)
	if expiry != "" {
		fmt.Printf("This certificate expires on %s.\n", expiry)
	}

	// deploy_hook runs only on success, with RENEWED_LINEAGE / RENEWED_DOMAINS.
	env := hooks.DeployEnv(filepath.Dir(lineage.Live.Cert), cfg.Domains)
	if err := hooks.Run(ctx, cfg.DeployHook, env); err != nil {
		slog.Warn("deploy_hook failed", "err", err)
	}
	if err := hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("deploy"), env, cfg.DeployHook); err != nil {
		slog.Warn("deploy-hook directory failed", "err", err)
	}

	// EFF subscription (only for fresh accounts, only if user opted in).
	if !cfg.DryRun && eff.Decide(cfg) {
		_ = eff.Subscribe(ctx, cfg.Email)
	}
	return nil
}

// resolveAuthenticatorName chooses the authenticator plugin name from the
// flag soup. Mirrors Certbot's plugin_selection.choose_configurator_plugins
// for the certonly path.
func resolveAuthenticatorName(cfg *config.Config) (string, error) {
	if cfg.Authenticator != "" {
		return cfg.Authenticator, nil
	}
	count := 0
	picked := ""
	for name, on := range map[string]bool{
		"standalone": cfg.Standalone,
		"webroot":    cfg.Webroot,
		"manual":     cfg.Manual,
	} {
		if on {
			count++
			picked = name
		}
	}
	for name, on := range cfg.DNSSelected {
		if on {
			count++
			picked = "dns-" + name
		}
	}
	if count > 1 {
		return "", errors.New("certonly: more than one authenticator selected; pick one of --standalone/--webroot/--manual/--dns-*")
	}
	if count == 0 {
		return "", errors.New("certonly: an authenticator is required (--standalone / --webroot / --manual / --dns-* / --authenticator)")
	}
	return picked, nil
}

// lineageKeyType returns the key_type stored in the given lineage's
// renewal conf, or "" if not present or the file can't be read.
func lineageKeyType(cfg *config.Config, certName string) string {
	conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), certName+".conf"))
	if err != nil {
		return ""
	}
	return conf.RenewalParams["key_type"]
}

// mergeExistingKeyType reads the existing lineage's renewal conf and
// preserves the lineage's key_type when the user didn't pass --key-type
// on the cmd line. Per certbot test_certonly_non_default_key_size_kept,
// key_type stays but key SIZE resets to default — so we only merge the
// key_type and elliptic_curve fields, not rsa_key_size.
func mergeExistingKeyType(cfg *config.Config, certName string) {
	if cfg.SetByUser("key-type") {
		return
	}
	confPath := filepath.Join(cfg.RenewalConfigsDir(), certName+".conf")
	conf, err := renewalconf.Load(confPath)
	if err != nil {
		return
	}
	if v := conf.RenewalParams["key_type"]; v != "" {
		cfg.KeyType = v
	}
	// Preserve elliptic_curve only when key_type is ecdsa AND the user
	// didn't pass --elliptic-curve; otherwise the CLI default applies.
	if cfg.KeyType == "ecdsa" && !cfg.SetByUser("elliptic-curve") {
		if v := conf.RenewalParams["elliptic_curve"]; v != "" {
			cfg.EllipticCurve = v
		}
	}
}

// findCertDispatch looks for an existing lineage that overlaps with the
// requested cert-name/SAN set and returns a directive:
//
//   - "skip":   existing cert covers all requested names and isn't near
//     expiry — Certbot's _ask_user_to_confirm_new_names + _avoid_reissuing
//     short-circuit (cert_manager._find_lineage_for_sans_and_certname,
//     storage.find_duplicative_certs).
//   - "renew":  user passed --force-renewal or --keep-until-expiring on a
//     cert that's now near expiry.
//   - "expand": user passed --expand and an existing lineage matches the
//     cert-name but the SANs differ.
//   - "newcert": user passed --duplicate; suffix the cert-name.
//   - "":       no overlap; issue fresh.
//
// The default (no --duplicate/--expand/--keep) prompts only in interactive
// mode; in non-interactive mode it falls through to "renew" if the request
// matches exactly, else errors out so the user must pick an action.
func findCertDispatch(cfg *config.Config, certName string) (string, error) {
	confPath := filepath.Join(cfg.RenewalConfigsDir(), certName+".conf")
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	conf, err := renewalconf.Load(confPath)
	if err != nil {
		return "", err
	}
	leafPath := conf.Top["cert"]
	if leafPath == "" {
		return "", nil
	}
	existingSANs := sansFromCertOrEmpty(leafPath)
	want := append([]string(nil), cfg.Domains...)
	for _, ip := range cfg.IPAddresses {
		want = append(want, ip)
	}

	identical := sameSANSet(existingSANs, want)
	expansion := isSuperset(existingSANs, want)

	switch {
	case cfg.ForceRenewal:
		return "renew", nil
	case cfg.Duplicate:
		return "newcert", nil
	case cfg.Expand && !identical:
		return "expand", nil
	case cfg.ReinstallExisting && identical:
		// --keep-until-expiring / --reinstall: only re-use if not near
		// expiry. Otherwise renew.
		if needs, _, err := needsRenewal(leafPath, conf); err == nil && needs {
			return "renew", nil
		}
		return "skip", nil
	case identical:
		if cfg.NonInteractive {
			return "renew", nil
		}
		ans := display.YesNoDefault(
			"You have an existing certificate that has exactly the same domains or certificate name you requested. Renew & replace the certificate?",
			true)
		if ans {
			return "renew", nil
		}
		return "skip", nil
	case expansion:
		if cfg.NonInteractive {
			return "", errors.New("certonly: existing lineage covers a superset of the requested domains; use --expand to broaden, --duplicate to issue a separate cert, or change --cert-name")
		}
		ans := display.YesNoDefault(
			"You have an existing certificate that contains a portion of the domains you requested. Expand and renew with the new domains?",
			true)
		if ans {
			return "expand", nil
		}
		return "newcert", nil
	default:
		// Disjoint SANs — non-fatal; issue under a duplicate cert-name suffix.
		return "newcert", nil
	}
}

func sansFromCertOrEmpty(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	out := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func sameSANSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return isSuperset(a, b) && isSuperset(b, a)
}

func isSuperset(haystack, needles []string) bool {
	set := map[string]bool{}
	for _, h := range haystack {
		set[h] = true
	}
	for _, n := range needles {
		if !set[n] {
			return false
		}
	}
	return true
}

func nextDuplicateCertName(cfg *config.Config, base string) string {
	for i := 0; i < 1000; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%04d", base, i)
		}
		if _, err := os.Stat(filepath.Join(cfg.RenewalConfigsDir(), candidate+".conf")); os.IsNotExist(err) {
			return candidate
		}
	}
	return base + "-" + strings.Repeat("d", 4)
}

func loadOrCreateAccount(cfg *config.Config, storage *account.FileStorage) (*account.Account, error) {
	if cfg.Account != "" {
		return storage.Load(cfg.Account)
	}
	existing, err := storage.FindAll()
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return existing[0], nil
	}
	// Creating a new account: refuse to proceed in non-interactive mode
	// when neither --email nor --register-unsafely-without-email is
	// set. Mirrors certbot _determine_account (main.py:750-751): when
	// these flags are missing, get_email() raises MissingCommandlineFlag
	// in non-interactive mode rather than silently registering with no
	// contact info. Interactive mode is handled later by
	// EnsureRegistered which prompts for email.
	if cfg.NonInteractive && cfg.Email == "" && !cfg.RegisterUnsafelyWithoutEmail {
		return nil, fmt.Errorf("--email is required to create an account in non-interactive mode (or pass --register-unsafely-without-email)")
	}
	key, err := account.NewKey(cfg.KeyType, cfg.RSAKeySize)
	if err != nil {
		return nil, err
	}
	pub, err := account.PublicKey(key)
	if err != nil {
		return nil, err
	}
	id, err := account.ComputeID(pub)
	if err != nil {
		return nil, err
	}
	acc := &account.Account{ID: id, Key: key}
	return acc, nil
}
