package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// REVOCATION_REASONS mirrors Certbot constants.REVOCATION_REASONS. argparse
// translates the keyword via _EncodeReasonAction (cli/subparsers.py:42-49)
// before storing in config.reason.
var revocationReasons = map[string]int{
	"unspecified":          0,
	"keycompromise":        1,
	"affiliationchanged":   3,
	"superseded":           4,
	"cessationofoperation": 5,
}

// registerFlags wires CLI flags onto the given FlagSet, pointing them at the
// supplied Config. Names match Certbot exactly so cli.ini files and shell
// scripts that work with Certbot keep working.
//
// Every key in certbot._internal.constants.CLI_DEFAULTS is registered here.
// Flags whose behavior isn't fully wired still parse so cli.ini files don't
// break.
func registerFlags(fs *pflag.FlagSet, c *config.Config) {
	// Paths
	fs.StringVar(&c.ConfigDir, "config-dir", c.ConfigDir, "Configuration directory.")
	fs.StringVar(&c.WorkDir, "work-dir", c.WorkDir, "Working directory.")
	fs.StringVar(&c.LogsDir, "logs-dir", c.LogsDir, "Logs directory.")

	// Server / identity
	fs.StringVar(&c.Server, "server", c.Server, "ACME directory URL.")
	fs.StringVarP(&c.Email, "email", "m", c.Email, "Email used for registration and recovery contact.")
	fs.BoolVar(&c.TOS, "agree-tos", false, "Agree to the ACME server's Subscriber Agreement.")
	fs.BoolVar(&c.RegisterUnsafelyWithoutEmail, "register-unsafely-without-email", false, "Register without providing an email address.")
	fs.StringVar(&c.Account, "account", "", "Account id to use; default = first found.")
	fs.BoolVar(&c.NoEFFEmail, "no-eff-email", false, "Don't subscribe to the EFF mailing list.")
	fs.BoolVar(&c.EFFEmailExplicit, "eff-email", false, "Subscribe to the EFF mailing list after successful issuance.")
	// Resolve EFFEmail tri-state from the two paired flags. Order matches
	// Certbot (cli/__init__.py:195-200): --eff-email=true, --no-eff-email=false,
	// neither = nil (ask interactively when issuing).
	c.PostParseHooks = append(c.PostParseHooks, func() {
		switch {
		case c.SetByUser("eff-email"):
			t := true
			c.EFFEmail = &t
		case c.SetByUser("no-eff-email"):
			f := false
			c.EFFEmail = &f
		}
	})

	// Domains
	fs.StringSliceVarP(&c.Domains, "domain", "d", c.Domains, "Domain name to include (repeatable).")
	fs.StringSliceVar(&c.Domains, "domains", c.Domains, "Alias for --domain.")
	// Mirrors certbot._internal.cli.cli_utils.DomainsAction: lowercase,
	// strip trailing dot, dedupe preserving order. Without this, a user
	// who passes `-d Example.COM.` issues against `example.com` but
	// renewal config records the unnormalized form, causing the next
	// renewal cycle to think it's a different SAN set.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		c.Domains = normalizeDomains(c.Domains)
	})
	fs.StringSliceVar(&c.IPAddresses, "ip-address", c.IPAddresses, "IP address SAN (repeatable). Requires --preferred-profile shortlived for Let's Encrypt.")
	fs.StringVar(&c.CertName, "cert-name", c.CertName, "Name (lineage) under which to track this cert.")

	// Key / profile
	fs.StringVar(&c.KeyType, "key-type", c.KeyType, "rsa or ecdsa.")
	fs.IntVar(&c.RSAKeySize, "rsa-key-size", c.RSAKeySize, "RSA key size when --key-type=rsa.")
	fs.StringVar(&c.EllipticCurve, "elliptic-curve", c.EllipticCurve, "Elliptic curve when --key-type=ecdsa.")
	fs.BoolVar(&c.MustStaple, "must-staple", c.MustStaple, "Include the OCSP Must-Staple extension.")
	fs.StringVar(&c.PreferredChain, "preferred-chain", c.PreferredChain, "Preferred issuer chain CN.")
	fs.StringVar(&c.PreferredProfile, "preferred-profile", c.PreferredProfile, "Preferred ACME profile name.")
	fs.StringVar(&c.RequiredProfile, "required-profile", c.RequiredProfile, "Required ACME profile name.")
	fs.BoolVar(&c.ReuseKey, "reuse-key", c.ReuseKey, "Reuse the same private key on renewal.")
	noReuseKey := false
	fs.BoolVar(&noReuseKey, "no-reuse-key", false, "Negation of --reuse-key.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-reuse-key") {
			c.ReuseKey = false
		}
	})
	fs.BoolVar(&c.NewKey, "new-key", c.NewKey, "Generate a fresh private key on renewal.")
	fs.BoolVar(&c.AllowSubsetOfNames, "allow-subset-of-names", c.AllowSubsetOfNames, "Continue if a subset of names authorize.")
	// --csr loads the file at flag-set time so downstream code has both the
	// path (for error messages) and the bytes (for ACME submission). Matches
	// Certbot's argparse type=read_file (helpful.py:332-355) which stores a
	// (path, contents) tuple in config.csr.
	csrPath := ""
	fs.StringVar(&csrPath, "csr", "",
		"Path to a CSR (DER or PEM); --csr-driven issuance with certonly.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if csrPath == "" {
			return
		}
		abs, err := filepath.Abs(csrPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot: --csr:", err)
			os.Exit(2)
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot: --csr:", err)
			os.Exit(2)
		}
		c.CSR = config.CSRArg{Path: abs, Contents: data}
	})
	fs.StringVar(&c.CertPath, "cert-path", c.CertPath, "Path to an existing fullchain PEM (revoke/install).")
	fs.StringVar(&c.KeyPath, "key-path", c.KeyPath, "Path to an existing private key (install / revoke --key-path).")
	reasonWord := ""
	fs.StringVar(&reasonWord, "reason", "", "Revocation reason: unspecified, keycompromise, affiliationchanged, superseded, cessationofoperation.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if !c.SetByUser("reason") || reasonWord == "" {
			return
		}
		code, ok := revocationReasons[strings.ToLower(reasonWord)]
		if !ok {
			fmt.Fprintf(os.Stderr, "go-certbot: invalid --reason %q (expected one of: unspecified, keycompromise, affiliationchanged, superseded, cessationofoperation)\n", reasonWord)
			os.Exit(2)
		}
		c.Reason = code
	})
	fs.BoolVar(&c.DeleteAfterRevoke, "delete-after-revoke", c.DeleteAfterRevoke, "Also delete lineage files after a successful revoke.")
	noDeleteAfterRevoke := false
	fs.BoolVar(&noDeleteAfterRevoke, "no-delete-after-revoke", false, "Don't delete lineage after a successful revoke.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-delete-after-revoke") {
			c.DeleteAfterRevoke = false
		}
	})

	// Plugin selection
	fs.StringVarP(&c.Authenticator, "authenticator", "a", c.Authenticator, "Authenticator plugin name.")
	fs.StringVarP(&c.Installer, "installer", "i", c.Installer, "Installer plugin name.")
	fs.StringVar(&c.Configurator, "configurator", c.Configurator, "Plugin that is both authenticator and installer.")
	fs.BoolVar(&c.Apache, "apache", c.Apache, "Use the apache plugin.")
	fs.StringVar(&c.ApacheServerRoot, "apache-server-root", c.ApacheServerRoot, "Apache server root (default /etc/apache2).")
	fs.StringVar(&c.ApacheCtl, "apache-ctl", c.ApacheCtl, "Apache control binary (default apachectl).")
	fs.StringVar(&c.ApacheBin, "apache-bin", c.ApacheBin, "Apache httpd binary (used for `-v`/`-M`; falls back to apache-ctl).")
	fs.StringVar(&c.ApacheEnMod, "apache-enmod", c.ApacheEnMod, "Command to enable an Apache module (e.g. a2enmod).")
	fs.StringVar(&c.ApacheDismod, "apache-dismod", c.ApacheDismod, "Command to disable an Apache module.")
	fs.StringVar(&c.ApacheLeVhostExt, "apache-le-vhost-ext", "-le-ssl.conf", "Extension appended to source vhost filenames for SSL clones.")
	fs.StringVar(&c.ApacheVHostRoot, "apache-vhost-root", c.ApacheVHostRoot, "Directory where SSL vhost clones land (overrides per-OS default).")
	fs.StringVar(&c.ApacheLogsRoot, "apache-logs-root", c.ApacheLogsRoot, "Apache log directory (e.g. /var/log/apache2).")
	fs.StringVar(&c.ApacheChallengeLocation, "apache-challenge-location", c.ApacheChallengeLocation, "Directory used for HTTP-01 challenge files.")
	fs.BoolVar(&c.ApacheHandleModules, "apache-handle-modules", c.ApacheHandleModules, "Manage a2enmod/a2dismod (Debian-style).")
	fs.BoolVar(&c.ApacheHandleSites, "apache-handle-sites", c.ApacheHandleSites, "Manage a2ensite/a2dissite (Debian-style).")

	// Enhancements — tri-state via paired --X / --no-X flags. Certbot lets
	// users opt out of an enhancement that was previously applied; we
	// honor that by flipping the bool back to false in a post-parse hook.
	fs.BoolVar(&c.HSTS, "hsts", c.HSTS, "Add a Strict-Transport-Security header (enhance verb).")
	noHSTS := false
	fs.BoolVar(&noHSTS, "no-hsts", false, "Remove the Strict-Transport-Security header.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-hsts") {
			c.HSTS = false
		}
	})
	fs.BoolVar(&c.UIR, "uir", c.UIR, "Add a Content-Security-Policy: upgrade-insecure-requests header (enhance verb).")
	noUIR := false
	fs.BoolVar(&noUIR, "no-uir", false, "Remove the upgrade-insecure-requests header.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-uir") {
			c.UIR = false
		}
	})
	fs.BoolVar(&c.Staple, "staple-ocsp", c.Staple, "Enable OCSP stapling (enhance verb).")
	noStaple := false
	fs.BoolVar(&noStaple, "no-staple-ocsp", false, "Disable OCSP stapling.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-staple-ocsp") {
			c.Staple = false
		}
	})

	// Rollback
	fs.IntVar(&c.RollbackCheckpoints, "checkpoints", c.RollbackCheckpoints, "Number of previous checkpoints to revert (rollback verb; default 1).")
	fs.StringVar(&c.RenewBeforeExpiry, "renew-before-expiry", c.RenewBeforeExpiry, "Interval before expiry at which to renew (e.g. \"30 days\"). Persisted into renewal.conf via reconfigure.")
	fs.BoolVar(&c.Nginx, "nginx", c.Nginx, "Use the nginx plugin.")
	fs.StringVar(&c.NginxServerRoot, "nginx-server-root", c.NginxServerRoot, "Nginx server root (default /etc/nginx).")
	fs.StringVar(&c.NginxCtl, "nginx-ctl", c.NginxCtl, "Nginx control binary (default nginx).")
	fs.IntVar(&c.NginxSleepSeconds, "nginx-sleep-seconds", 1, "Number of seconds to sleep after nginx reload (default 1).")
	registerRedirectFlags(fs, c)
	fs.BoolVar(&c.Standalone, "standalone", c.Standalone, "Use the standalone plugin.")
	fs.BoolVar(&c.Webroot, "webroot", c.Webroot, "Use the webroot plugin.")
	fs.StringSliceVarP(&c.WebrootPath, "webroot-path", "w", c.WebrootPath, "Webroot directory (interleave with -d for per-domain map).")
	// --webroot-map accepts a JSON dict mapping domain → webroot path.
	// Certbot uses a custom _WebrootMapAction (plugins/webroot.py:77-85)
	// that json-decodes the value; we mirror that and merge into cfg.WebrootMap
	// (taking precedence over -w/-d interleaving so cli.ini users keep working).
	webrootMapJSON := ""
	fs.StringVar(&webrootMapJSON, "webroot-map", "",
		"JSON dict mapping domains to webroot paths.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if webrootMapJSON == "" {
			return
		}
		m := map[string]string{}
		if err := json.Unmarshal([]byte(webrootMapJSON), &m); err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot: --webroot-map must be a JSON object: ", err)
			os.Exit(2)
		}
		if c.WebrootMap == nil {
			c.WebrootMap = map[string]string{}
		}
		for k, v := range m {
			// Lowercase the key so it matches normalized cfg.Domains.
			k = strings.ToLower(strings.TrimSpace(k))
			k = strings.TrimSuffix(k, ".")
			if k == "" {
				continue
			}
			c.WebrootMap[k] = v
		}
	})
	fs.BoolVar(&c.Manual, "manual", c.Manual, "Use the manual plugin.")

	// HTTP-01
	fs.IntVar(&c.HTTP01Port, "http-01-port", c.HTTP01Port, "Port for the http-01 challenge.")
	fs.StringVar(&c.HTTP01Address, "http-01-address", c.HTTP01Address, "Address the standalone server binds to. Empty = all interfaces.")
	fs.IntVar(&c.HTTPSPort, "https-port", c.HTTPSPort, "Port to use when configuring https.")

	// Behavior
	fs.BoolVar(&c.DryRun, "dry-run", c.DryRun, "Run as if obtaining a cert without writing to disk.")
	fs.BoolVar(&c.Staging, "staging", c.Staging, "Use the Let's Encrypt staging server.")
	fs.BoolVar(&c.Staging, "test-cert", c.Staging, "Alias for --staging.")
	fs.BoolVar(&c.Debug, "debug", c.Debug, "Show tracebacks on errors. (Use --verbose for log-level changes.)")
	fs.BoolVar(&c.NoVerifySSL, "no-verify-ssl", c.NoVerifySSL, "Skip TLS verification when talking to the ACME server.")
	fs.BoolVarP(&c.Quiet, "quiet", "q", c.Quiet, "Quiet mode. Implies --non-interactive.")
	fs.BoolVarP(&c.NonInteractive, "non-interactive", "n", c.NonInteractive, "Run without prompts.")
	fs.BoolVar(&c.NonInteractive, "noninteractive", c.NonInteractive, "Alias for --non-interactive.")
	fs.BoolVar(&c.ForceInteractive, "force-interactive", c.ForceInteractive, "Force interactive mode.")
	fs.CountVarP(&c.Verbose, "verbose", "v", "Increase verbosity.")
	fs.StringVar(&c.VerboseLevel, "verbose-level", c.VerboseLevel, "Set log verbosity by level name (debug/info/warning/error).")
	fs.BoolVarP(&c.TextMode, "text", "t", c.TextMode, "Use ncurses-free text mode (kept for compat).")
	fs.IntVar(&c.MaxLogBackups, "max-log-backups", c.MaxLogBackups, "Max number of rotated log files to keep.")
	fs.BoolVar(&c.PreconfiguredRenew, "preconfigured-renewal", c.PreconfiguredRenew, "Internal flag set by snap to skip systemd-timer setup.")
	fs.BoolVar(&c.DebugChallenges, "debug-challenges", c.DebugChallenges, "After setting up challenges, wait for user input.")
	fs.BoolVar(&c.BreakMyCerts, "break-my-certs", c.BreakMyCerts, "Acknowledge that issuance against a non-default server may break existing certs.")
	fs.BoolVar(&c.StrictPermissions, "strict-permissions", c.StrictPermissions, "Enforce strict ownership checks on config files.")

	// Lifecycle of an existing lineage.
	fs.BoolVar(&c.Duplicate, "duplicate", c.Duplicate, "Allow creating a duplicate cert (instead of renewing).")
	fs.BoolVar(&c.Expand, "expand", c.Expand, "Expand an existing cert to cover new SANs.")
	fs.BoolVar(&c.ForceRenewal, "force-renewal", c.ForceRenewal, "Force renewal even if not near expiry.")
	fs.BoolVar(&c.ForceRenewal, "renew-by-default", c.ForceRenewal, "Alias for --force-renewal.")
	fs.BoolVar(&c.ReinstallExisting, "reinstall", c.ReinstallExisting, "If cert matches existing, reinstall without renewal.")
	fs.BoolVar(&c.ReinstallExisting, "keep", c.ReinstallExisting, "Alias for --reinstall.")
	fs.BoolVar(&c.ReinstallExisting, "keep-until-expiring", c.ReinstallExisting, "Alias for --reinstall.")
	fs.BoolVar(&c.RenewWithNewDomains, "renew-with-new-domains", c.RenewWithNewDomains, "On renewal, expand cert with new SANs given on cmd line.")
	fs.IntVar(&c.IssuanceTimeout, "issuance-timeout", c.IssuanceTimeout, "Per-domain timeout (seconds).")
	fs.StringSliceVar(&c.PreferredChallenges, "preferred-challenges", c.PreferredChallenges, "Preferred challenge types, comma-separated.")
	// Normalize aliases (`http`/`http_01` → `http-01`, `dns`/`dns_01` →
	// `dns-01`) so downstream comparisons can match the canonical name.
	// Mirrors Certbot's _PrefChallAction (cli_utils.py:185-221).
	// Trim whitespace around each entry so `--preferred-challenges
	// 'http, dns'` (Certbot's cli_test exercises the space variant)
	// works the same as `'http,dns'`.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		for i, ch := range c.PreferredChallenges {
			c.PreferredChallenges[i] = strings.TrimSpace(ch)
		}
		for i, ch := range c.PreferredChallenges {
			switch ch {
			case "http", "http_01":
				c.PreferredChallenges[i] = "http-01"
			case "dns", "dns_01":
				c.PreferredChallenges[i] = "dns-01"
			case "tls-alpn", "tls_alpn_01":
				c.PreferredChallenges[i] = "tls-alpn-01"
			}
		}
	})
	// --must-staple implies --staple-ocsp (helpful.py:295-296).
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("must-staple") && c.MustStaple {
			c.Staple = true
		}
	})
	// Validate --key-type (cli/__init__.py:320).
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if !c.SetByUser("key-type") {
			return
		}
		// Normalize to lowercase canonical form. Certbot's argparse
		// `choices=['rsa','ecdsa']` rejects mixed-case outright; we
		// accept it but canonicalize so downstream string-compare
		// checks (cfg.KeyType=="ecdsa") work.
		c.KeyType = strings.ToLower(c.KeyType)
		switch c.KeyType {
		case "rsa", "ecdsa":
		default:
			fmt.Fprintf(os.Stderr, "go-certbot: invalid --key-type %q (expected rsa or ecdsa)\n", c.KeyType)
			os.Exit(2)
		}
	})
	// Validate --elliptic-curve.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if !c.SetByUser("elliptic-curve") {
			return
		}
		switch c.EllipticCurve {
		case "secp256r1", "secp384r1", "secp521r1":
		default:
			fmt.Fprintf(os.Stderr, "go-certbot: invalid --elliptic-curve %q (expected secp256r1, secp384r1, or secp521r1)\n", c.EllipticCurve)
			os.Exit(2)
		}
	})
	// --max-log-backups must be non-negative (cli_utils.py:224).
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.MaxLogBackups < 0 {
			fmt.Fprintf(os.Stderr, "go-certbot: --max-log-backups must be non-negative, got %d\n", c.MaxLogBackups)
			os.Exit(2)
		}
	})
	// --user-agent-comment can't contain ( or ) per Certbot
	// cli_utils.py:166-169 (would unbalance the User-Agent header).
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if strings.ContainsAny(c.UserAgentComment, "()") {
			fmt.Fprintln(os.Stderr, "go-certbot: --user-agent-comment may not contain ( or )")
			os.Exit(2)
		}
	})
	fs.BoolVar(&c.RunDeployHooks, "run-deploy-hooks", c.RunDeployHooks, "Always run deploy hooks on `reconfigure`.")

	// Path overrides for certonly --csr. Note: --cert-path itself is also
	// registered above (bound to c.CertPath for revoke/install). For
	// certonly --csr destinations Certbot uses these chain variants.
	fs.StringVar(&c.AuthChainPath, "chain-path", c.AuthChainPath, "Where to write the issuer chain when using --csr.")
	fs.StringVar(&c.FullchainPath, "fullchain-path", c.FullchainPath, "Where to write the full chain when using --csr.")
	// Under certonly --csr, --cert-path is the OUTPUT path (default
	// ./cert.pem), not the input. Certbot's paths_parser.py:20-27
	// binds --cert-path to `auth_cert_path` when verb=certonly. We
	// route here in a PostParseHook so the same flag works for
	// revoke/install (input) and certonly --csr (output) without
	// requiring callers to know about both fields.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.Verb == "certonly" && c.CSR.Path != "" && c.SetByUser("cert-path") {
			c.AuthCertPath = c.CertPath
			c.CertPath = ""
		}
	})
	// Convert install/revoke path flags to absolute paths so the
	// resolved paths survive the `cd` Certbot performs into a temp
	// working dir, and so renewal.conf records absolute paths.
	// Mirrors certbot _internal/cli/paths_parser.py's `path_surgery`
	// and the test_install_abspath test (cli_test.py:142-156).
	c.PostParseHooks = append(c.PostParseHooks, func() {
		abs := func(p string) string {
			if p == "" {
				return p
			}
			if a, err := filepath.Abs(p); err == nil {
				return a
			}
			return p
		}
		if c.SetByUser("cert-path") {
			c.CertPath = abs(c.CertPath)
		}
		if c.SetByUser("key-path") {
			c.KeyPath = abs(c.KeyPath)
		}
		if c.SetByUser("chain-path") {
			c.AuthChainPath = abs(c.AuthChainPath)
		}
		if c.SetByUser("fullchain-path") {
			c.FullchainPath = abs(c.FullchainPath)
		}
	})

	// Hooks
	fs.StringVar(&c.PreHook, "pre-hook", c.PreHook, "Command to run before challenge.")
	fs.StringVar(&c.PostHook, "post-hook", c.PostHook, "Command to run after any attempt.")
	fs.StringVar(&c.DeployHook, "deploy-hook", c.DeployHook, "Command to run after a successful issuance.")
	fs.StringVar(&c.DeployHook, "renew-hook", c.DeployHook, "Alias for --deploy-hook (legacy name).")
	fs.BoolVar(&c.DisableHookValidation, "disable-hook-validation", c.DisableHookValidation, "Skip the check that hook commands are executable.")
	// In Certbot, --disable-hook-validation is `store_false dest=validate_hooks`
	// (cli/__init__.py:453). Mirror so a single source of truth (ValidateHooks)
	// governs the check.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("disable-hook-validation") {
			c.ValidateHooks = false
		}
	})
	fs.StringVar(&c.ManualAuthHook, "manual-auth-hook", c.ManualAuthHook, "Path to a script that publishes challenge data (manual plugin).")
	fs.StringVar(&c.ManualCleanupHook, "manual-cleanup-hook", c.ManualCleanupHook, "Path to a script that removes challenge data (manual plugin).")

	// Default-True bool pairs (`--no-X` flips off).
	registerBoolDefaultTrue(fs, c, &c.Autorenew, "autorenew", "Track this cert for auto-renewal.")
	registerBoolDefaultTrue(fs, c, &c.RandomSleepOnRenew, "random-sleep-on-renew", "Insert a random sleep at the start of renew.")
	registerBoolDefaultTrue(fs, c, &c.DirectoryHooks, "directory-hooks", "Run scripts in renewal-hooks/{pre,post,deploy}/ alongside the flag hooks.")
	registerBoolDefaultTrue(fs, c, &c.ValidateHooks, "validate-hooks", "Validate hook commands are executable before running.")

	// DNS plugins. Each gets --dns-X (boolean selector),
	// --dns-X-credentials (path to INI), and --dns-X-propagation-seconds.
	// Propagation defaults match Certbot's per-plugin defaults; 0 means "use lego's default".
	for _, name := range dnsPluginNames {
		registerDNSPluginFlags(fs, c, name)
	}

	// User agent
	fs.StringVar(&c.UserAgent, "user-agent", c.UserAgent, "Override the User-Agent header.")
	fs.StringVar(&c.UserAgentComment, "user-agent-comment", c.UserAgentComment, "Append a comment to the default User-Agent string.")

	// External Account Binding
	fs.StringVar(&c.EABKid, "eab-kid", c.EABKid, "Key id for ACME External Account Binding.")
	fs.StringVar(&c.EABHMACKey, "eab-hmac-key", c.EABHMACKey, "HMAC key for ACME External Account Binding.")
	fs.StringVar(&c.EABHMACAlg, "eab-hmac-alg", c.EABHMACAlg, "HMAC algorithm for ACME External Account Binding.")

	// Misc
	fs.BoolVar(&c.AutoHSTS, "auto-hsts", c.AutoHSTS, "Apache only: automatically manage HSTS header.")
	fs.BoolVar(&c.DisableRenewUpdates, "disable-renew-updates", c.DisableRenewUpdates, "Disable installer enhancement updates on `certbot renew`.")
	fs.IntVar(&c.Num, "num", c.Num, "Numeric positional argument (used by `rollback --checkpoints`).")
	fs.BoolVar(&c.PluginsInit, "init", c.PluginsInit, "(plugins verb) Initialize plugins.")
	fs.BoolVar(&c.PluginsPrepare, "prepare", c.PluginsPrepare, "(plugins verb) Initialize and prepare plugins.")
	// `plugins --authenticators` / `--installers` are zero-arg in Certbot
	// (action=append_const in subparsers.py:67-73). Append the interface
	// name to c.PluginIfaces on each occurrence.
	authIface := false
	instIface := false
	fs.BoolVar(&authIface, "authenticators", false, "(plugins verb) Limit to authenticator plugins only.")
	fs.BoolVar(&instIface, "installers", false, "(plugins verb) Limit to installer plugins only.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if authIface {
			c.PluginIfaces = append(c.PluginIfaces, "Authenticator")
		}
		if instIface {
			c.PluginIfaces = append(c.PluginIfaces, "Installer")
		}
	})

	// Mutual-exclusion checks. Each mirrors a Certbot helpful.py guard.
	// Run as a single PostParseHook so the error message comes after all
	// flags are parsed and `SetByUser` is reliable.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		fail := func(msg string) {
			fmt.Fprintln(os.Stderr, "go-certbot:", msg)
			os.Exit(2)
		}
		// --force-interactive + -n/--non-interactive  (helpful.py:277-280)
		if c.ForceInteractive && c.NonInteractive {
			fail("Flag for non-interactive mode and --force-interactive conflict")
		}
		// --force-interactive forbidden with `renew` (helpful.py:284-285).
		// renew is always batch and cannot be interactive — pre-fix we
		// silently accepted the combination and ignored the flag.
		if c.ForceInteractive && c.Verb == "renew" {
			fail("--force-interactive cannot be used with renew")
		}
		// --hsts + --auto-hsts  (helpful.py:306-308)
		if c.HSTS && c.AutoHSTS {
			fail("Parameters --hsts and --auto-hsts cannot be used simultaneously.")
		}
		// --allow-subset-of-names + --csr  (helpful.py:329-330)
		if c.AllowSubsetOfNames && c.CSR.Path != "" {
			fail("--allow-subset-of-names cannot be used with --csr")
		}
		// --csr is only allowed with `certonly` (helpful.py:323-328).
		// Pre-fix we silently ignored --csr with run/renew/etc.
		if c.CSR.Path != "" && c.Verb != "" && c.Verb != "certonly" {
			fail("Currently, a CSR file may only be specified when obtaining a new or replacement via the certonly command.")
		}
		// --dry-run is only valid with certonly/renew/reconfigure
		// (cli_utils.py:282-284). Pre-fix we applied dry-run side
		// effects (rewrite to staging, flip --break-my-certs) for any
		// verb, which made `certbot install --dry-run` quietly point
		// at the staging account directory.
		if c.DryRun {
			switch c.Verb {
			case "", "certonly", "renew", "run", "reconfigure":
				// `run` is allowed because Certbot's certonly+install
				// fused path is `run`; staging works there too.
			default:
				fail("--dry-run currently only works with the certonly, renew, run, or reconfigure verbs")
			}
		}
	})

	// Hide flags Certbot marks help=argparse.SUPPRESS (cli/__init__.py:84-99,
	// 188-190, 354, 363, 371, 432-437). They remain settable for compat but
	// shouldn't clutter `--help`.
	c.PostParseHooks = append(c.PostParseHooks, func() {})
	for _, name := range []string{
		"text",
		"verbose-level",
		"register-unsafely-without-email",
		"preconfigured-renewal",
		"no-random-sleep-on-renew",
		"renew-hook",
		"no-hsts",
		"no-uir",
		"no-staple-ocsp",
		"no-self-upgrade",
		"no-reuse-key",
	} {
		_ = fs.MarkHidden(name)
	}

	// Deprecated flags Certbot accepts but ignores. Registered so cli.ini and
	// command-line invocations don't error.
	registerDeprecated(fs, c, []string{
		"os-packages-only",
		"no-self-upgrade",
		"no-bootstrap",
		"no-permissions-check",
		"manual-public-ip-logging-ok",
		// `dns-route53-propagation-seconds` is in Certbot's
		// DEPRECATED_OPTIONS list but is also the real flag name we use
		// for the per-plugin propagation timeout, so we don't register
		// it as deprecated to avoid a pflag duplicate-flag panic.
	})
}

// applyDryRunSideEffects applies the side effects Certbot's
// set_test_server_options (cli_utils.py:247-290) sets when --dry-run is
// passed. We invoke this from main.go after CLI parsing finishes.
func applyDryRunSideEffects(c *config.Config) {
	if !c.DryRun {
		return
	}
	// --dry-run rewrites --server to the staging directory (only when the
	// user didn't explicitly pick a custom server) and clears --account so
	// the staging-side registration is used rather than a prod account.
	// Certbot: cli_utils.py:set_test_server_options.
	if !c.SetByUser("server") || c.Server == config.DefaultLetsEncryptDirectory {
		c.Server = config.StagingDirectory
		c.MarkSet("server", config.SourceRuntime)
	}
	if !c.SetByUser("account") {
		c.Account = ""
	}
	// --dry-run still implies the --staging flag so downstream code
	// (EffectiveServer, etc.) sees a consistent picture.
	c.Staging = true
	c.MarkSet("staging", config.SourceRuntime)
	// --dry-run implies --break-my-certs so issuance against a non-default
	// server doesn't error out on the "are you sure?" check.
	c.BreakMyCerts = true
	c.MarkSet("break-my-certs", config.SourceRuntime)
	// --dry-run + no agreement + no email + no existing account =>
	// Certbot auto-agrees TOS and uses the unsafely-without-email mode
	// only when there's no prod account on disk. Mirrors
	// cli_utils.py:286-290 which checks
	// `glob.glob(... ACCOUNTS_DIR/*)` before flipping the flags. If
	// the user already has an account, registration is a no-op and
	// these flags are irrelevant — flipping them unconditionally
	// would surprise users who deliberately omit --agree-tos.
	if !hasAnyAccount(c) {
		if !c.TOS {
			c.TOS = true
			c.MarkSet("agree-tos", config.SourceRuntime)
		}
		if c.Email == "" {
			c.RegisterUnsafelyWithoutEmail = true
			c.MarkSet("register-unsafely-without-email", config.SourceRuntime)
		}
	}
}

// hasAnyAccount returns true if the configured AccountsDir contains at
// least one entry. Mirrors certbot's existence check in
// cli_utils.set_test_server_options: glob.glob(... accounts dir/*).
func hasAnyAccount(c *config.Config) bool {
	d, err := c.AccountsDir()
	if err != nil {
		return false
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// trackSources walks the FlagSet after parsing and records, for each flag
// that Visit reported (i.e. was set by the user), the source as command line.
// Also applies VAR_MODIFIERS (Certbot's cli_constants.py:VAR_MODIFIERS):
// when one flag is user-set we mark another as user-set too so renewal-restore
// reuses fresh values.
func trackSources(fs *pflag.FlagSet, c *config.Config) {
	fs.Visit(func(f *pflag.Flag) {
		c.MarkSet(f.Name, config.SourceCommandLine)
	})
	// --staging or --dry-run imply --server was user-chosen.
	if c.SetByUser("staging") || c.SetByUser("dry-run") || c.SetByUser("test-cert") {
		c.MarkSet("server", config.SourceRuntime)
	}
	// --server being set implies --account was chosen too.
	if c.SetByUser("server") {
		c.MarkSet("account", config.SourceRuntime)
	}
	// --quiet implies --non-interactive.
	if c.SetByUser("quiet") {
		c.NonInteractive = true
		c.MarkSet("non-interactive", config.SourceRuntime)
	}
}

// registerBoolDefaultTrue registers `--<name>` (defaults true) and
// `--no-<name>` (negation). Either name being passed on argv updates `dst`.
// We use a PostParseHook on the Config to apply the --no-X side because pflag
// uses a separate var for the negation.
func registerBoolDefaultTrue(fs *pflag.FlagSet, c *config.Config, dst *bool, name, usage string) {
	if !*dst {
		*dst = true
	}
	fs.BoolVar(dst, name, true, usage)
	negate := false
	fs.BoolVar(&negate, "no-"+name, false, "Disable --"+name+".")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-" + name) {
			*dst = false
		}
	})
}

// registerDeprecated registers each name as a hidden boolean no-op so old
// cli.ini files and shell scripts don't error out. Matches Certbot's
// DEPRECATED_OPTIONS handling. A first use prints
// "Use of --foo is deprecated." to stderr like Certbot's
// DeprecatedArgumentAction (util.py:add_deprecated_argument).
func registerDeprecated(fs *pflag.FlagSet, c *config.Config, names []string) {
	for _, n := range names {
		name := n // capture
		dummy := false
		fs.BoolVar(&dummy, name, false, "(deprecated, ignored)")
		_ = fs.MarkHidden(name)
		c.PostParseHooks = append(c.PostParseHooks, func() {
			if c.SetByUser(name) {
				fmt.Fprintf(os.Stderr, "Use of %s is deprecated.\n", name)
			}
		})
	}
}

// normalizeDomains lower-cases each entry, strips trailing dots, and dedupes
// preserving first-seen order. Mirrors certbot.cli.cli_utils.DomainsAction
// (cli_utils.py:_DomainsAction.__call__).
func normalizeDomains(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		s = strings.ToLower(s)
		// Strip a single trailing dot; an FQDN with `.` at the end
		// (the root label) is equivalent to the same name without.
		s = strings.TrimSuffix(s, ".")
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
