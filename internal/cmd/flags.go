package cmd

import (
	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

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

	// Domains
	fs.StringSliceVarP(&c.Domains, "domain", "d", c.Domains, "Domain name to include (repeatable).")
	fs.StringSliceVar(&c.Domains, "domains", c.Domains, "Alias for --domain.")
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
	fs.StringVar(&c.CSR, "csr", c.CSR, "Path to a CSR (DER or PEM); --csr-driven issuance with certonly.")
	fs.StringVar(&c.CertPath, "cert-path", c.CertPath, "Path to an existing fullchain PEM (revoke/install).")
	fs.StringVar(&c.KeyPath, "key-path", c.KeyPath, "Path to an existing private key (install / revoke --key-path).")
	fs.StringVar(&c.Reason, "reason", c.Reason, "Revocation reason: unspecified, keycompromise, affiliationchanged, superseded, cessationofoperation.")
	fs.BoolVar(&c.DeleteAfterRevoke, "delete-after-revoke", c.DeleteAfterRevoke, "Also delete lineage files after a successful revoke.")

	// Plugin selection
	fs.StringVar(&c.Authenticator, "authenticator", c.Authenticator, "Authenticator plugin name.")
	fs.StringVar(&c.Installer, "installer", c.Installer, "Installer plugin name.")
	fs.StringVar(&c.Configurator, "configurator", c.Configurator, "Plugin that is both authenticator and installer.")
	fs.BoolVar(&c.Apache, "apache", c.Apache, "Use the apache plugin.")
	fs.StringVar(&c.ApacheConfig, "apache-config", c.ApacheConfig, "Path to apache2.conf / httpd.conf (default /etc/apache2/apache2.conf).")
	fs.StringVar(&c.ApacheServerRoot, "apache-server-root", c.ApacheServerRoot, "Apache server root (default /etc/apache2).")
	fs.StringVar(&c.ApacheCtl, "apache-ctl", c.ApacheCtl, "Apache control binary (default apachectl).")

	// Enhancements
	fs.BoolVar(&c.HSTS, "hsts", c.HSTS, "Add a Strict-Transport-Security header (enhance verb).")
	fs.BoolVar(&c.UIR, "uir", c.UIR, "Add a Content-Security-Policy: upgrade-insecure-requests header (enhance verb).")
	fs.BoolVar(&c.Staple, "staple-ocsp", c.Staple, "Enable OCSP stapling (enhance verb).")
	fs.BoolVar(&c.Nginx, "nginx", c.Nginx, "Use the nginx plugin.")
	fs.StringVar(&c.NginxConfig, "nginx-config", c.NginxConfig, "Path to nginx.conf (default /etc/nginx/nginx.conf).")
	fs.StringVar(&c.NginxServerRoot, "nginx-server-root", c.NginxServerRoot, "Nginx server root (default /etc/nginx).")
	fs.StringVar(&c.NginxCtl, "nginx-ctl", c.NginxCtl, "Nginx control binary (default nginx).")
	registerRedirectFlags(fs, c)
	fs.BoolVar(&c.Standalone, "standalone", c.Standalone, "Use the standalone plugin.")
	fs.BoolVar(&c.Webroot, "webroot", c.Webroot, "Use the webroot plugin.")
	fs.StringSliceVarP(&c.WebrootPath, "webroot-path", "w", c.WebrootPath, "Webroot directory (interleave with -d for per-domain map).")
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
	fs.BoolVar(&c.Quiet, "quiet", c.Quiet, "Quiet mode. Implies --non-interactive.")
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
	fs.BoolVar(&c.RunDeployHooks, "run-deploy-hooks", c.RunDeployHooks, "Always run deploy hooks on `reconfigure`.")

	// Path overrides for certonly --csr. Note: --cert-path itself is also
	// registered above (bound to c.CertPath for revoke/install). For
	// certonly --csr destinations Certbot uses these chain variants.
	fs.StringVar(&c.AuthChainPath, "chain-path", c.AuthChainPath, "Where to write the issuer chain when using --csr.")
	fs.StringVar(&c.FullchainPath, "fullchain-path", c.FullchainPath, "Where to write the full chain when using --csr.")

	// Hooks
	fs.StringVar(&c.PreHook, "pre-hook", c.PreHook, "Command to run before challenge.")
	fs.StringVar(&c.PostHook, "post-hook", c.PostHook, "Command to run after any attempt.")
	fs.StringVar(&c.DeployHook, "deploy-hook", c.DeployHook, "Command to run after a successful issuance.")
	fs.StringVar(&c.DeployHook, "renew-hook", c.DeployHook, "Alias for --deploy-hook (legacy name).")
	fs.BoolVar(&c.DisableHookValidation, "disable-hook-validation", c.DisableHookValidation, "Skip the check that hook commands are executable.")
	fs.StringVar(&c.ManualAuthHook, "manual-auth-hook", c.ManualAuthHook, "Path to a script that publishes challenge data (manual plugin).")
	fs.StringVar(&c.ManualCleanupHook, "manual-cleanup-hook", c.ManualCleanupHook, "Path to a script that removes challenge data (manual plugin).")

	// Default-True bool pairs (`--no-X` flips off).
	registerBoolDefaultTrue(fs, c, &c.Autorenew, "autorenew", "Track this cert for auto-renewal.")
	registerBoolDefaultTrue(fs, c, &c.RandomSleepOnRenew, "random-sleep-on-renew", "Insert a random sleep at the start of renew.")

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
	fs.StringSliceVar(&c.PluginIfaces, "authenticators", c.PluginIfaces, "(plugins verb) Limit to authenticator plugins only.")
	fs.StringSliceVar(&c.PluginIfaces, "installers", c.PluginIfaces, "(plugins verb) Limit to installer plugins only.")

	// Deprecated flags Certbot accepts but ignores. Registered so cli.ini and
	// command-line invocations don't error.
	registerDeprecated(fs, []string{
		"os-packages-only",
		"no-self-upgrade",
		"no-bootstrap",
		"no-permissions-check",
		"dns-route53-propagation-seconds",
		"manual-public-ip-logging-ok",
	})
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
		if c.SetByUser("no-"+name) {
			*dst = false
		}
	})
}

// registerDeprecated registers each name as a hidden boolean no-op so old
// cli.ini files and shell scripts don't error out. Matches Certbot's
// DEPRECATED_OPTIONS handling.
func registerDeprecated(fs *pflag.FlagSet, names []string) {
	for _, n := range names {
		dummy := false
		fs.BoolVar(&dummy, n, false, "(deprecated, ignored)")
		_ = fs.MarkHidden(n)
	}
}
