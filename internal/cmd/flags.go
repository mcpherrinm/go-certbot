package cmd

import (
	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// registerFlags wires CLI flags onto the given FlagSet, pointing them at the
// supplied Config. Names match Certbot exactly (including kebab-case) so a
// cli.ini written for Certbot Just Works.
//
// In Phase 1 not every flag has behavior — flags with no current handler are
// still registered so they parse cleanly out of cli.ini and renewal configs.
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

	// Domains
	fs.StringSliceVarP(&c.Domains, "domain", "d", c.Domains, "Domain name to include (repeatable).")
	fs.StringSliceVar(&c.IPAddresses, "ip-address", c.IPAddresses, "IP address SAN (repeatable). Requires --preferred-profile shortlived for Let's Encrypt.")
	fs.StringVar(&c.CertName, "cert-name", c.CertName, "Name (lineage) under which to track this cert.")

	// Key / profile
	fs.StringVar(&c.KeyType, "key-type", c.KeyType, "rsa or ecdsa.")
	fs.IntVar(&c.RSAKeySize, "rsa-key-size", c.RSAKeySize, "RSA key size when --key-type=rsa.")
	fs.StringVar(&c.EllipticCurve, "elliptic-curve", c.EllipticCurve, "Elliptic curve when --key-type=ecdsa.")
	fs.BoolVar(&c.MustStaple, "must-staple", c.MustStaple, "Include the OCSP Must-Staple extension in the issued cert.")
	fs.StringVar(&c.PreferredChain, "preferred-chain", c.PreferredChain, "Preferred issuer chain CN.")
	fs.StringVar(&c.PreferredProfile, "preferred-profile", c.PreferredProfile, "Preferred ACME profile name (falls back if not available).")
	fs.StringVar(&c.RequiredProfile, "required-profile", c.RequiredProfile, "Required ACME profile name (fails if not available).")
	fs.BoolVar(&c.ReuseKey, "reuse-key", c.ReuseKey, "Reuse the same private key on renewal.")
	fs.BoolVar(&c.NewKey, "new-key", c.NewKey, "Generate a fresh private key on renewal.")
	fs.BoolVar(&c.AllowSubsetOfNames, "allow-subset-of-names", c.AllowSubsetOfNames, "Continue if a subset of names authorize.")
	fs.StringVar(&c.CSR, "csr", c.CSR, "Path to a CSR (DER or PEM); only --csr-driven issuance with certonly is supported (not yet in Phase 1).")

	// Plugin selection
	fs.StringVar(&c.Authenticator, "authenticator", c.Authenticator, "Authenticator plugin name.")
	fs.StringVar(&c.Installer, "installer", c.Installer, "Installer plugin name.")
	fs.StringVar(&c.Configurator, "configurator", c.Configurator, "Plugin that is both authenticator and installer.")
	fs.BoolVar(&c.Apache, "apache", c.Apache, "Use the apache plugin (not yet implemented).")
	fs.BoolVar(&c.Nginx, "nginx", c.Nginx, "Use the nginx plugin (not yet implemented).")
	fs.BoolVar(&c.Standalone, "standalone", c.Standalone, "Use the standalone plugin (runs a local HTTP server).")
	fs.BoolVar(&c.Webroot, "webroot", c.Webroot, "Use the webroot plugin (not yet implemented in Phase 1).")
	fs.StringSliceVarP(&c.WebrootPath, "webroot-path", "w", c.WebrootPath, "Webroot directory.")
	fs.BoolVar(&c.Manual, "manual", c.Manual, "Use the manual plugin (not yet implemented in Phase 1).")

	// HTTP-01
	fs.IntVar(&c.HTTP01Port, "http-01-port", c.HTTP01Port, "Port for the http-01 challenge (default 80).")
	fs.StringVar(&c.HTTP01Address, "http-01-address", c.HTTP01Address, "Address to bind the http-01 server to.")
	fs.IntVar(&c.HTTPSPort, "https-port", c.HTTPSPort, "Port to use when configuring https.")

	// Behavior
	fs.BoolVar(&c.DryRun, "dry-run", c.DryRun, "Run as if obtaining a cert without writing to disk.")
	fs.BoolVar(&c.Staging, "staging", c.Staging, "Use the Let's Encrypt staging server.")
	fs.BoolVar(&c.Staging, "test-cert", c.Staging, "Alias for --staging.")
	fs.BoolVar(&c.Debug, "debug", c.Debug, "Enable debug logging.")
	fs.BoolVar(&c.NoVerifySSL, "no-verify-ssl", c.NoVerifySSL, "Skip TLS verification when talking to the ACME server.")
	fs.BoolVar(&c.Quiet, "quiet", c.Quiet, "Quiet mode.")
	fs.BoolVarP(&c.NonInteractive, "non-interactive", "n", c.NonInteractive, "Run without prompts.")
	fs.BoolVar(&c.ForceInteractive, "force-interactive", c.ForceInteractive, "Force interactive mode.")
	fs.CountVarP(&c.Verbose, "verbose", "v", "Increase verbosity.")
	fs.BoolVar(&c.StrictPermissions, "strict-permissions", c.StrictPermissions, "Enforce 0700/0600 on config files.")

	// Hooks
	fs.StringVar(&c.PreHook, "pre-hook", c.PreHook, "Command to run before challenge.")
	fs.StringVar(&c.PostHook, "post-hook", c.PostHook, "Command to run after any attempt.")
	fs.StringVar(&c.DeployHook, "deploy-hook", c.DeployHook, "Command to run after a successful issuance.")

	// User agent
	fs.StringVar(&c.UserAgent, "user-agent", c.UserAgent, "Override the User-Agent header.")
	fs.StringVar(&c.UserAgentComment, "user-agent-comment", c.UserAgentComment, "Append a comment to the User-Agent header.")

	// External Account Binding
	fs.StringVar(&c.EABKid, "eab-kid", c.EABKid, "Key id for ACME External Account Binding.")
	fs.StringVar(&c.EABHMACKey, "eab-hmac-key", c.EABHMACKey, "HMAC key for ACME External Account Binding.")
	fs.StringVar(&c.EABHMACAlg, "eab-hmac-alg", c.EABHMACAlg, "HMAC algorithm for ACME External Account Binding.")

	// Lifecycle flags Certbot accepts (parsed but not yet wired)
	fs.BoolVar(&c.Duplicate, "duplicate", c.Duplicate, "Allow duplicate certs.")
	fs.BoolVar(&c.Expand, "expand", c.Expand, "Expand an existing cert.")
	fs.BoolVar(&c.ForceRenewal, "force-renewal", c.ForceRenewal, "Force renewal even if not near expiry.")
	fs.BoolVar(&c.ForceRenewal, "renew-by-default", c.ForceRenewal, "Alias for --force-renewal.")
	fs.IntVar(&c.IssuanceTimeout, "issuance-timeout", c.IssuanceTimeout, "Per-domain timeout (seconds).")
	fs.StringSliceVar(&c.PreferredChallenges, "preferred-challenges", c.PreferredChallenges, "Preferred challenge types, comma-separated.")
}

// trackSources walks the FlagSet after parsing and records, for each flag
// that Visit reported (i.e. was set by the user), the source as command line.
func trackSources(fs *pflag.FlagSet, c *config.Config) {
	fs.Visit(func(f *pflag.Flag) {
		c.MarkSet(f.Name, config.SourceCommandLine)
	})
}
