// Package config holds the runtime configuration analogous to Certbot's
// certbot.configuration.NamespaceConfig. Fields mirror constants.CLI_DEFAULTS;
// only the subset wired through Phase 1 has behavior — other fields are
// preserved verbatim through the CLI/INI layer so flags don't churn as later
// phases land.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ArgumentSource records where a config value came from. Mirrors
// certbot.configuration.ArgumentSource. Used during renewal to decide whether
// to override on-disk values with command-line overrides.
type ArgumentSource int

const (
	SourceDefault     ArgumentSource = iota // not set by the user
	SourceCommandLine                       // --flag on argv
	SourceConfigFile                        // cli.ini
	SourceEnvVar                            // CERTBOT_* env
	SourceRuntime                           // computed at runtime
)

const (
	DefaultLetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	StagingDirectory            = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Config is the parsed-and-merged configuration for a single invocation.
type Config struct {
	Verb string

	// Paths
	ConfigDir string
	WorkDir   string
	LogsDir   string

	// Identity / server
	Server                       string
	Email                        string
	RegisterUnsafelyWithoutEmail bool
	TOS                          bool
	Account                      string
	NoEFFEmail                   bool
	EFFEmailExplicit             bool // --eff-email was passed (vs unset)

	// Certificate request
	Domains            []string
	IPAddresses        []string
	CertName           string
	KeyType            string // "rsa" | "ecdsa"
	RSAKeySize         int
	EllipticCurve      string
	MustStaple         bool
	PreferredChain     string
	PreferredProfile   string
	RequiredProfile    string
	ReuseKey           bool
	NewKey             bool
	AllowSubsetOfNames bool
	CSR                string
	CertPath           string // existing fullchain PEM, e.g. for --revoke / --install
	KeyPath            string // private key, e.g. for --install or --revoke --key-path
	Reason             string // revocation reason word
	DeleteAfterRevoke  bool

	// Plugin selection
	Authenticator string
	Installer     string
	Configurator  string
	Apache        bool
	Nginx         bool
	// Nginx-specific
	NginxConfig     string // explicit nginx.conf path; overrides NginxServerRoot
	NginxServerRoot string // /etc/nginx default
	NginxCtl        string // nginx binary (default "nginx")
	Redirect        *bool  // tri-state: nil = ask/auto, true = add 301, false = skip
	// Apache-specific
	ApacheConfig     string // explicit apache2.conf path; overrides ApacheServerRoot
	ApacheServerRoot string // /etc/apache2 default
	ApacheCtl        string // apachectl binary (default "apachectl")
	Standalone    bool
	Webroot       bool
	WebrootPath   []string
	// WebrootMap is the resolved domain → webroot path map. Built before
	// pflag parsing from the `-w`/`-d` interleaving order in os.Args; mirrors
	// Certbot's _WebrootPathProcessor. Persisted under [[webroot_map]] in the
	// renewal conf and restored on `renew`.
	WebrootMap map[string]string
	Manual     bool

	// DNS plugins. Selected[name]=true means --dns-<name> was set.
	// Credentials[name]=path is --dns-<name>-credentials. Propagation[name]
	// is --dns-<name>-propagation-seconds.
	DNSSelected           map[string]bool
	DNSCredentials        map[string]string
	DNSPropagationSeconds map[string]int

	// HTTP-01
	HTTP01Port    int
	HTTP01Address string
	HTTPSPort     int

	// Behavior flags
	DryRun           bool
	Staging          bool
	Debug            bool
	NoVerifySSL      bool
	Quiet            bool
	NonInteractive   bool
	ForceInteractive bool
	Verbose          int

	// Hooks
	PreHook            string
	PostHook           string
	DeployHook         string
	DisableHookValidation bool
	ManualAuthHook     string
	ManualCleanupHook  string
	ManualPublicIPLoggingOK bool

	// User agent
	UserAgent        string
	UserAgentComment string

	// External Account Binding
	EABKid     string
	EABHMACKey string
	EABHMACAlg string

	// Lifecycle / behavior flags Certbot accepts.
	Duplicate           bool
	Expand              bool
	ForceRenewal        bool
	StrictPermissions   bool
	IssuanceTimeout     int
	PreferredChallenges []string

	// Tri-state booleans (nil = "Ask", true = yes, false = no). Mirrors
	// Certbot's None default for HSTS/UIR/staple/EFF-subscribe/redirect.
	EFFEmail *bool // --eff-email / --no-eff-email

	// CSR-driven certonly destination paths.
	AuthCertPath  string // --cert-path under certonly --csr
	AuthChainPath string // --chain-path under certonly --csr
	FullchainPath string // --fullchain-path

	// `certificates`, `delete`, `revoke` numeric controls.
	Num                int
	BreakMyCerts       bool
	ReinstallExisting  bool
	RenewWithNewDomains bool
	RunDeployHooks     bool
	AutoHSTS           bool
	DisableRenewUpdates bool

	// Three-state defaults-True flags (`--no-X` flips them off). Stored as
	// non-pointer booleans seeded True in NewDefault().
	RandomSleepOnRenew bool // --no-random-sleep-on-renew
	DirectoryHooks     bool // --no-directory-hooks
	Autorenew          bool // --no-autorenew
	ValidateHooks      bool // --no-validate-hooks / --disable-hook-validation

	// Plugins-verb scoped state.
	PluginsInit    bool
	PluginsPrepare bool
	PluginIfaces   []string // --authenticators / --installers selector

	// Logging.
	VerboseLevel      string
	TextMode          bool
	MaxLogBackups     int
	PreconfiguredRenew bool
	DebugChallenges   bool

	// Sources tracks which fields were user-set, for renewal merge logic.
	Sources map[string]ArgumentSource

	// PostParseHooks run after CLI parsing completes. Used by tri-state and
	// default-True bool flags (--no-X) that need a post-pass to resolve.
	PostParseHooks []func()
}

// NewDefault returns a Config seeded with Certbot's CLI_DEFAULTS for the host OS.
func NewDefault() *Config {
	return &Config{
		ConfigDir:             DefaultConfigDir(),
		WorkDir:               DefaultWorkDir(),
		LogsDir:               DefaultLogsDir(),
		Server:                DefaultLetsEncryptDirectory,
		KeyType:               "ecdsa",
		RSAKeySize:            2048,
		EllipticCurve:         "secp256r1",
		HTTP01Port:            80,
		HTTPSPort:             443,
		EABHMACAlg:            "HS256",
		IssuanceTimeout:       90,
		MaxLogBackups:         1000,
		RandomSleepOnRenew:    true,
		DirectoryHooks:        true,
		Autorenew:             true,
		ValidateHooks:         true,
		AuthCertPath:          "./cert.pem",
		AuthChainPath:         "./chain.pem",
		Sources:               map[string]ArgumentSource{},
		DNSSelected:           map[string]bool{},
		DNSCredentials:        map[string]string{},
		DNSPropagationSeconds: map[string]int{},
	}
}

// MarkSet records that a field was set by the named source.
func (c *Config) MarkSet(field string, src ArgumentSource) {
	if c.Sources == nil {
		c.Sources = map[string]ArgumentSource{}
	}
	c.Sources[field] = src
}

// SetByUser reports whether `name` was specified by the user (CLI, config file,
// env). Mirrors NamespaceConfig.set_by_user. Used by renewal logic.
func (c *Config) SetByUser(name string) bool {
	src, ok := c.Sources[name]
	if !ok {
		return false
	}
	return src != SourceDefault
}

// EffectiveServer returns the directory URL to use, honoring --staging.
func (c *Config) EffectiveServer() string {
	if c.Staging && c.Server == DefaultLetsEncryptDirectory {
		return StagingDirectory
	}
	return c.Server
}

// ServerPath returns the on-disk path component for the current server,
// matching certbot.configuration.NamespaceConfig.server_path: netloc + path
// with '/' replaced by os.PathSeparator. Used inside accounts/. The
// underscore-substitution step is applied separately by AccountsDir, matching
// certbot.configuration.accounts_dir_for_server_path.
func (c *Config) ServerPath() (string, error) {
	u, err := url.Parse(c.EffectiveServer())
	if err != nil {
		return "", fmt.Errorf("parse server URL %q: %w", c.EffectiveServer(), err)
	}
	combined := u.Host + u.Path
	return strings.ReplaceAll(combined, "/", string(filepath.Separator)), nil
}

// AccountsDir returns <config_dir>/accounts/<server_path>.
func (c *Config) AccountsDir() (string, error) {
	sp, err := c.ServerPath()
	if err != nil {
		return "", err
	}
	sp = underscoresForUnsupportedChars(sp)
	return filepath.Join(c.ConfigDir, "accounts", sp), nil
}

func (c *Config) LiveDir() string           { return filepath.Join(c.ConfigDir, "live") }
func (c *Config) ArchiveDir() string        { return filepath.Join(c.ConfigDir, "archive") }
func (c *Config) RenewalConfigsDir() string { return filepath.Join(c.ConfigDir, "renewal") }
func (c *Config) KeysDir() string           { return filepath.Join(c.ConfigDir, "keys") }
func (c *Config) CSRDir() string            { return filepath.Join(c.ConfigDir, "csr") }

// HookDir returns <config_dir>/renewal-hooks/<kind>.
func (c *Config) HookDir(kind string) string {
	return filepath.Join(c.ConfigDir, "renewal-hooks", kind)
}

// underscoresForUnsupportedChars replaces ':' characters in path with '_'
// after the optional drive prefix. Matches Certbot's
// underscores_for_unsupported_characters_in_path (compat/misc.py:121-135),
// which only touches ':' (and only in the tail after splitdrive). No-op on
// non-Windows.
func underscoresForUnsupportedChars(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	// Equivalent of Python os.path.splitdrive: drive is `X:` or `\\server\share`.
	drive := ""
	tail := p
	if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		drive = p[:2]
		tail = p[2:]
	}
	return drive + strings.ReplaceAll(tail, ":", "_")
}

func DefaultConfigDir() string {
	if runtime.GOOS == "windows" {
		return `C:\Certbot`
	}
	return "/etc/letsencrypt"
}

func DefaultWorkDir() string {
	if runtime.GOOS == "windows" {
		return `C:\Certbot\lib`
	}
	return "/var/lib/letsencrypt"
}

func DefaultLogsDir() string {
	if runtime.GOOS == "windows" {
		return `C:\Certbot\log`
	}
	return "/var/log/letsencrypt"
}

// CLIIniSearchPaths returns the paths Certbot probes for cli.ini, in order.
// See certbot._internal.constants.CLI_DEFAULTS["config_files"].
func CLIIniSearchPaths(configDir string) []string {
	out := []string{filepath.Join(configDir, "cli.ini")}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		if home, err := os.UserHomeDir(); err == nil {
			xdg = filepath.Join(home, ".config")
		}
	}
	if xdg != "" {
		out = append(out, filepath.Join(xdg, "letsencrypt", "cli.ini"))
	}
	return out
}
