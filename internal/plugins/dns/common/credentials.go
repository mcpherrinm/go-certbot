// Package common holds shared plumbing for DNS authenticator plugins:
// credentials INI parsing matching certbot.plugins.dns_common, env-var
// translation, and the lego-provider factory pattern each plugin follows.
package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Credentials is a parsed dns_<name>_<key> INI file.
type Credentials struct {
	// Prefix is the plugin prefix ("dns_cloudflare", "dns_route53", …).
	Prefix string
	// Path is the source file path (for error messages).
	Path string
	// Values keys are stripped of the prefix (e.g. "api_token", "email").
	Values map[string]string
}

// LoadCredentials reads the named INI file and returns only keys that start
// with `<prefix>_`. Unknown sections are merged into a single map. Matches
// Certbot's CredentialsConfiguration which collapses everything into the
// default section.
//
// Missing or unreadable files are returned as errors; an empty (but readable)
// file is allowed — required-key validation happens via Required().
func LoadCredentials(path, prefix string) (*Credentials, error) {
	if path == "" {
		return nil, fmt.Errorf("%s: --%s-credentials is required", prefix, dashify(prefix))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: stat credentials: %w", prefix, err)
	}
	// Certbot's dns_common.validate_file_permissions only warns on
	// world-readable bits (mask 0o007). Group-readable INI files are
	// common in shared-admin setups, so we don't warn on those.
	if info.Mode().Perm()&0o007 != 0 {
		fmt.Fprintf(os.Stderr,
			"warning: %s is world-accessible (%o); recommend chmod 600 or 640 to protect credentials\n",
			abs, info.Mode().Perm())
	}

	cfg, err := ini.LoadSources(ini.LoadOptions{
		Loose:              false,
		KeyValueDelimiters: "=",
		AllowBooleanKeys:   true,
	}, abs)
	if err != nil {
		return nil, fmt.Errorf("%s: parse credentials %s: %w", prefix, abs, err)
	}

	want := prefix + "_"
	values := map[string]string{}
	for _, section := range cfg.Sections() {
		for _, k := range section.Keys() {
			name := strings.ToLower(k.Name())
			if !strings.HasPrefix(name, want) {
				continue
			}
			values[strings.TrimPrefix(name, want)] = k.Value()
		}
	}
	return &Credentials{Prefix: prefix, Path: abs, Values: values}, nil
}

// Required verifies all listed keys are present and non-empty.
func (c *Credentials) Required(keys ...string) error {
	var missing []string
	for _, k := range keys {
		if v, ok := c.Values[k]; !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, c.Prefix+"_"+k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s: missing required keys in %s: %s",
			c.Prefix, c.Path, strings.Join(missing, ", "))
	}
	return nil
}

// AnyOf checks that at least one of the named keys is present and non-empty.
// Returns the first matching key name (without prefix) or "" if none matched.
func (c *Credentials) AnyOf(keys ...string) string {
	for _, k := range keys {
		if v, ok := c.Values[k]; ok && strings.TrimSpace(v) != "" {
			return k
		}
	}
	return ""
}

// Get returns the value for a credentials key, or "" if absent.
func (c *Credentials) Get(key string) string { return c.Values[key] }

// SetEnv puts the given key into the environment under envName, so a lego
// provider's NewDNSProvider() picks it up. Restoring previous env is not
// attempted (the process is short-lived).
func (c *Credentials) SetEnv(key, envName string) error {
	v, ok := c.Values[key]
	if !ok || strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s: credentials key %q is empty", c.Prefix, key)
	}
	return os.Setenv(envName, v)
}

// SetEnvOpt is like SetEnv but doesn't error on missing keys.
func (c *Credentials) SetEnvOpt(key, envName string) {
	if v, ok := c.Values[key]; ok && strings.TrimSpace(v) != "" {
		_ = os.Setenv(envName, v)
	}
}

// PropagationEnv translates a Certbot-style propagation-seconds value into
// lego's PROPAGATION_TIMEOUT env (in Go duration form). prefix matches lego's
// EnvPropagationTimeout pattern (e.g. "CLOUDFLARE_").
func PropagationEnv(envPrefix string, seconds int) {
	if seconds <= 0 {
		return
	}
	_ = os.Setenv(envPrefix+"PROPAGATION_TIMEOUT", fmt.Sprintf("%ds", seconds))
}

// PropagationFor returns the Certbot CLI propagation-seconds value for a
// plugin, looking up cfg.DNSPropagationSeconds[name]. If the user did not set
// the flag, returns def — the upstream Certbot default for the plugin.
func PropagationFor(cfg *config.Config, name string, def int) int {
	if cfg.DNSPropagationSeconds == nil {
		return def
	}
	if v, ok := cfg.DNSPropagationSeconds[name]; ok {
		return v
	}
	return def
}

// CredentialsFor returns cfg.DNSCredentials[name].
func CredentialsFor(cfg *config.Config, name string) string {
	if cfg.DNSCredentials == nil {
		return ""
	}
	return cfg.DNSCredentials[name]
}

// SelectedDNSPlugin returns the name of the dns-* authenticator the user
// selected, or "" if none.
func SelectedDNSPlugin(cfg *config.Config) string {
	if cfg.DNSSelected == nil {
		return ""
	}
	for name, on := range cfg.DNSSelected {
		if on {
			return "dns-" + name
		}
	}
	return ""
}

func dashify(prefix string) string {
	return strings.ReplaceAll(prefix, "_", "-")
}

// PluginKind is what every DNS plugin returns from Prepare.
const PluginKind = plugins.DNS01

// ErrUnconfigured is the canonical error for "credentials file missing".
var ErrUnconfigured = errors.New("dns: credentials file is required")
