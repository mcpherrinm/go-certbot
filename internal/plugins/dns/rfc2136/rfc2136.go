// Package rfc2136 wraps lego's dnsupdate (RFC 2136) DNS-01 provider as a
// go-certbot authenticator named "dns-rfc2136" (matching Certbot, despite
// lego's package being dnsupdate).
//
// Credentials keys:
//
//	dns_rfc2136_server = 192.0.2.1
//	dns_rfc2136_port = 53                # optional
//	dns_rfc2136_name = keyname
//	dns_rfc2136_secret = base64-secret
//	dns_rfc2136_algorithm = HMAC-SHA512  # optional, default HMAC-SHA512
package rfc2136

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/dnsupdate"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

// Algorithms accepted by certbot-dns-rfc2136 (uppercase, no trailing dot).
// Matches certbot-dns-rfc2136 ALGORITHMS table; rejecting unknown values here
// surfaces the typo at preflight rather than mid-update.
var acceptedAlgorithms = map[string]struct{}{
	"HMAC-MD5":    {},
	"HMAC-SHA1":   {},
	"HMAC-SHA224": {},
	"HMAC-SHA256": {},
	"HMAC-SHA384": {},
	"HMAC-SHA512": {},
}

type Authenticator struct{}

func New() *Authenticator             { return &Authenticator{} }
func (a *Authenticator) Name() string { return "dns-rfc2136" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via RFC 2136 dynamic updates."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "rfc2136"), "dns_rfc2136")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("server", "name", "secret"); err != nil {
		return 0, nil, err
	}
	server := cred.Get("server")
	if net.ParseIP(server) == nil {
		return 0, nil, fmt.Errorf(
			"The configured target DNS server (%s) is not a valid IPv4 or IPv6 address. A hostname is not allowed.",
			server)
	}
	if port := cred.Get("port"); port != "" {
		server += ":" + port
	}
	if alg := cred.Get("algorithm"); alg != "" {
		if _, ok := acceptedAlgorithms[strings.ToUpper(alg)]; !ok {
			return 0, nil, fmt.Errorf("Unknown algorithm: %s.", alg)
		}
	}
	_ = os.Setenv("DNSUPDATE_NAMESERVER", server)
	_ = cred.SetEnv("name", "DNSUPDATE_TSIG_KEY")
	_ = cred.SetEnv("secret", "DNSUPDATE_TSIG_SECRET")
	// Certbot accepts algorithm names like "HMAC-SHA512" (uppercase, no dot);
	// lego's dnsupdate (miekg/dns under the hood) expects "hmac-sha512."
	// (lowercase, trailing dot). Translate or every RFC 2136 user breaks.
	if alg := cred.Get("algorithm"); alg != "" {
		_ = os.Setenv("DNSUPDATE_TSIG_ALGORITHM", normalizeTSIGAlg(alg))
	}
	common.PropagationEnv("DNSUPDATE_", common.PropagationFor(cfg, "rfc2136", 60))
	p, err := dnsupdate.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("rfc2136: %w", err)
	}
	return common.PluginKind, p, nil
}

// normalizeTSIGAlg converts a Certbot-style TSIG algorithm name to lego's
// expected miekg/dns form (lowercase + trailing dot). "hmac-sha512." is
// passed through as-is.
func normalizeTSIGAlg(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
