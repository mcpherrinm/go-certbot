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
	"os"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/dnsupdate"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-rfc2136" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via RFC 2136 dynamic updates." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "rfc2136"), "dns_rfc2136")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("server", "name", "secret"); err != nil {
		return 0, nil, err
	}
	server := cred.Get("server")
	if port := cred.Get("port"); port != "" {
		server += ":" + port
	}
	_ = os.Setenv("DNSUPDATE_NAMESERVER", server)
	_ = cred.SetEnv("name", "DNSUPDATE_TSIG_KEY")
	_ = cred.SetEnv("secret", "DNSUPDATE_TSIG_SECRET")
	cred.SetEnvOpt("algorithm", "DNSUPDATE_TSIG_ALGORITHM")
	common.PropagationEnv("DNSUPDATE_", common.PropagationFor(cfg, "rfc2136"))
	p, err := dnsupdate.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("rfc2136: %w", err)
	}
	return common.PluginKind, p, nil
}
