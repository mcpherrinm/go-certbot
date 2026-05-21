// Package route53 wraps lego's AWS Route 53 DNS-01 provider.
//
// Certbot's --dns-route53 traditionally honors any of the standard
// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_PROFILE / instance-role
// auth chains; we follow that, letting lego (and the AWS SDK) resolve creds.
// If --dns-route53-credentials is set, we treat it as an additional INI:
//
//	dns_route53_access_key_id = ...
//	dns_route53_secret_access_key = ...
//	dns_route53_hosted_zone_id = ...   # optional
//	dns_route53_region = us-east-1     # optional
package route53

import (
	"context"
	"fmt"
	"os"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/route53"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator             { return &Authenticator{} }
func (a *Authenticator) Name() string { return "dns-route53" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via AWS Route 53."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	if path := common.CredentialsFor(cfg, "route53"); path != "" {
		cred, err := common.LoadCredentials(path, "dns_route53")
		if err != nil {
			return 0, nil, err
		}
		cred.SetEnvOpt("access_key_id", "AWS_ACCESS_KEY_ID")
		cred.SetEnvOpt("secret_access_key", "AWS_SECRET_ACCESS_KEY")
		cred.SetEnvOpt("region", "AWS_REGION")
		cred.SetEnvOpt("hosted_zone_id", "AWS_HOSTED_ZONE_ID")
	} else if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		// No explicit creds and no environment chain hint — surface a clear
		// message rather than letting the SDK fail mid-order.
		fmt.Fprintln(os.Stderr,
			"dns-route53: no --dns-route53-credentials and no AWS_ACCESS_KEY_ID set; relying on the AWS SDK credential chain (instance role / shared config / SSO).")
	}
	common.PropagationEnv("AWS_", common.PropagationFor(cfg, "route53", 10))
	p, err := route53.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("route53: %w", err)
	}
	return common.PluginKind, p, nil
}
