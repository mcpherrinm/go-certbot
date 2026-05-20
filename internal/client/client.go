// Package client wraps lego v5 to drive ACME flows while reading/writing the
// Certbot-shaped on-disk state in internal/account, internal/storage, and
// internal/storage/renewalconf.
package client

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	legoclient "github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage"
)

// version is the go-certbot version string; used in the User-Agent.
const version = "0.6.0-phase6"

// Client bundles a lego Client with the loaded account.
type Client struct {
	cfg     *config.Config
	account *account.Account
	user    *legoUser
	lego    *legoclient.Client
}

// New constructs a Client for the given config and account. The account must
// already be registered with the CA (its Registration.URI populated) unless
// EnsureAccount has been called.
func New(cfg *config.Config, acc *account.Account) (*Client, error) {
	user := userFromAccount(acc)
	lcfg := legoclient.NewConfig(user)
	lcfg.CADirURL = cfg.EffectiveServer()
	lcfg.UserAgent = userAgent(cfg)
	if cfg.NoVerifySSL {
		lcfg.HTTPClient.Transport = insecureTransport()
	}
	// Validate key_type early; the actual KeyType travels on the per-cert
	// ObtainRequest, not the Config.
	if _, err := certKeyType(cfg); err != nil {
		return nil, err
	}
	lc, err := legoclient.NewClient(lcfg)
	if err != nil {
		return nil, fmt.Errorf("client: lego.NewClient: %w", err)
	}
	return &Client{cfg: cfg, account: acc, user: user, lego: lc}, nil
}

// EnsureRegistered registers the account with the CA if it has no Location
// URL. On success, c.account.Registration is updated and written to disk.
func (c *Client) EnsureRegistered(ctx context.Context, accountStorage *account.FileStorage) error {
	if c.account.Registration.URI != "" {
		return nil
	}
	if !c.cfg.TOS {
		return errors.New("client: --agree-tos is required to register a new ACME account")
	}
	if c.cfg.Email == "" && !c.cfg.RegisterUnsafelyWithoutEmail {
		return errors.New("client: --email is required (or pass --register-unsafely-without-email)")
	}

	var (
		reg *acme.ExtendedAccount
		err error
	)
	if c.cfg.EABKid != "" {
		// External Account Binding: required by Sectigo/ZeroSSL and
		// optionally by Let's Encrypt for some profile types. lego's
		// RegisterWithExternalAccountBinding wraps the EAB JWS.
		reg, err = c.lego.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  c.cfg.EABKid,
			HmacEncoded:          c.cfg.EABHMACKey,
		})
	} else {
		reg, err = c.lego.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return fmt.Errorf("client: ACME register: %w", err)
	}
	c.account.Registration.URI = reg.Location
	if c.cfg.Email != "" {
		c.account.Contact = []string{"mailto:" + c.cfg.Email}
	}
	c.account.Meta.CreationDT.Time = time.Now().UTC().Round(time.Second)
	if h, err := os.Hostname(); err == nil {
		c.account.Meta.CreationHost = h
	}
	c.user.reg = &acme.ExtendedAccount{Location: reg.Location}
	if err := accountStorage.Save(c.account); err != nil {
		return fmt.Errorf("client: save account: %w", err)
	}
	return nil
}

// Obtain runs an ACME order for the given domains using the supplied
// authenticator and writes the result to disk as a new lineage version.
// Returns the lineage path information.
func (c *Client) Obtain(ctx context.Context, auth plugins.Authenticator, domains []string, certName string) (*storage.Lineage, error) {
	kind, provider, err := auth.Prepare(ctx, c.cfg, domains)
	if err != nil {
		return nil, fmt.Errorf("client: authenticator %s: %w", auth.Name(), err)
	}
	defer func() { _ = auth.Cleanup(ctx) }()
	switch kind {
	case plugins.HTTP01:
		if err := c.lego.Challenge.SetHTTP01Provider(provider); err != nil {
			return nil, fmt.Errorf("client: SetHTTP01Provider: %w", err)
		}
	case plugins.DNS01:
		if err := c.lego.Challenge.SetDNS01Provider(provider); err != nil {
			return nil, fmt.Errorf("client: SetDNS01Provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("client: authenticator %s returned unknown challenge kind %d", auth.Name(), kind)
	}

	kt, err := certKeyType(c.cfg)
	if err != nil {
		return nil, err
	}
	req := certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		MustStaple:     c.cfg.MustStaple,
		PreferredChain: c.cfg.PreferredChain,
		Profile:        c.cfg.PreferredProfile,
		KeyType:        kt,
	}
	if c.cfg.RequiredProfile != "" {
		req.Profile = c.cfg.RequiredProfile
	}
	resource, err := c.lego.Certificate.Obtain(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client: ACME order: %w", err)
	}

	lineage, err := storage.Write(c.cfg.ConfigDir, certName, resource.Certificate, resource.IssuerCertificate, resource.PrivateKey, storage.WriteOptions{
		StrictPermissions: c.cfg.StrictPermissions,
	})
	if err != nil {
		return nil, err
	}

	if err := writeRenewalConf(c.cfg, certName, c.account.ID, domains, lineage); err != nil {
		return nil, err
	}
	return lineage, nil
}

// RevokeWithReason revokes the given PEM-encoded certificate using lego's
// Certifier.RevokeWithReason. reason is an RFC 5280 code (use 0 if unset).
func (c *Client) RevokeWithReason(ctx context.Context, certPEM []byte, reason uint) error {
	r := reason // lego wants *uint, distinguish unspecified from 0
	return c.lego.Certificate.RevokeWithReason(ctx, certPEM, &r)
}

// UpdateAccount changes the account's contact email at the ACME server.
// Pass "" to clear it (use carefully — Let's Encrypt currently rejects this).
func (c *Client) UpdateAccount(ctx context.Context, email string) error {
	c.user.email = email
	_, err := c.lego.Registration.UpdateRegistration(ctx, registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	return err
}

// DeactivateAccount marks the account "deactivated" at the ACME server.
// After this the account key can no longer be used for new orders.
func (c *Client) DeactivateAccount(ctx context.Context) error {
	return c.lego.Registration.DeleteRegistration(ctx)
}

// LeafExpiry parses the issued cert's NotAfter for logging.
func LeafExpiry(fullchainPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(fullchainPEM)
	if block == nil {
		return time.Time{}, errors.New("client: empty PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// certKeyType maps Certbot's key_type/rsa_key_size/elliptic_curve trio onto
// lego's KeyType enum.
func certKeyType(cfg *config.Config) (certcrypto.KeyType, error) {
	switch cfg.KeyType {
	case "rsa":
		switch cfg.RSAKeySize {
		case 0, 2048:
			return certcrypto.RSA2048, nil
		case 4096:
			return certcrypto.RSA4096, nil
		case 8192:
			return certcrypto.RSA8192, nil
		}
		return "", fmt.Errorf("client: unsupported rsa_key_size %d", cfg.RSAKeySize)
	case "ecdsa", "ec", "":
		switch cfg.EllipticCurve {
		case "", "secp256r1", "P-256":
			return certcrypto.EC256, nil
		case "secp384r1", "P-384":
			return certcrypto.EC384, nil
		}
		return "", fmt.Errorf("client: unsupported elliptic_curve %q", cfg.EllipticCurve)
	}
	return "", fmt.Errorf("client: unsupported key_type %q", cfg.KeyType)
}

func userAgent(cfg *config.Config) string {
	if cfg.UserAgent != "" {
		return cfg.UserAgent
	}
	base := fmt.Sprintf("go-certbot/%s (%s; %s)", version, runtime.GOOS, runtime.GOARCH)
	if cfg.UserAgentComment != "" {
		base += " " + cfg.UserAgentComment
	}
	return base
}
