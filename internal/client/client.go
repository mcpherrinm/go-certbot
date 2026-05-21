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
	"net"
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
	"github.com/letsencrypt/go-certbot/internal/display"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage"
)

// version is the go-certbot version string; used in the User-Agent.
const version = "1.4.0"

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
//
// Mirrors certbot._internal.main._determine_account: if --agree-tos isn't
// set and we're interactive, prompt before failing. Non-interactive without
// --agree-tos errors out (same wording as Certbot's _tos_cb).
func (c *Client) EnsureRegistered(ctx context.Context, accountStorage *account.FileStorage) error {
	if c.account.Registration.URI != "" {
		return nil
	}
	if !c.cfg.TOS {
		if c.cfg.NonInteractive {
			return errors.New("client: --agree-tos is required to register a new ACME account (and you passed --non-interactive, so I can't prompt)")
		}
		prompt := fmt.Sprintf(
			"Please read the Terms of Service at %s. You must agree in order to register with the ACME server. Do you agree?",
			"https://letsencrypt.org/repository/")
		if !display.YesNoDefault(prompt, true) {
			return errors.New("client: TOS not accepted; aborting registration")
		}
		c.cfg.TOS = true
	}
	if c.cfg.Email == "" && !c.cfg.RegisterUnsafelyWithoutEmail {
		if c.cfg.NonInteractive {
			// Certbot 3.3.0 dropped --register-unsafely-without-email's
			// requirement in non-interactive mode: an empty email is
			// treated as an explicit no-email opt-in.
			c.cfg.RegisterUnsafelyWithoutEmail = true
		} else {
			c.cfg.Email = display.Email("Enter email address (used for urgent renewal and security notices):")
			if c.cfg.Email == "" {
				// Interactive: pressing Enter at the prompt registers
				// without email, matching certbot._internal.main._determine_account
				// and the accounts verb.
				c.cfg.RegisterUnsafelyWithoutEmail = true
			}
		}
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
	identifiers := append([]string(nil), domains...)
	// IP-address SANs (--ip-address) are added to the identifier list; lego
	// auto-detects IP literals via net.ParseIP and switches Type to "ip".
	for _, ip := range c.cfg.IPAddresses {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("client: --ip-address %q is not a valid IP literal", ip)
		}
		identifiers = append(identifiers, ip)
	}
	req := certificate.ObtainRequest{
		Domains:        identifiers,
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

	// Certbot saves private keys in PKCS#8 (PEM `PRIVATE KEY`). lego returns
	// PKCS#1 for RSA and SEC1 for EC; re-wrap for on-disk parity.
	pkcs8Key, err := toPKCS8(resource.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("client: re-encode key as PKCS#8: %w", err)
	}

	lineage, err := storage.Write(c.cfg.ConfigDir, certName, resource.Certificate, resource.IssuerCertificate, pkcs8Key, storage.WriteOptions{
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

// RenewalInfo queries the ACME server's RFC 9773 renewalInfo endpoint for the
// given leaf cert. Returns (nil, nil) if the server doesn't support ARI.
func (c *Client) RenewalInfo(ctx context.Context, leaf *x509.Certificate) (*certificate.RenewalInfo, error) {
	info, err := c.lego.Certificate.GetRenewalInfo(ctx, leaf)
	if err != nil {
		// Treat unsupported / 404 as "no ARI" rather than an error so renew
		// falls back to renew_before_expiry. Use lego's typed error so a
		// URL like "/.../404x/..." doesn't accidentally swallow the failure.
		var pd *acme.ProblemDetails
		if errors.As(err, &pd) && pd.HTTPStatus == 404 {
			return nil, nil
		}
		return nil, err
	}
	return info, nil
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

// toPKCS8 rewraps a PEM-encoded private key into a PKCS#8 `PRIVATE KEY`
// block. lego emits PKCS#1 (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`);
// Certbot has saved keys in PKCS#8 since 3.2.0 (the older format was a
// regression). Idempotent: already-PKCS#8 input is returned verbatim.
func toPKCS8(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("empty PEM")
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		return keyPEM, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// userAgent composes the User-Agent string Certbot sends to the ACME server.
// Format mirrors certbot.client.determine_user_agent's template:
//
//	CertbotACMEClient/<ver> (<cmd>; <os>) Authenticator/<auth> Installer/<inst> (<verb>; flags: <flags>) Go/<ver>
//
// The flag-derived suffix encodes --duplicate (dup), --force-renewal (frn),
// --allow-subset-of-names (asn), -n / --non-interactive (n), and the
// presence of any hook (hook). The CA uses this for telemetry.
func userAgent(cfg *config.Config) string {
	if cfg.UserAgent != "" {
		return cfg.UserAgent
	}
	authn := cfg.Authenticator
	if authn == "" {
		authn = "none"
	}
	inst := cfg.Installer
	if inst == "" {
		inst = "none"
	}
	verb := cfg.Verb
	if verb == "" {
		verb = "run"
	}
	// Match Certbot's UA token (_internal/client.py:92-105): "certbot" as
	// the cli_command identifier (not "go-certbot"), Py/<go-runtime> as
	// the runtime tag so CA log parsers keying on "Py/" still classify
	// requests as Certbot-shaped.
	ua := fmt.Sprintf("CertbotACMEClient/%s (certbot; %s/%s) Authenticator/%s Installer/%s (%s; flags: %s) Py/%s",
		version, runtime.GOOS, runtime.GOARCH, authn, inst, verb, uaFlags(cfg), runtime.Version())
	if cfg.UserAgentComment != "" {
		ua += " " + cfg.UserAgentComment
	}
	return ua
}

// uaFlags encodes the same flag bits Certbot's ua_flags emits.
func uaFlags(cfg *config.Config) string {
	var flags []string
	if cfg.Duplicate {
		flags = append(flags, "dup")
	}
	if cfg.ForceRenewal {
		flags = append(flags, "frn")
	}
	if cfg.AllowSubsetOfNames {
		flags = append(flags, "asn")
	}
	if cfg.NonInteractive {
		flags = append(flags, "n")
	}
	if cfg.PreHook != "" || cfg.PostHook != "" || cfg.DeployHook != "" ||
		cfg.ManualAuthHook != "" || cfg.ManualCleanupHook != "" {
		flags = append(flags, "hook")
	}
	if len(flags) == 0 {
		return ""
	}
	out := flags[0]
	for _, f := range flags[1:] {
		out += " " + f
	}
	return out
}
