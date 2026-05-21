package verbs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// Certificates lists certificates managed by go-certbot. Output matches
// Certbot's `certificates` verb (cert_manager.human_readable_cert_info).
func Certificates(_ context.Context, cfg *config.Config, _ *plugins.Registry) error {
	dir := cfg.RenewalConfigsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No certificates found.")
			return nil
		}
		return fmt.Errorf("certificates: read %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	type cert struct {
		text string
	}
	var matched []cert
	var failures []string
	filterSet := append([]string{}, cfg.Domains...)
	filterSet = append(filterSet, cfg.IPAddresses...)
	for _, name := range names {
		confPath := filepath.Join(dir, name)
		certName := strings.TrimSuffix(name, ".conf")
		if cfg.CertName != "" && cfg.CertName != certName {
			continue
		}
		info, err := describeCert(confPath, certName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", confPath, err))
			continue
		}
		if len(filterSet) > 0 && !info.matches(filterSet) {
			continue
		}
		matched = append(matched, cert{text: info.String()})
	}

	switch {
	case len(matched) == 0 && len(failures) == 0:
		fmt.Println("No certificates found.")
	case len(matched) > 0:
		if cfg.CertName != "" || len(filterSet) > 0 {
			fmt.Println("Found the following matching certs:")
		} else {
			fmt.Println("Found the following certs:")
		}
		for _, c := range matched {
			fmt.Println(c.text)
		}
	}
	if len(failures) > 0 {
		fmt.Println("\nThe following renewal configurations were invalid:")
		for _, f := range failures {
			fmt.Println("  " + f)
		}
	}
	return nil
}

type certInfo struct {
	Name     string
	Serial   string
	KeyType  string
	SANs     []string
	NotAfter time.Time
	Status   string // "VALID: N days" or "INVALID: REASON"
	CertPath string // top-level "fullchain"
	KeyPath  string // top-level "privkey"
}

func (c certInfo) String() string {
	// Certbot formats the expiry as Python's `str(datetime)` does:
	// `2026-01-01 12:34:56+00:00`. Use the equivalent Go layout so monitoring
	// scripts grep-ing for the timestamp still work.
	return fmt.Sprintf("  Certificate Name: %s\n"+
		"    Serial Number: %s\n"+
		"    Key Type: %s\n"+
		"    Identifiers: %s\n"+
		"    Expiry Date: %s (%s)\n"+
		"    Certificate Path: %s\n"+
		"    Private Key Path: %s\n",
		c.Name, c.Serial, c.KeyType,
		strings.Join(c.SANs, " "),
		c.NotAfter.Format("2006-01-02 15:04:05-07:00"), c.Status,
		c.CertPath, c.KeyPath)
}

// matches returns true when every filter name is present in c.SANs.
// Mirrors cert_manager.py:259 which uses `config_sans.issubset(cert.sans())`.
func (c certInfo) matches(filter []string) bool {
	for _, want := range filter {
		found := false
		for _, s := range c.SANs {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func describeCert(confPath, certName string) (*certInfo, error) {
	conf, err := renewalconf.Load(confPath)
	if err != nil {
		return nil, err
	}
	certPath := conf.Top["cert"]
	if certPath == "" {
		return nil, fmt.Errorf("missing 'cert' in %s", confPath)
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("empty PEM in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	keyType := "unknown"
	keyPath := conf.Top["privkey"]
	if kp, err := readKeyType(keyPath); err == nil {
		keyType = kp
	}

	// Mirrors certbot._internal.cert_manager.human_readable_cert_info
	// (cert_manager.py:264-269): TEST_CERT, EXPIRED, REVOKED are independent
	// labels — a staging cert that's also revoked says "TEST_CERT, REVOKED".
	now := time.Now().UTC()
	var reasons []string
	if isTestCert(cert) {
		reasons = append(reasons, "TEST_CERT")
	}
	expired := cert.NotAfter.Before(now)
	if expired {
		reasons = append(reasons, "EXPIRED")
	}
	// OCSP revocation check is a per-cert HTTP roundtrip; skip for already-
	// expired certs (Certbot does the same — the OCSP signer often refuses
	// expired serials) but otherwise run independently of TEST_CERT.
	if !expired && certIsRevoked(cert, conf.Top["chain"]) {
		reasons = append(reasons, "REVOKED")
	}
	var status string
	if len(reasons) > 0 {
		status = "INVALID: " + strings.Join(reasons, ", ")
	} else {
		diff := cert.NotAfter.Sub(now)
		days := int(diff.Hours()) / 24
		switch {
		case days == 1:
			status = "VALID: 1 day"
		case days < 1:
			status = fmt.Sprintf("VALID: %d hour(s)", int(diff.Hours()))
		default:
			status = fmt.Sprintf("VALID: %d days", days)
		}
	}

	return &certInfo{
		Name:     certName,
		Serial:   fmt.Sprintf("%x", cert.SerialNumber),
		KeyType:  keyType,
		SANs:     sans,
		NotAfter: cert.NotAfter.UTC(),
		Status:   status,
		CertPath: conf.Top["fullchain"],
		KeyPath:  keyPath,
	}, nil
}

func readKeyType(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty key path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("empty PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return keyTypeFromKey(key), nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return keyTypeFromKey(key), nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return keyTypeFromKey(key), nil
	}
	return "", fmt.Errorf("unknown key encoding")
}

func keyTypeFromKey(k any) string {
	switch k.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA"
	}
	return "unknown"
}

// isTestCert reports whether the certificate was issued by a staging /
// test-only CA. Certbot's heuristic (cert_manager.is_test_cert) looks for
// "STAGING" or "(STAGING)" in the issuer CN; Let's Encrypt staging issuers
// (Pebble too) follow this pattern.
func isTestCert(cert *x509.Certificate) bool {
	issuer := cert.Issuer.CommonName
	for _, marker := range []string{"STAGING", "(STAGING)", "Pebble", "Fake"} {
		if strings.Contains(issuer, marker) {
			return true
		}
	}
	return false
}

// certIsRevoked queries the cert's OCSP responder using `issuer` from the
// chain PEM. Errors and "unknown" responses are treated as "not revoked" so
// transient OCSP outages don't flag every managed cert as INVALID.
func certIsRevoked(cert *x509.Certificate, chainPath string) bool {
	if len(cert.OCSPServer) == 0 || chainPath == "" {
		return false
	}
	chainBytes, err := os.ReadFile(chainPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(chainBytes)
	if block == nil {
		return false
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return false
	}
	httpReq, err := http.NewRequest(http.MethodPost, cert.OCSPServer[0], bytes.NewReader(req))
	if err != nil {
		return false
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	parsed, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return false
	}
	return parsed.Status == ocsp.Revoked
}
