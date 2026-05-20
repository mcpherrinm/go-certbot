package verbs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeLineage(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	live := filepath.Join(dir, "live", name)
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	renewal := filepath.Join(dir, "renewal", name+".conf")
	if err := os.MkdirAll(filepath.Dir(renewal), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name, "www." + name},
		IPAddresses:  []net.IP{net.ParseIP("203.0.113.1")},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(live, "cert.pem")
	keyPath := filepath.Join(live, "privkey.pem")
	full := filepath.Join(live, "fullchain.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	conf := "cert = " + certPath + "\n" +
		"privkey = " + keyPath + "\n" +
		"chain = " + certPath + "\n" +
		"fullchain = " + full + "\n\n" +
		"[renewalparams]\n" +
		"authenticator = standalone\n"
	if err := os.WriteFile(renewal, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDescribeCertValid(t *testing.T) {
	dir := t.TempDir()
	makeLineage(t, dir, "example.test", time.Now().Add(60*24*time.Hour))
	info, err := describeCert(filepath.Join(dir, "renewal", "example.test.conf"), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "example.test" {
		t.Errorf("name: %q", info.Name)
	}
	if info.Serial != "2a" {
		t.Errorf("serial: %q", info.Serial)
	}
	if info.KeyType != "ECDSA" {
		t.Errorf("key type: %q", info.KeyType)
	}
	if !strings.HasPrefix(info.Status, "VALID:") {
		t.Errorf("status: %q", info.Status)
	}
	if len(info.SANs) != 3 {
		t.Errorf("SANs: %v", info.SANs)
	}
}

func TestDescribeCertExpired(t *testing.T) {
	dir := t.TempDir()
	makeLineage(t, dir, "old.test", time.Now().Add(-24*time.Hour))
	info, err := describeCert(filepath.Join(dir, "renewal", "old.test.conf"), "old.test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != "INVALID: EXPIRED" {
		t.Errorf("status: %q", info.Status)
	}
}

func TestCertInfoMatchesByDomain(t *testing.T) {
	info := certInfo{SANs: []string{"a.test", "b.test"}}
	if !info.matches([]string{"a.test"}) {
		t.Errorf("should match")
	}
	if info.matches([]string{"c.test"}) {
		t.Errorf("should not match")
	}
}
