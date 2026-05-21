package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makePEMChain(t *testing.T) (fullchain, chain, privkey []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 90),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// fullchain = leaf + (here, the same self-signed cert again for "issuer")
	return append(certPEM, certPEM...), certPEM, keyPEM
}

func TestWriteCreatesLineage(t *testing.T) {
	dir := t.TempDir()
	full, chain, key := makePEMChain(t)
	lineage, err := Write(dir, "example.test", full, chain, key, WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if lineage.Version != 1 {
		t.Errorf("expected version 1, got %d", lineage.Version)
	}
	for _, p := range []string{lineage.Archive.Cert, lineage.Archive.Privkey, lineage.Archive.Chain, lineage.Archive.Fullchain} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("archive file missing: %s: %v", p, err)
		}
	}
	for _, p := range []string{lineage.Live.Cert, lineage.Live.Privkey, lineage.Live.Chain, lineage.Live.Fullchain} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Errorf("live file missing: %s: %v", p, err)
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("live %s is not a symlink", p)
		}
	}
	st, err := os.Stat(lineage.Archive.Privkey)
	if err == nil && st.Mode().Perm() != 0o600 {
		t.Errorf("privkey perm: got %o want 0600", st.Mode().Perm())
	}
}

func TestWriteIncrementsVersion(t *testing.T) {
	dir := t.TempDir()
	full, chain, key := makePEMChain(t)
	if _, err := Write(dir, "x", full, chain, key, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	l2, err := Write(dir, "x", full, chain, key, WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if l2.Version != 2 {
		t.Errorf("expected version 2, got %d", l2.Version)
	}
	// live symlinks should now point at the new archive.
	target, err := os.Readlink(filepath.Join(dir, "live", "x", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != "cert2.pem" {
		t.Errorf("live link points at %q, expected cert2.pem", target)
	}
}

// TestWritePropagatesPrivkeyMode mirrors certbot integration test
// test_renew_files_propagate_permissions: when a user chmods their
// privkey to add a group/other read bit, the next renewal must keep
// that bit.
func TestWritePropagatesPrivkeyMode(t *testing.T) {
	if testing.Short() {
		t.Skip("filesystem perms test")
	}
	dir := t.TempDir()
	full, chain, key := makePEMChain(t)
	if _, err := Write(dir, "x", full, chain, key, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	priv1 := filepath.Join(dir, "archive", "x", "privkey1.pem")
	// User chmods their privkey to add group-read + other-read.
	if err := os.Chmod(priv1, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, "x", full, chain, key, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	priv2 := filepath.Join(dir, "archive", "x", "privkey2.pem")
	st, err := os.Stat(priv2)
	if err != nil {
		t.Fatal(err)
	}
	// 0o644 has bits 0o044 in the certbotMask (S_IRGRP|S_IROTH).
	// Result: 0o600 | 0o044 = 0o644.
	if got := st.Mode().Perm(); got != 0o644 {
		t.Errorf("renewed privkey perm: got %o want 0644 (propagated from prior)", got)
	}
}
