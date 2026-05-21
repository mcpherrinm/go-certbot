package account

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestJWKRoundTripRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := MarshalJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	g := got.(*rsa.PrivateKey)
	if !reflect.DeepEqual(g.PublicKey, key.PublicKey) {
		t.Errorf("public key mismatch after round-trip")
	}
	if g.D.Cmp(key.D) != 0 {
		t.Errorf("D mismatch")
	}
}

func TestJWKRoundTripECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := MarshalJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	g := got.(*ecdsa.PrivateKey)
	if g.X.Cmp(key.X) != 0 || g.Y.Cmp(key.Y) != 0 {
		t.Errorf("public point mismatch")
	}
	if g.D.Cmp(key.D) != 0 {
		t.Errorf("D mismatch")
	}
}

func TestSPKIPEMFormat(t *testing.T) {
	// Sanity: lines of body are ≤ 64 chars and end with newline.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := SubjectPublicKeyInfoPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s := string(pem)
	if s[:len("-----BEGIN PUBLIC KEY-----")] != "-----BEGIN PUBLIC KEY-----" {
		t.Errorf("missing header")
	}
	if !endsWith(s, "-----END PUBLIC KEY-----\n") {
		t.Errorf("missing trailing footer+newline; got %q", s)
	}
}

func TestComputeIDDeterministic(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ComputeID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("ComputeID not deterministic: %q vs %q", a, b)
	}
	if len(a) != 32 {
		t.Errorf("expected 32-char hex MD5, got %d", len(a))
	}
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
