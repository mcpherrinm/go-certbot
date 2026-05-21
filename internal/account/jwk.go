// Package account implements Certbot-compatible on-disk account storage:
//
//	<config_dir>/accounts/<server_path>/<account_id>/
//	    private_key.json   josepy-compatible JWK (RSA or EC P-256)
//	    regr.json          josepy RegistrationResource JSON
//	    meta.json          {"creation_dt","creation_host","register_to_eff"}
//
// The account_id is the lowercase hex MD5 of the SubjectPublicKeyInfo PEM,
// matching certbot._internal.account.Account.__init__.
package account

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// rawJWK is the on-disk shape. josepy emits keys as JWK per RFC 7517/7518 with
// base64url-encoded big-endian integers. Only the fields Certbot writes are
// listed.
type rawJWK struct {
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	Dp  string `json:"dp,omitempty"`
	Dq  string `json:"dq,omitempty"`
	Qi  string `json:"qi,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// MarshalJWK serializes an RSA or ECDSA private key into a josepy-compatible
// JWK JSON blob. Field order matches josepy's
// `to_partial_json` exactly so byte-for-byte interop with Certbot is
// preserved:
//
//	RSA: n, e, d, p, q, dp, dq, qi, kty
//	EC:  d, x, y, crv, kty
//
// `kty` is always appended *last* (json_util.py:539-550). Separators are
// Python's defaults `", "` and `": "` (with spaces), matching
// json.dumps's default Encoder.
func MarshalJWK(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return marshalPythonJSON([]jsonField{
			{"n", b64uInt(k.N)},
			{"e", b64uInt(big.NewInt(int64(k.E)))},
			{"d", b64uInt(k.D)},
			{"p", b64uInt(k.Primes[0])},
			{"q", b64uInt(k.Primes[1])},
			{"dp", b64uInt(k.Precomputed.Dp)},
			{"dq", b64uInt(k.Precomputed.Dq)},
			{"qi", b64uInt(k.Precomputed.Qinv)},
			{"kty", "RSA"},
		}), nil
	case *ecdsa.PrivateKey:
		crv, err := curveName(k.Curve)
		if err != nil {
			return nil, err
		}
		size := ecCoordinateSize(k.Curve)
		return marshalPythonJSON([]jsonField{
			{"d", b64uIntPadded(k.D, size)},
			{"x", b64uIntPadded(k.X, size)},
			{"y", b64uIntPadded(k.Y, size)},
			{"crv", crv},
			{"kty", "EC"},
		}), nil
	default:
		return nil, fmt.Errorf("account: unsupported private key type %T", key)
	}
}

// jsonField is a (key, value) pair for marshalPythonJSON. Value may be a
// string, json.RawMessage, or any of the JSON primitives encoding/json
// understands; encoding/json handles the value side.
type jsonField struct {
	key   string
	value any
}

// marshalPythonJSON emits {"k1": v1, "k2": v2, ...} with Python-style
// separators `", "` and `": "`. Used for every JSON we write that needs to
// be byte-equivalent with Certbot output.
func marshalPythonJSON(fields []jsonField) []byte {
	var buf []byte
	buf = append(buf, '{')
	for i, f := range fields {
		if i > 0 {
			buf = append(buf, ',', ' ')
		}
		kb, _ := json.Marshal(f.key)
		buf = append(buf, kb...)
		buf = append(buf, ':', ' ')
		vb, _ := json.Marshal(f.value)
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return buf
}

// JWKThumbprintCanonical returns the RFC 7638 canonical JSON of the JWK's
// REQUIRED public fields (sorted lex, no whitespace), suitable for hashing
// with SHA-256 to produce the JWK thumbprint. Matches josepy's
// JWK.thumbprint (interfaces.py:180-187):
//
//	RSA: {"e":"...","kty":"RSA","n":"..."}
//	EC:  {"crv":"P-256","kty":"EC","x":"...","y":"..."}
func JWKThumbprintCanonical(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return canonicalJSON([]jsonField{
			{"e", b64uInt(big.NewInt(int64(k.E)))},
			{"kty", "RSA"},
			{"n", b64uInt(k.N)},
		}), nil
	case *ecdsa.PrivateKey:
		crv, err := curveName(k.Curve)
		if err != nil {
			return nil, err
		}
		size := ecCoordinateSize(k.Curve)
		return canonicalJSON([]jsonField{
			{"crv", crv},
			{"kty", "EC"},
			{"x", b64uIntPadded(k.X, size)},
			{"y", b64uIntPadded(k.Y, size)},
		}), nil
	}
	return nil, fmt.Errorf("account: unsupported key type %T", key)
}

// canonicalJSON emits {"k1":v1,"k2":v2,...} with no whitespace. Used by
// JWKThumbprintCanonical and other places needing RFC 8785-style output.
func canonicalJSON(fields []jsonField) []byte {
	var buf []byte
	buf = append(buf, '{')
	for i, f := range fields {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, _ := json.Marshal(f.key)
		buf = append(buf, kb...)
		buf = append(buf, ':')
		vb, _ := json.Marshal(f.value)
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return buf
}

// UnmarshalJWK parses a josepy JWK blob into an *rsa.PrivateKey or
// *ecdsa.PrivateKey.
func UnmarshalJWK(b []byte) (crypto.PrivateKey, error) {
	var jwk rawJWK
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, fmt.Errorf("account: parse JWK: %w", err)
	}
	switch jwk.Kty {
	case "RSA":
		n, err := b64uToInt(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("account: jwk n: %w", err)
		}
		e, err := b64uToInt(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("account: jwk e: %w", err)
		}
		d, err := b64uToInt(jwk.D)
		if err != nil {
			return nil, fmt.Errorf("account: jwk d: %w", err)
		}
		if !e.IsInt64() || e.Int64() > (1<<31-1) {
			return nil, errors.New("account: jwk e too large")
		}
		k := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
			D:         d,
		}
		if jwk.P != "" && jwk.Q != "" {
			p, err := b64uToInt(jwk.P)
			if err != nil {
				return nil, fmt.Errorf("account: jwk p: %w", err)
			}
			q, err := b64uToInt(jwk.Q)
			if err != nil {
				return nil, fmt.Errorf("account: jwk q: %w", err)
			}
			k.Primes = []*big.Int{p, q}
		}
		k.Precompute()
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("account: jwk RSA invalid: %w", err)
		}
		return k, nil
	case "EC":
		curve, err := curveByName(jwk.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64uToInt(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("account: jwk x: %w", err)
		}
		y, err := b64uToInt(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("account: jwk y: %w", err)
		}
		d, err := b64uToInt(jwk.D)
		if err != nil {
			return nil, fmt.Errorf("account: jwk d: %w", err)
		}
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         d,
		}, nil
	default:
		return nil, fmt.Errorf("account: unsupported kty %q", jwk.Kty)
	}
}

// PublicKey returns the public half of an RSA or ECDSA private key.
func PublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("account: unsupported private key type %T", priv)
	}
}

// SubjectPublicKeyInfoPEM returns the PKIX/SPKI PEM-encoded public key,
// matching what cryptography.hazmat...public_bytes(PEM, SubjectPublicKeyInfo)
// emits in Python.
func SubjectPublicKeyInfoPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("account: marshal SPKI: %w", err)
	}
	header := "-----BEGIN PUBLIC KEY-----\n"
	footer := "-----END PUBLIC KEY-----\n"
	encoded := base64.StdEncoding.EncodeToString(der)
	var body []byte
	for i := 0; i < len(encoded); i += 64 {
		end := i + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		body = append(body, encoded[i:end]...)
		body = append(body, '\n')
	}
	out := make([]byte, 0, len(header)+len(body)+len(footer))
	out = append(out, header...)
	out = append(out, body...)
	out = append(out, footer...)
	return out, nil
}

// ParsePrivateKeyPEM accepts a PEM-encoded RSA or EC private key and returns
// it in a form usable as a crypto.Signer. Used by revoke --key-path to do
// cert-key revocation (RFC 8555 §7.6).
func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("account: not a PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	}
	return nil, fmt.Errorf("account: unsupported PEM block %q", block.Type)
}

func b64uInt(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64uIntPadded encodes n with leading-zero padding to exactly `size` bytes
// (or one extra leading byte if n is larger than expected). Used for EC
// scalars where josepy enforces a fixed length per curve.
func b64uIntPadded(n *big.Int, size int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) < size {
		pad := make([]byte, size-len(b))
		b = append(pad, b...)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ecCoordinateSize returns the field-element byte length for a curve, used to
// pad x/y/d in EC JWKs to a fixed length matching josepy.
func ecCoordinateSize(c elliptic.Curve) int {
	bits := c.Params().BitSize
	return (bits + 7) / 8
}

func b64uToInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func curveName(c elliptic.Curve) (string, error) {
	switch c {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	}
	return "", fmt.Errorf("account: unsupported EC curve %v", c.Params().Name)
}

func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("account: unknown EC curve %q", name)
}
