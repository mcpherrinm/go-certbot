package account

import (
	"crypto"
	"crypto/md5"
	"encoding/hex"
)

// ComputeID derives the account id Certbot would assign to this account: the
// lowercase hex MD5 of the SubjectPublicKeyInfo PEM. See
// certbot._internal.account.Account.__init__.
func ComputeID(pub crypto.PublicKey) (string, error) {
	pem, err := SubjectPublicKeyInfoPEM(pub)
	if err != nil {
		return "", err
	}
	sum := md5.Sum(pem) //nolint:gosec // not security; chosen for Certbot compat
	return hex.EncodeToString(sum[:]), nil
}
