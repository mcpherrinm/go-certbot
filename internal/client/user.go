package client

import (
	"crypto"

	"github.com/go-acme/lego/v5/acme"

	"github.com/letsencrypt/go-certbot/internal/account"
)

// legoUser adapts an internal/account.Account to lego's registration.User
// interface.
type legoUser struct {
	email string
	key   crypto.Signer
	reg   *acme.ExtendedAccount
}

func userFromAccount(a *account.Account) *legoUser {
	email := ""
	if len(a.Contact) > 0 {
		// Contact entries are "mailto:foo@bar"; lego wants the bare email.
		first := a.Contact[0]
		if len(first) > 7 && first[:7] == "mailto:" {
			email = first[7:]
		} else {
			email = first
		}
	}
	signer, _ := a.Key.(crypto.Signer)
	u := &legoUser{email: email, key: signer}
	if a.Registration.URI != "" {
		u.reg = &acme.ExtendedAccount{Location: a.Registration.URI}
	}
	return u
}

func (u *legoUser) GetEmail() string {
	return u.email
}

func (u *legoUser) GetRegistration() *acme.ExtendedAccount {
	return u.reg
}

func (u *legoUser) GetPrivateKey() crypto.Signer {
	return u.key
}
