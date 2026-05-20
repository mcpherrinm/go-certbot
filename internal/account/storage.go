package account

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Meta mirrors certbot._internal.account.Account.Meta.
type Meta struct {
	CreationDT    time.Time `json:"creation_dt"`
	CreationHost  string    `json:"creation_host"`
	RegisterToEFF string    `json:"register_to_eff,omitempty"`
}

// Registration mirrors josepy's serialization of acme.messages.RegistrationResource.
// Lego's registration.Resource has the same fields under different names; the
// canonical disk shape is Certbot's.
type Registration struct {
	Body            RegistrationBody `json:"body"`
	URI             string           `json:"uri"`
	TermsOfService  string           `json:"terms_of_service,omitempty"`
	NewAuthzrURI    *string          `json:"new_authzr_uri"`
}

// RegistrationBody is the inner "body" object.
type RegistrationBody struct {
	Contact []string `json:"contact,omitempty"`
	Status  string   `json:"status,omitempty"`
	Agreement string `json:"agreement,omitempty"`
	OnlyReturnExisting bool `json:"only_return_existing,omitempty"`
	TermsOfServiceAgreed bool `json:"terms_of_service_agreed,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"external_account_binding,omitempty"`
}

// Account is a loaded account: its key, registration resource, and metadata.
type Account struct {
	ID           string
	Key          crypto.PrivateKey
	Registration Registration
	Meta         Meta
}

// PublicKey returns the public half of the account key.
func (a *Account) PublicKey() crypto.PublicKey {
	pub, _ := PublicKey(a.Key)
	return pub
}

// FileStorage implements Certbot's accounts/<server_path>/<id>/ layout.
type FileStorage struct {
	// AccountsDir is the absolute path to accounts/<server_path>/.
	AccountsDir string
	// StrictPermissions, when true, enforces 0700 on the accounts dir and
	// 0600 on private_key.json. The defaults already use those.
	StrictPermissions bool
}

func (s *FileStorage) accountDir(id string) string {
	return filepath.Join(s.AccountsDir, id)
}

func (s *FileStorage) regrPath(dir string) string       { return filepath.Join(dir, "regr.json") }
func (s *FileStorage) keyPath(dir string) string        { return filepath.Join(dir, "private_key.json") }
func (s *FileStorage) metaPath(dir string) string       { return filepath.Join(dir, "meta.json") }

// FindAll returns every account in this storage. Returns an empty slice if the
// accounts directory doesn't exist.
func (s *FileStorage) FindAll() ([]*Account, error) {
	entries, err := os.ReadDir(s.AccountsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("account: read accounts dir: %w", err)
	}
	var out []*Account
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		acc, err := s.Load(e.Name())
		if err != nil {
			// Match Certbot: skip unreadable accounts rather than abort.
			continue
		}
		out = append(out, acc)
	}
	return out, nil
}

// Load reads a single account by id.
func (s *FileStorage) Load(id string) (*Account, error) {
	dir := s.accountDir(id)
	keyBytes, err := os.ReadFile(s.keyPath(dir))
	if err != nil {
		return nil, fmt.Errorf("account: read key: %w", err)
	}
	key, err := UnmarshalJWK(keyBytes)
	if err != nil {
		return nil, err
	}
	regrBytes, err := os.ReadFile(s.regrPath(dir))
	if err != nil {
		return nil, fmt.Errorf("account: read regr: %w", err)
	}
	var regr Registration
	if err := json.Unmarshal(regrBytes, &regr); err != nil {
		return nil, fmt.Errorf("account: parse regr: %w", err)
	}
	metaBytes, err := os.ReadFile(s.metaPath(dir))
	if err != nil {
		return nil, fmt.Errorf("account: read meta: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("account: parse meta: %w", err)
	}
	return &Account{ID: id, Key: key, Registration: regr, Meta: meta}, nil
}

// Save writes an account to disk, creating parent directories as needed.
func (s *FileStorage) Save(a *Account) error {
	dirMode := os.FileMode(0o755)
	keyMode := os.FileMode(0o600)
	if s.StrictPermissions {
		dirMode = 0o700
	}
	dir := s.accountDir(a.ID)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("account: mkdir: %w", err)
	}

	keyBytes, err := MarshalJWK(a.Key)
	if err != nil {
		return err
	}
	if err := writeFile(s.keyPath(dir), keyBytes, keyMode); err != nil {
		return err
	}
	regrBytes, err := json.Marshal(a.Registration)
	if err != nil {
		return fmt.Errorf("account: marshal regr: %w", err)
	}
	if err := writeFile(s.regrPath(dir), regrBytes, 0o644); err != nil {
		return err
	}
	metaBytes, err := json.Marshal(a.Meta)
	if err != nil {
		return fmt.Errorf("account: marshal meta: %w", err)
	}
	if err := writeFile(s.metaPath(dir), metaBytes, 0o644); err != nil {
		return err
	}
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("account: create temp: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("account: write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("account: chmod %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("account: close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("account: rename to %s: %w", path, err)
	}
	return nil
}

// NewKey generates a fresh account key. keyType is "rsa" or "ecdsa"; for RSA
// rsaSize is the modulus size (Certbot default 2048).
func NewKey(keyType string, rsaSize int) (crypto.PrivateKey, error) {
	switch keyType {
	case "", "rsa":
		size := rsaSize
		if size == 0 {
			size = 2048
		}
		return rsa.GenerateKey(rand.Reader, size)
	case "ecdsa", "ec":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("account: unknown key type %q", keyType)
}
