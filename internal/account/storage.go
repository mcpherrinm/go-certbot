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
	"strings"
	"time"
)

// Meta mirrors certbot._internal.account.Account.Meta. The on-disk timestamp
// is pyrfc3339-style: RFC 3339 truncated to whole seconds, with `Z` suffix.
type Meta struct {
	CreationDT    metaTime `json:"creation_dt"`
	CreationHost  string   `json:"creation_host"`
	RegisterToEFF string   `json:"register_to_eff,omitempty"`
}

// metaTime is time.Time with Certbot-compatible JSON serialization (RFC 3339,
// no fractional seconds, UTC).
type metaTime struct{ time.Time }

func (t metaTime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte(`null`), nil
	}
	s := t.Time.UTC().Truncate(time.Second).Format(time.RFC3339)
	return []byte(`"` + s + `"`), nil
}

func (t *metaTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	// Accept fractional or no-fractional; either way we store UTC.
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, s); err == nil {
			t.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("account: invalid creation_dt %q", s)
}

// Registration is the on-disk shape Certbot writes for regr.json: a minimal
// `{"body": {}, "uri": "..."}` document. The body content is intentionally
// dropped at save time (mirrors certbot._internal.account._update_regr) so the
// file doesn't carry stale contact/status fields after the ACME server is
// canonical.
type Registration struct {
	Body json.RawMessage `json:"body"`
	URI  string          `json:"uri"`
}

// RegistrationBody is the populated body used in memory only; it is never
// written to regr.json (we always write Body=`{}`). On load we accept any
// shape Certbot might have left in the file.
type RegistrationBody struct {
	Contact                []string        `json:"contact,omitempty"`
	Status                 string          `json:"status,omitempty"`
	Agreement              string          `json:"agreement,omitempty"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting,omitempty"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

// Body returns a parsed RegistrationBody from the on-disk JSON, or a zero
// value if the body is `{}`.
func (r *Registration) ParsedBody() RegistrationBody {
	var b RegistrationBody
	if len(r.Body) > 0 {
		_ = json.Unmarshal(r.Body, &b)
	}
	return b
}

// Account is a loaded account: its key, registration resource, and metadata.
// In-memory Contact is the convenience accessor we synthesize from
// Registration.Body when present. URI and Body bytes are what's persisted.
type Account struct {
	ID           string
	Key          crypto.PrivateKey
	Registration Registration
	Meta         Meta

	// Contact is the in-memory list of "mailto:..." entries. Set explicitly
	// when (re)registering or updating account; never written to regr.json.
	Contact []string
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
	// StrictPermissions controls the ownership *verification* (not the mode
	// itself); Certbot always uses 0700 for the accounts dirs and 0400 for
	// private_key.json regardless of this flag.
	StrictPermissions bool
}

func (s *FileStorage) accountDir(id string) string {
	return filepath.Join(s.AccountsDir, id)
}

func (s *FileStorage) regrPath(dir string) string { return filepath.Join(dir, "regr.json") }
func (s *FileStorage) keyPath(dir string) string  { return filepath.Join(dir, "private_key.json") }
func (s *FileStorage) metaPath(dir string) string { return filepath.Join(dir, "meta.json") }

// FindAll returns every account in this storage. Returns an empty slice if the
// accounts directory doesn't exist. When no accounts exist under the current
// server's path but one of the LE_REUSE_SERVERS predecessors has accounts,
// symlink the predecessor's directory in and return its accounts (matches
// certbot._internal.account.AccountFileStorage._find_all_for_server_path).
func (s *FileStorage) FindAll() ([]*Account, error) {
	out, err := s.findAllUnder(s.AccountsDir)
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		return out, nil
	}
	// Fallback: look in the predecessor's accounts dir.
	if prev := reuseFallbackDir(s.AccountsDir); prev != "" {
		prevAccounts, err := s.findAllUnder(prev)
		if err == nil && len(prevAccounts) > 0 {
			if err := symlinkToAccountsDir(prev, s.AccountsDir); err == nil {
				return prevAccounts, nil
			}
		}
	}
	return out, nil
}

func (s *FileStorage) findAllUnder(dir string) ([]*Account, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("account: read accounts dir: %w", err)
	}
	var out []*Account
	for _, e := range entries {
		if !e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		acc, err := s.loadFrom(dir, e.Name())
		if err != nil {
			continue
		}
		out = append(out, acc)
	}
	return out, nil
}

// Load reads a single account by id. If the account isn't under the current
// server's accounts dir, falls back to a LE_REUSE_SERVERS predecessor (e.g.
// `acme-v01...` for an `acme-v02...` lookup) and creates a per-account
// symlink so subsequent calls don't have to walk the chain. Matches
// AccountFileStorage._load_for_server_path (account.py:200-214).
func (s *FileStorage) Load(id string) (*Account, error) {
	if acc, err := s.loadFrom(s.AccountsDir, id); err == nil {
		return acc, nil
	}
	if prev := reuseFallbackDir(s.AccountsDir); prev != "" {
		if acc, err := s.loadFrom(prev, id); err == nil {
			// Link the predecessor's account dir into the current
			// accounts dir so future loads are O(1).
			_ = os.MkdirAll(s.AccountsDir, 0o700)
			link := filepath.Join(s.AccountsDir, id)
			if _, lerr := os.Lstat(link); lerr != nil {
				_ = os.Symlink(filepath.Join(prev, id), link)
			}
			return acc, nil
		}
	}
	// Fall through with the original error.
	return s.loadFrom(s.AccountsDir, id)
}

func (s *FileStorage) loadFrom(base, id string) (*Account, error) {
	dir := filepath.Join(base, id)
	keyBytes, err := os.ReadFile(filepath.Join(dir, "private_key.json"))
	if err != nil {
		return nil, fmt.Errorf("account: read key: %w", err)
	}
	key, err := UnmarshalJWK(keyBytes)
	if err != nil {
		return nil, err
	}
	regrBytes, err := os.ReadFile(filepath.Join(dir, "regr.json"))
	if err != nil {
		return nil, fmt.Errorf("account: read regr: %w", err)
	}
	var regr Registration
	if err := json.Unmarshal(regrBytes, &regr); err != nil {
		return nil, fmt.Errorf("account: parse regr: %w", err)
	}
	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("account: read meta: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("account: parse meta: %w", err)
	}
	body := regr.ParsedBody()
	return &Account{
		ID:           id,
		Key:          key,
		Registration: regr,
		Meta:         meta,
		Contact:      body.Contact,
	}, nil
}

// Save writes an account to disk. Permissions match Certbot exactly:
// accounts/, accounts/<server>/, and accounts/<server>/<id>/ are 0700;
// private_key.json is 0400 and refused if a file already exists at the path
// (mirrors `safe_open(..., O_CREAT|O_EXCL, 0o400)`); regr.json and meta.json
// are 0644.
func (s *FileStorage) Save(a *Account) error {
	const accountDirMode = os.FileMode(0o700)
	const keyMode = os.FileMode(0o400)

	dir := s.accountDir(a.ID)
	if err := os.MkdirAll(dir, accountDirMode); err != nil {
		return fmt.Errorf("account: mkdir: %w", err)
	}

	keyPath := filepath.Join(dir, "private_key.json")
	if _, err := os.Stat(keyPath); err == nil {
		// Certbot's _create uses safe_open with O_CREAT|O_EXCL and lets the
		// error propagate. Mirror that — silently skipping the write here
		// would leave regr.json paired with a *different* key than the
		// caller passed in.
		return fmt.Errorf("account: refusing to overwrite existing key at %s", keyPath)
	}
	keyBytes, err := MarshalJWK(a.Key)
	if err != nil {
		return err
	}
	if err := writeFileExcl(keyPath, keyBytes, keyMode); err != nil {
		return err
	}
	// Minimal regr.json: Certbot writes `{"body": {}, "uri": "..."}` and
	// nothing else (account.py _update_regr).
	regrBytes, err := json.Marshal(Registration{Body: json.RawMessage(`{}`), URI: a.Registration.URI})
	if err != nil {
		return fmt.Errorf("account: marshal regr: %w", err)
	}
	if err := writeFile(filepath.Join(dir, "regr.json"), regrBytes, 0o644); err != nil {
		return err
	}
	metaBytes, err := json.Marshal(a.Meta)
	if err != nil {
		return fmt.Errorf("account: marshal meta: %w", err)
	}
	if err := writeFile(filepath.Join(dir, "meta.json"), metaBytes, 0o644); err != nil {
		return err
	}
	return nil
}

// UpdateMeta rewrites meta.json without touching the key or regr files.
func (s *FileStorage) UpdateMeta(a *Account) error {
	dir := s.accountDir(a.ID)
	metaBytes, err := json.Marshal(a.Meta)
	if err != nil {
		return fmt.Errorf("account: marshal meta: %w", err)
	}
	return writeFile(filepath.Join(dir, "meta.json"), metaBytes, 0o644)
}

// UpdateRegistration rewrites regr.json (used after registration URI changes).
func (s *FileStorage) UpdateRegistration(a *Account) error {
	dir := s.accountDir(a.ID)
	regrBytes, err := json.Marshal(Registration{Body: json.RawMessage(`{}`), URI: a.Registration.URI})
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "regr.json"), regrBytes, 0o644)
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

// writeFileExcl writes path with O_CREAT|O_EXCL — fails if path exists.
func writeFileExcl(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("account: create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("account: write %s: %w", path, err)
	}
	return f.Close()
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

// reuseServers mirrors certbot._internal.constants.LE_REUSE_SERVERS: the
// keys are accounts/<server_path>/ tails for which Certbot will look in the
// matching predecessor when no accounts exist locally. We compare on the tail
// of the accounts dir (the server_path component) so the lookup is portable.
var reuseServers = map[string]string{
	filepath.Join("acme-v02.api.letsencrypt.org", "directory"):         filepath.Join("acme-v01.api.letsencrypt.org", "directory"),
	filepath.Join("acme-staging-v02.api.letsencrypt.org", "directory"): filepath.Join("acme-staging.api.letsencrypt.org", "directory"),
}

// reuseFallbackDir returns the predecessor accounts dir for the given server
// accounts dir, or "" if there isn't one.
func reuseFallbackDir(accountsDir string) string {
	for cur, prev := range reuseServers {
		if strings.HasSuffix(filepath.Clean(accountsDir), string(filepath.Separator)+cur) ||
			filepath.Clean(accountsDir) == cur {
			return strings.TrimSuffix(accountsDir, cur) + prev
		}
	}
	return ""
}

// symlinkToAccountsDir replaces (the empty) accountsDir with a symlink to
// prev. Matches `_symlink_to_accounts_dir`.
func symlinkToAccountsDir(prev, accountsDir string) error {
	// Remove the empty accountsDir (or the symlink if one exists), then link.
	info, err := os.Lstat(accountsDir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(accountsDir)
		} else {
			_ = os.Remove(accountsDir) // os.Remove on empty dir succeeds
		}
	}
	return os.Symlink(prev, accountsDir)
}
