// Package renewalconf reads and writes Certbot's renewal/<certname>.conf
// files. The format is a configobj-compatible INI:
//
//	cert = .../live/<name>/cert.pem
//	privkey = .../live/<name>/privkey.pem
//	chain = .../live/<name>/chain.pem
//	fullchain = .../live/<name>/fullchain.pem
//	renew_before_expiry = 30 days
//
//	[renewalparams]
//	authenticator = standalone
//	server = https://acme-v02.api.letsencrypt.org/directory
//	domains = example.com,
//	key_type = ecdsa
//	...
//
// Values are stringly-typed on disk; callers convert using the Bool/Int/List
// helpers, which mirror certbot._internal.renewal's STR_/INT_/BOOL_/list type
// tables.
package renewalconf

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// File is a parsed renewal .conf.
type File struct {
	// Top-level keys (cert/privkey/chain/fullchain/renew_before_expiry/ari_retry_after).
	Top map[string]string
	// [renewalparams] section.
	RenewalParams map[string]string
	// Order keys were seen in (for deterministic write-back).
	topOrder    []string
	paramsOrder []string
}

func newFile() *File {
	return &File{
		Top:           map[string]string{},
		RenewalParams: map[string]string{},
	}
}

// Bool returns the named renewalparam as a bool. Returns (false, false) if
// absent. Recognized truthy/falsy values match Certbot's configobj behavior:
// case-insensitive true/false/yes/no/on/off/1/0.
func (f *File) Bool(name string) (val, present bool) {
	v, ok := f.RenewalParams[name]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, true
}

// Int returns the named renewalparam as an int.
func (f *File) Int(name string) (int, bool, error) {
	v, ok := f.RenewalParams[name]
	if !ok {
		return 0, false, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, true, fmt.Errorf("renewalconf: %s=%q is not an int: %w", name, v, err)
	}
	return n, true, nil
}

// List returns the named renewalparam as a list of strings. configobj treats
// any value containing a comma as a list; trailing commas produce
// single-element lists. Whitespace around items is stripped.
func (f *File) List(name string) ([]string, bool) {
	v, ok := f.RenewalParams[name]
	if !ok {
		return nil, false
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out, true
}

// Load parses a single renewal config file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("renewalconf: read %s: %w", path, err)
	}
	return parse(b)
}

func parse(b []byte) (*File, error) {
	f := newFile()
	section := "" // "" = top-level, "renewalparams" = [renewalparams]
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
			// Nested section (e.g. [[webroot_map]]). Not Phase 1 — skip until next ^[.
			section = trimmed[2 : len(trimmed)-2]
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed[1 : len(trimmed)-1]
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 0 {
			return nil, fmt.Errorf("renewalconf: malformed line: %q", line)
		}
		key := strings.TrimSpace(trimmed[:idx])
		value := strings.TrimSpace(trimmed[idx+1:])
		switch section {
		case "":
			if _, exists := f.Top[key]; !exists {
				f.topOrder = append(f.topOrder, key)
			}
			f.Top[key] = value
		case "renewalparams":
			if _, exists := f.RenewalParams[key]; !exists {
				f.paramsOrder = append(f.paramsOrder, key)
			}
			f.RenewalParams[key] = value
		default:
			// nested-section keys — ignored for Phase 1
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("renewalconf: scan: %w", err)
	}
	return f, nil
}

// Save writes the renewal config to path atomically.
func (f *File) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("renewalconf: mkdir: %w", err)
	}
	var sb strings.Builder
	written := map[string]bool{}
	for _, k := range f.topOrder {
		fmt.Fprintf(&sb, "%s = %s\n", k, f.Top[k])
		written[k] = true
	}
	for k, v := range f.Top {
		if written[k] {
			continue
		}
		fmt.Fprintf(&sb, "%s = %s\n", k, v)
	}
	sb.WriteString("\n# Options used in the renewal process\n[renewalparams]\n")
	written = map[string]bool{}
	for _, k := range f.paramsOrder {
		fmt.Fprintf(&sb, "%s = %s\n", k, f.RenewalParams[k])
		written[k] = true
	}
	for k, v := range f.RenewalParams {
		if written[k] {
			continue
		}
		fmt.Fprintf(&sb, "%s = %s\n", k, v)
	}
	return writeFile(path, []byte(sb.String()), 0o644)
}

// SetTop sets a top-level key, recording insertion order if new.
func (f *File) SetTop(key, value string) {
	if _, ok := f.Top[key]; !ok {
		f.topOrder = append(f.topOrder, key)
	}
	f.Top[key] = value
}

// SetParam sets a [renewalparams] key, recording insertion order if new.
func (f *File) SetParam(key, value string) {
	if _, ok := f.RenewalParams[key]; !ok {
		f.paramsOrder = append(f.paramsOrder, key)
	}
	f.RenewalParams[key] = value
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("renewalconf: create temp: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("renewalconf: write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("renewalconf: chmod %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("renewalconf: close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("renewalconf: rename to %s: %w", path, err)
	}
	return nil
}

// New returns an empty renewal config.
func New() *File { return newFile() }

// ErrNotFound is returned when a renewal config file doesn't exist.
var ErrNotFound = errors.New("renewalconf: file not found")
