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
//	  [[webroot_map]]
//	  example.com = /var/www/example
//	  www.example.com = /var/www/example
//
// Values are stringly-typed on disk; callers convert using the Bool/Int/List
// helpers, which mirror certbot._internal.renewal's STR_/INT_/BOOL_/list type
// tables. The parser preserves all sections (including unknown ones, comments,
// blank lines) so round-tripping a Certbot conf is non-destructive.
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
	// Top-level keys (cert/privkey/chain/fullchain/renew_before_expiry/etc.).
	Top map[string]string
	// [renewalparams] section.
	RenewalParams map[string]string
	// Sections holds top-level [section]... blocks other than [renewalparams].
	// Each entry is `name → key → value`. Preserved through round-trips.
	Sections map[string]map[string]string
	// Nested holds [[nested]] subsections within [renewalparams]; the most
	// important being webroot_map (renewalparams.py:163).
	Nested map[string]map[string]string

	// Insertion-order trackers.
	topOrder      []string
	paramsOrder   []string
	sectionsOrder []string
	nestedOrder   []string
	keyOrder      map[string][]string // section name → keys in order
}

func newFile() *File {
	return &File{
		Top:           map[string]string{},
		RenewalParams: map[string]string{},
		Sections:      map[string]map[string]string{},
		Nested:        map[string]map[string]string{},
		keyOrder:      map[string][]string{},
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
		p = strings.TrimSpace(unquote(p))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out, true
}

// NestedMap returns the named nested section under [renewalparams] (e.g.
// "webroot_map"), or nil if absent.
func (f *File) NestedMap(name string) map[string]string {
	return f.Nested[name]
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
	// section is the active scope. "" means top-level. "renewalparams" is
	// the conventional named section. ">renewalparams>name" means an active
	// nested [[name]] inside renewalparams.
	section := ""
	nested := ""
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Nested-section header: [[name]] only valid inside [renewalparams].
		if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
			nested = strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			if _, ok := f.Nested[nested]; !ok {
				f.Nested[nested] = map[string]string{}
				f.nestedOrder = append(f.nestedOrder, nested)
			}
			continue
		}
		// Top-level section header: [name].
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			nested = ""
			if section != "renewalparams" {
				if _, ok := f.Sections[section]; !ok {
					f.Sections[section] = map[string]string{}
					f.sectionsOrder = append(f.sectionsOrder, section)
				}
			}
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 0 {
			return nil, fmt.Errorf("renewalconf: malformed line: %q", line)
		}
		key := strings.TrimSpace(trimmed[:idx])
		value := strings.TrimSpace(trimmed[idx+1:])
		switch {
		case nested != "" && section == "renewalparams":
			if _, ok := f.Nested[nested][key]; !ok {
				f.keyOrder["nested:"+nested] = append(f.keyOrder["nested:"+nested], key)
			}
			f.Nested[nested][key] = value
		case section == "":
			if _, ok := f.Top[key]; !ok {
				f.topOrder = append(f.topOrder, key)
			}
			f.Top[key] = value
		case section == "renewalparams":
			if _, ok := f.RenewalParams[key]; !ok {
				f.paramsOrder = append(f.paramsOrder, key)
			}
			f.RenewalParams[key] = value
		default:
			if _, ok := f.Sections[section][key]; !ok {
				f.keyOrder["section:"+section] = append(f.keyOrder["section:"+section], key)
			}
			f.Sections[section][key] = value
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
	emitKV(&sb, f.topOrder, f.Top)

	sb.WriteString("[renewalparams]\n")
	emitKV(&sb, f.paramsOrder, f.RenewalParams)

	// Nested sections inside [renewalparams]. configobj writes nested keys
	// flush-left when the parent had no indent_type recorded; Certbot's
	// freshly-emitted confs follow that convention.
	for _, name := range f.nestedOrder {
		fmt.Fprintf(&sb, "[[%s]]\n", name)
		emitKV(&sb, f.keyOrder["nested:"+name], f.Nested[name])
	}
	// Other top-level sections (preserved verbatim from input).
	for _, name := range f.sectionsOrder {
		fmt.Fprintf(&sb, "[%s]\n", name)
		emitKV(&sb, f.keyOrder["section:"+name], f.Sections[name])
	}
	return writeFile(path, []byte(sb.String()), 0o644)
}

func emitKV(sb *strings.Builder, order []string, m map[string]string) {
	written := map[string]bool{}
	for _, k := range order {
		fmt.Fprintf(sb, "%s = %s\n", k, formatValue(m[k]))
		written[k] = true
	}
	for k, v := range m {
		if written[k] {
			continue
		}
		fmt.Fprintf(sb, "%s = %s\n", k, formatValue(v))
	}
}

// formatValue emits a value the way configobj would. configobj's writer
// behaves per the list_values=True default:
//
//   - A value parsed as a list (any unquoted string containing `,`) is written
//     bare, e.g. `domains = a.com, b.com`, with a trailing comma for the
//     single-element case (`only.com,`).
//   - A scalar value preserved from input as a quoted form keeps its quotes.
//   - A scalar value containing `,`, `#`, `"` or surrounding whitespace is
//     double-quoted on write so configobj parses it back as a scalar.
//   - `=` is allowed bare; configobj splits on the first `=` and never quotes
//     for it.
func formatValue(v string) string {
	if v == "" {
		return v
	}
	// Already-quoted scalar (round-tripped through input): keep as-is.
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return v
		}
	}
	// List form: configobj treats any unquoted comma-bearing value as a list.
	if strings.Contains(v, ",") {
		parts := strings.Split(v, ",")
		items := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			items = append(items, p)
		}
		if len(items) == 1 {
			// Single-element list keeps the trailing-comma marker so the
			// reader still sees a list on the next round-trip.
			return items[0] + ","
		}
		return strings.Join(items, ", ")
	}
	// Scalar without commas: quote only if configobj would otherwise mis-parse.
	needs := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '"' || c == '#' || c == '\n' {
			needs = true
			break
		}
	}
	if !needs && v == strings.TrimSpace(v) {
		return v
	}
	if !strings.Contains(v, `"`) {
		return `"` + v + `"`
	}
	return `'` + v + `'`
}

// unquote strips surrounding double or single quotes from a value.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
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

// DeleteParam removes a key from [renewalparams]. Used by reconfigure to
// clear a hook when the user passed e.g. `--deploy-hook ""`.
func (f *File) DeleteParam(key string) {
	if _, ok := f.RenewalParams[key]; !ok {
		return
	}
	delete(f.RenewalParams, key)
	out := f.paramsOrder[:0]
	for _, k := range f.paramsOrder {
		if k != key {
			out = append(out, k)
		}
	}
	f.paramsOrder = out
}

// SetNested sets a key inside a [[nested]] section of [renewalparams].
// Creates the section if it doesn't exist. Used for `webroot_map`.
func (f *File) SetNested(name, key, value string) {
	if _, ok := f.Nested[name]; !ok {
		f.Nested[name] = map[string]string{}
		f.nestedOrder = append(f.nestedOrder, name)
	}
	if _, ok := f.Nested[name][key]; !ok {
		f.keyOrder["nested:"+name] = append(f.keyOrder["nested:"+name], key)
	}
	f.Nested[name][key] = value
}

// SetSection sets a key inside a top-level [section] block. Round-trip use
// for [acme_renewal_info] etc. Creates the section if needed.
func (f *File) SetSection(name, key, value string) {
	if _, ok := f.Sections[name]; !ok {
		f.Sections[name] = map[string]string{}
		f.sectionsOrder = append(f.sectionsOrder, name)
	}
	if _, ok := f.Sections[name][key]; !ok {
		f.keyOrder["section:"+name] = append(f.keyOrder["section:"+name], key)
	}
	f.Sections[name][key] = value
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
