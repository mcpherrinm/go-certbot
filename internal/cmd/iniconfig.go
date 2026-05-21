package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"gopkg.in/ini.v1"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// loadIni reads a Certbot cli.ini file and applies its top-level keys onto
// the FlagSet's defaults. Returns nil if the file doesn't exist.
//
// Certbot's cli.ini is INI with a single (default) section. Keys use either
// dashes or underscores; we normalize underscores to dashes to match the
// pflag flag names.
func loadIni(path string, fs *pflag.FlagSet, c *config.Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cli.ini: read %s: %w", path, err)
	}
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Loose:                    false,
		Insensitive:              false,
		IgnoreInlineComment:      false,
		AllowBooleanKeys:         true,
		SpaceBeforeInlineComment: true,
		KeyValueDelimiters:       "=",
	}, b)
	if err != nil {
		return fmt.Errorf("cli.ini: parse %s: %w", path, err)
	}
	section := cfg.Section("")
	for _, k := range section.Keys() {
		name := strings.ReplaceAll(k.Name(), "_", "-")
		f := fs.Lookup(name)
		if f == nil {
			// Unknown key — match Certbot's behavior and skip silently. (We
			// don't error so users with cli.ini files containing flags from a
			// later phase aren't blocked.)
			continue
		}
		if err := f.Value.Set(k.Value()); err != nil {
			return fmt.Errorf("cli.ini: %s=%q: %w", name, k.Value(), err)
		}
		c.MarkSet(name, config.SourceConfigFile)
	}
	return nil
}
