package apache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/plugins/apache/parser"
)

// parsedFile is one Apache configuration file in the Include tree.
type parsedFile struct {
	Path string
	AST  *parser.Config
}

// loadAll parses the given root file and recursively follows Include /
// IncludeOptional directives (globs supported). Returns one parsedFile per
// discovered file. Cycles are short-circuited.
func loadAll(rootPath string) ([]*parsedFile, error) {
	visited := map[string]bool{}
	var out []*parsedFile
	if err := loadInto(rootPath, visited, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadInto(path string, visited map[string]bool, out *[]*parsedFile) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	// Dedupe by symlink-resolved real path so a file reached through
	// both sites-available/foo.conf AND sites-enabled/foo.conf (which
	// is a symlink to the former) isn't parsed twice. Without this,
	// the second parse + writeAllFiles loop would clobber the first's
	// edits — and `applySSLDirectives` would run twice per vhost.
	// Mirrors certbot configurator.py:1076-1100 (`filesystem.realpath`).
	real := abs
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		real = r
	}
	if visited[real] {
		return nil
	}
	visited[real] = true
	b, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("apache: read %s: %w", abs, err)
	}
	cfg, err := parser.Parse(string(b))
	if err != nil {
		return fmt.Errorf("apache: parse %s: %w", abs, err)
	}
	// Track the user-facing path (the symlink they configured) on the
	// parsedFile so writeAllFiles writes through it. We dedupe ONCE
	// per real file, so subsequent writes from the same source path
	// remain correct.
	*out = append(*out, &parsedFile{Path: abs, AST: cfg})
	return walkIncludes(filepath.Dir(abs), cfg.Nodes, visited, out)
}

func walkIncludes(base string, nodes []parser.Node, visited map[string]bool, out *[]*parsedFile) error {
	for _, n := range nodes {
		switch nn := n.(type) {
		case *parser.Directive:
			if strings.EqualFold(nn.Name, "Include") || strings.EqualFold(nn.Name, "IncludeOptional") {
				if len(nn.Args) == 0 {
					continue
				}
				glob := strings.Trim(nn.Args[0], `"`)
				if !filepath.IsAbs(glob) {
					glob = filepath.Join(base, glob)
				}
				matches, err := filepath.Glob(glob)
				if err != nil {
					return fmt.Errorf("apache: include glob %s: %w", glob, err)
				}
				for _, m := range matches {
					info, err := os.Stat(m)
					if err != nil {
						continue
					}
					if info.IsDir() {
						// Apache lets you include a directory; expand to *.conf in it.
						subs, err := filepath.Glob(filepath.Join(m, "*.conf"))
						if err == nil {
							for _, s := range subs {
								if err := loadInto(s, visited, out); err != nil {
									return err
								}
							}
						}
						continue
					}
					if err := loadInto(m, visited, out); err != nil {
						return err
					}
				}
			}
		case *parser.Section:
			if err := walkIncludes(base, nn.Body, visited, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// findMatchingVHostsAcrossFiles iterates every parsed file and returns its
// matching VirtualHost sections with source file pointers.
type vhostHit struct {
	File *parsedFile
	Sec  *parser.Section
}

func findMatchingVHostsAcrossFiles(files []*parsedFile, domains []string, wantPort string) []vhostHit {
	var hits []vhostHit
	for _, f := range files {
		for _, sec := range findMatchingVHosts(f.AST, domains, wantPort) {
			hits = append(hits, vhostHit{File: f, Sec: sec})
		}
	}
	return hits
}

func writeAllFiles(files []*parsedFile) error {
	for _, f := range files {
		if err := os.WriteFile(f.Path, []byte(f.AST.String()), 0o644); err != nil {
			return fmt.Errorf("apache: write %s: %w", f.Path, err)
		}
	}
	return nil
}
