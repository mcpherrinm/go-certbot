package nginx

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

// parsedFile is one nginx configuration file in the include tree.
type parsedFile struct {
	Path string
	AST  *parser.Config
}

// loadAll parses the given root file and recursively follows `include`
// directives (globs supported). Returns one parsedFile per discovered file.
// Cycles are short-circuited.
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
	if visited[abs] {
		return nil
	}
	visited[abs] = true
	b, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("nginx: read %s: %w", abs, err)
	}
	cfg, err := parser.Parse(string(b))
	if err != nil {
		return fmt.Errorf("nginx: parse %s: %w", abs, err)
	}
	*out = append(*out, &parsedFile{Path: abs, AST: cfg})
	// Walk top-level + nested blocks for include directives.
	return walkIncludes(filepath.Dir(abs), cfg.Nodes, visited, out)
}

func walkIncludes(base string, nodes []parser.Node, visited map[string]bool, out *[]*parsedFile) error {
	for _, n := range nodes {
		switch nn := n.(type) {
		case *parser.Directive:
			if nn.Name == "include" && len(nn.Args) > 0 {
				glob := dequote(nn.Args[0])
				if !filepath.IsAbs(glob) {
					glob = filepath.Join(base, glob)
				}
				matches, err := filepath.Glob(glob)
				if err != nil {
					return fmt.Errorf("nginx: include glob %s: %w", glob, err)
				}
				for _, m := range matches {
					info, err := os.Stat(m)
					if err != nil || info.IsDir() {
						continue
					}
					if err := loadInto(m, visited, out); err != nil {
						return err
					}
				}
			}
		case *parser.Block:
			if err := walkIncludes(base, nn.Body, visited, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func dequote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// findMatchingServersAcrossFiles returns the server-block pointers in each
// file that match any requested domain, along with the file each lives in.
type serverHit struct {
	File   *parsedFile
	Server *parser.Block
}

func findMatchingServersAcrossFiles(files []*parsedFile, domains []string) []serverHit {
	var hits []serverHit
	for _, f := range files {
		for _, srv := range findMatchingServers(f.AST, domains) {
			hits = append(hits, serverHit{File: f, Server: srv})
		}
	}
	return hits
}

// writeAllFiles writes each parsedFile back to disk if it was modified.
// (For Phase 5 we conservatively rewrite everything we loaded so any tree
// mutations land. nginx -t will catch regressions.)
func writeAllFiles(files []*parsedFile) error {
	for _, f := range files {
		if err := os.WriteFile(f.Path, []byte(f.AST.String()), 0o644); err != nil {
			return fmt.Errorf("nginx: write %s: %w", f.Path, err)
		}
	}
	return nil
}
