// Package checkpoint provides a simple file-snapshot mechanism so installers
// can revert the most recent change(s) on `go-certbot rollback`.
//
// Layout under work_dir/backups/:
//
//	<work_dir>/backups/
//	    20260520T193245Z-nginx/
//	        manifest.json        list of {abs_path, sha256} entries
//	        files/<sha>          original file content
//
// Each call to Save() writes one new <timestamp>-<label>/ directory. Restore()
// walks them in reverse order and copies the files back to their original
// paths.
package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Manifest struct {
	Label   string  `json:"label"`
	Created string  `json:"created"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	Path string `json:"path"`
	SHA  string `json:"sha"`
}

// Save copies each file in paths into a new checkpoint dir under
// work_dir/backups/<timestamp>-<label>/. Files that don't exist are skipped.
func Save(workDir, label string, paths []string) (string, error) {
	base := filepath.Join(workDir, "backups")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("checkpoint: mkdir %s: %w", base, err)
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	dir := filepath.Join(base, fmt.Sprintf("%s-%s", ts, sanitize(label)))
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		return "", err
	}
	m := Manifest{Label: label, Created: ts}
	for _, p := range paths {
		entry, err := snapshot(dir, p)
		if err != nil {
			return "", err
		}
		if entry != nil {
			m.Entries = append(m.Entries, *entry)
		}
	}
	if len(m.Entries) == 0 {
		_ = os.RemoveAll(dir)
		return "", nil
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644); err != nil {
		return "", err
	}
	return dir, nil
}

func snapshot(dir, path string) (*Entry, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("checkpoint: read %s: %w", abs, err)
	}
	h := sha256.Sum256(data)
	sha := hex.EncodeToString(h[:])
	dst := filepath.Join(dir, "files", sha)
	if _, err := os.Stat(dst); err == nil {
		return &Entry{Path: abs, SHA: sha}, nil
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return nil, err
	}
	return &Entry{Path: abs, SHA: sha}, nil
}

// List returns checkpoint directory names, oldest first.
func List(workDir string) ([]string, error) {
	base := filepath.Join(workDir, "backups")
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, filepath.Join(base, e.Name()))
		}
	}
	sort.Strings(names)
	return names, nil
}

// Restore replays the most recent n checkpoints in reverse.
func Restore(workDir string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	all, err := List(workDir)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("rollback: no checkpoints to restore")
	}
	if n > len(all) {
		n = len(all)
	}
	toRestore := all[len(all)-n:]
	seen := map[string]bool{}
	var changed []string
	for i := len(toRestore) - 1; i >= 0; i-- {
		dir := toRestore[i]
		mBytes, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			return nil, fmt.Errorf("rollback: read %s/manifest.json: %w", dir, err)
		}
		var m Manifest
		if err := json.Unmarshal(mBytes, &m); err != nil {
			return nil, err
		}
		for _, e := range m.Entries {
			if seen[e.Path] {
				continue
			}
			seen[e.Path] = true
			src := filepath.Join(dir, "files", e.SHA)
			if err := restoreFile(src, e.Path); err != nil {
				return nil, err
			}
			changed = append(changed, e.Path)
		}
	}
	for _, dir := range toRestore {
		_ = os.RemoveAll(dir)
	}
	return changed, nil
}

func restoreFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("rollback: open %s: %w", src, err)
	}
	defer in.Close()
	mode := os.FileMode(0o644)
	if info, err := os.Stat(dst); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".rollback-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func sanitize(label string) string {
	var sb strings.Builder
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	if sb.Len() == 0 {
		return "checkpoint"
	}
	return sb.String()
}
