// Package processlock acquires advisory file locks on config/work/logs
// directories so concurrent go-certbot invocations don't race over shared
// state. Mirrors certbot._internal.lock.LockFile (lock.py:106-131).
//
// Each lock is an empty file `.certbot.lock` under the directory; we hold
// an LOCK_EX|LOCK_NB on it for the lifetime of the process. Locks release
// automatically when the process exits or Release is called explicitly.
package processlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Held is a set of locks acquired by AcquireDirs.
type Held struct {
	files []*os.File
}

// AcquireDirs locks each of the given directories. Skips empty strings.
// Returns ErrLocked if any of them is already locked by another process.
func AcquireDirs(dirs ...string) (*Held, error) {
	h := &Held{}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			h.Release()
			return nil, fmt.Errorf("processlock: mkdir %s: %w", d, err)
		}
		path := filepath.Join(d, ".certbot.lock")
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			h.Release()
			return nil, fmt.Errorf("processlock: open %s: %w", path, err)
		}
		if err := flockNB(f); err != nil {
			_ = f.Close()
			h.Release()
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				return nil, fmt.Errorf("processlock: another instance of go-certbot is already running (lock at %s)", path)
			}
			return nil, fmt.Errorf("processlock: flock %s: %w", path, err)
		}
		h.files = append(h.files, f)
	}
	return h, nil
}

// Release closes every held lock file (and so releases the lock).
func (h *Held) Release() {
	if h == nil {
		return
	}
	for _, f := range h.files {
		_ = f.Close()
	}
	h.files = nil
}

func flockNB(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
