// Package processlock acquires advisory file locks on config/work/logs
// directories so concurrent certbot/go-certbot invocations don't race over
// shared state. Mirrors certbot._internal.lock.LockFile (lock.py:106-181).
//
// Each lock is an empty file `.certbot.lock` under the directory; we hold
// an fcntl LOCK_EX|LOCK_NB (POSIX lockf/F_SETLK) on it for the lifetime of
// the process. POSIX file locks are required (not Go's syscall.Flock) so
// that go-certbot and Python Certbot, which uses fcntl.lockf, refuse to run
// concurrently — flock(2) and fcntl/lockf(2) are independent kernel locks.
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
	locks []heldLock
}

type heldLock struct {
	file *os.File
	path string
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
		f, err := tryAcquire(path)
		if err != nil {
			h.Release()
			return nil, err
		}
		h.locks = append(h.locks, heldLock{file: f, path: path})
	}
	return h, nil
}

// tryAcquire opens path and grabs an exclusive POSIX advisory lock on it.
// Implements the same open/lock/inode-recheck dance as Certbot's
// LockFile.acquire so a concurrent unlink+recreate doesn't leave the caller
// holding a lock on an orphan inode.
func tryAcquire(path string) (*os.File, error) {
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("processlock: open %s: %w", path, err)
		}
		if err := fcntlExclusive(f); err != nil {
			_ = f.Close()
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
				return nil, fmt.Errorf("processlock: another instance of Certbot is already running (lock at %s)", path)
			}
			return nil, fmt.Errorf("processlock: lockf %s: %w", path, err)
		}
		// Inode recheck: another process may have unlinked-and-recreated
		// the file between our open and our lock acquisition; in that
		// case our lock is on the orphan inode and means nothing.
		var diskStat syscall.Stat_t
		switch err := syscall.Stat(path, &diskStat); {
		case err == nil:
			var fdStat syscall.Stat_t
			if err := syscall.Fstat(int(f.Fd()), &fdStat); err == nil &&
				diskStat.Dev == fdStat.Dev && diskStat.Ino == fdStat.Ino {
				return f, nil
			}
		case errors.Is(err, syscall.ENOENT):
			// File was unlinked between our open and stat. Retry.
		default:
			_ = f.Close()
			return nil, fmt.Errorf("processlock: stat %s: %w", path, err)
		}
		// Try again with a fresh open.
		_ = f.Close()
	}
}

// Release removes and closes every held lock file. Certbot unlinks the
// lock file *before* closing so that a racing process can't re-open the
// inode under the same name and inherit a confusing semi-locked state.
func (h *Held) Release() {
	if h == nil {
		return
	}
	for _, l := range h.locks {
		_ = os.Remove(l.path)
		_ = l.file.Close()
	}
	h.locks = nil
}

func fcntlExclusive(f *os.File) error {
	lk := &syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: 0, // SEEK_SET
		Start:  0,
		Len:    0, // entire file
	}
	return syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, lk)
}
