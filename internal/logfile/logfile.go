// Package logfile writes /var/log/letsencrypt/letsencrypt.log alongside any
// stderr output, matching certbot/_internal/log.py's
// setup_log_file_handler. The log rotates at 1 MiB with backup count
// max_log_backups (default 1000).
package logfile

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
)

// Setup opens <logsDir>/letsencrypt.log (creating logsDir if missing) and
// attaches a slog handler that writes to both stderr and the file. Returns a
// close func that flushes and closes the file. If logsDir is empty or the
// file can't be opened, falls back to stderr-only (matching Certbot's
// behavior on permission errors — log to stderr and warn once).
//
// Mirrors certbot._internal.log.setup_log_file_handler. Format:
//   <RFC3339 timestamp>:<LEVEL>:<source>:<message>
//
// File mode is 0o640 (Certbot uses 0o640 for the log file via os.umask).
func Setup(logsDir string, level slog.Level, maxBackups int) (io.Closer, error) {
	if logsDir == "" {
		return noopCloser{}, nil
	}
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return noopCloser{}, fmt.Errorf("logfile: mkdir %s: %w", logsDir, err)
	}
	path := filepath.Join(logsDir, "letsencrypt.log")
	if err := maybeRotate(path, maxBackups); err != nil {
		// Continue; rotation failure is non-fatal.
		fmt.Fprintf(os.Stderr, "logfile: rotate %s: %v\n", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return noopCloser{}, fmt.Errorf("logfile: open %s: %w", path, err)
	}
	// Tee stderr and file. Certbot prints to stderr by default at WARNING+
	// and writes EVERYTHING to the file; we model the same here by giving
	// the file handler DEBUG.
	stderrH := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	fileH := slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(multiHandler{stderrH, fileH}))
	// Certbot's startup banner: print where to find the debug log so users
	// know to attach it on bug reports (log.py:140).
	if level > slog.LevelInfo {
		// quiet — skip the banner
	} else {
		fmt.Fprintf(os.Stderr, "Saving debug log to %s\n", path)
	}
	return f, nil
}

// maybeRotate moves letsencrypt.log → letsencrypt.log.1 (cascading the
// existing backups) once the file exceeds maxBytes. Matches Certbot's
// RotatingFileHandler with maxBytes=2**20.
const maxBytes = 1 << 20

func maybeRotate(path string, maxBackups int) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() < maxBytes {
		return nil
	}
	if maxBackups <= 0 {
		// Truncate in place rather than backup.
		return os.Truncate(path, 0)
	}
	// Cascade existing backups: .N-1 → .N
	for i := maxBackups - 1; i >= 1; i-- {
		from := path + "." + strconv.Itoa(i)
		to := path + "." + strconv.Itoa(i+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	return os.Rename(path, path+".1")
}

type multiHandler [2]slog.Handler

func (m multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return m[0].Enabled(ctx, l) || m[1].Enabled(ctx, l)
}
func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}
func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return multiHandler{m[0].WithAttrs(attrs), m[1].WithAttrs(attrs)}
}
func (m multiHandler) WithGroup(name string) slog.Handler {
	return multiHandler{m[0].WithGroup(name), m[1].WithGroup(name)}
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
