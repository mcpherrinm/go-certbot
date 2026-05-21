// Package logfile writes /var/log/letsencrypt/letsencrypt.log alongside any
// stderr output, matching certbot/_internal/log.py's
// setup_log_file_handler. The log rotates on every Setup call (Certbot does
// the same — log.py:173 calls handler.doRollover() unconditionally).
package logfile

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// lastPath holds the most recently opened log file path so the panic
// handler in cmd/main.go can write a stack trace alongside it.
var (
	lastMu   sync.Mutex
	lastFile string
	preBuf   []string // messages emitted before Setup ran
)

// LastPath returns the path Setup opened most recently, or "" if Setup
// never ran successfully.
func LastPath() string {
	lastMu.Lock()
	defer lastMu.Unlock()
	return lastFile
}

// Setup opens <logsDir>/letsencrypt.log (creating logsDir if missing) and
// attaches a slog handler that writes to both stderr and the file. Returns a
// close func that flushes and closes the file.
//
// Mirrors certbot._internal.log.setup_log_file_handler:
//
//   - Rotate on every invocation (not size).
//   - Custom format "RFC3339:LEVEL:logger:message" matching
//     log.FILE_FMT = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'.
//   - File mode 0o600 (Certbot safe_open with chmod 0o600).
//   - ANSI red on WARNING+ for stderr when TTY + NO_COLOR unset.
//   - Buffered pre-Setup messages flushed in after handler is set up.
func Setup(logsDir string, level slog.Level, maxBackups int) (io.Closer, error) {
	if logsDir == "" {
		return noopCloser{}, nil
	}
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return noopCloser{}, fmt.Errorf("logfile: mkdir %s: %w", logsDir, err)
	}
	path := filepath.Join(logsDir, "letsencrypt.log")
	if err := rotate(path, maxBackups); err != nil {
		fmt.Fprintf(os.Stderr, "logfile: rotate %s: %v\n", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return noopCloser{}, fmt.Errorf("logfile: open %s: %w", path, err)
	}
	lastMu.Lock()
	lastFile = path
	lastMu.Unlock()

	stderrH := newCertbotHandler(os.Stderr, level, isatty(os.Stderr))
	fileH := newCertbotHandler(f, slog.LevelDebug, false)
	slog.SetDefault(slog.New(multiHandler{stderrH, fileH}))

	// Flush any messages buffered before Setup opened the file.
	lastMu.Lock()
	pending := preBuf
	preBuf = nil
	lastMu.Unlock()
	for _, msg := range pending {
		_, _ = io.WriteString(f, msg)
	}

	return f, nil
}

// PreSetup buffers a message in memory so messages logged before the file
// handler exists still end up on disk after Setup runs.
func PreSetup(msg string) {
	lastMu.Lock()
	defer lastMu.Unlock()
	preBuf = append(preBuf, msg)
}

// WriteCrashTrace dumps the runtime stack to a crash file alongside the
// active log. Returns silently if no log path has been opened yet (best
// effort, called from a panic context).
func WriteCrashTrace(panicMsg string) {
	lastMu.Lock()
	path := lastFile
	lastMu.Unlock()
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n----- PANIC %s -----\n%s\n%s\n",
		time.Now().UTC().Format(time.RFC3339), panicMsg, string(debug.Stack()))
}

// rotate moves letsencrypt.log → letsencrypt.log.1 (cascading the existing
// backups) unconditionally on each Setup. Matches Certbot's log.py:173.
func rotate(path string, maxBackups int) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if maxBackups <= 0 {
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

// certbotHandler emits "RFC3339:LEVEL:logger:message" lines matching
// Certbot's log.FILE_FMT. When color=true, WARNING+ levels are wrapped in
// ANSI red — but only if NO_COLOR is unset.
type certbotHandler struct {
	mu    sync.Mutex
	w     io.Writer
	level slog.Level
	color bool
}

func newCertbotHandler(w io.Writer, level slog.Level, color bool) *certbotHandler {
	if os.Getenv("NO_COLOR") != "" {
		color = false
	}
	return &certbotHandler{w: w, level: level, color: color}
}

func (h *certbotHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }
func (h *certbotHandler) Handle(_ context.Context, r slog.Record) error {
	ts := r.Time.UTC().Format(time.RFC3339)
	lvl := levelName(r.Level)
	logger := "certbot"
	msg := r.Message
	// Append slog attrs as key=value pairs to keep parity with Python's
	// logger.info("...", extra={"key": val}).
	r.Attrs(func(a slog.Attr) bool {
		msg += " " + a.Key + "=" + a.Value.String()
		return true
	})
	line := fmt.Sprintf("%s:%s:%s:%s\n", ts, lvl, logger, msg)
	if h.color && r.Level >= slog.LevelWarn {
		line = "\x1b[31m" + strings.TrimRight(line, "\n") + "\x1b[0m\n"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line)
	return err
}
func (h *certbotHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *certbotHandler) WithGroup(name string) slog.Handler       { return h }

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARNING"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
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
