package logfile

import (
	"io"
	"os"

	"golang.org/x/term"
)

// isatty reports whether w writes to a terminal. Used to gate ANSI color.
func isatty(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
