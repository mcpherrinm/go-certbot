// Package display provides interactive-prompt helpers used by the account
// verbs (register, update_account, unregister). Matches certbot._internal.
// display.ops in behavior: prompts read from stdin and skip in
// non-interactive mode.
package display

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Input controls where prompts read from and write to. Defaults to os.Stdin/
// os.Stderr; tests override.
type Input struct {
	In  io.Reader
	Out io.Writer
}

// Default reads from os.Stdin and writes to os.Stderr.
var Default = &Input{In: os.Stdin, Out: os.Stderr}

// YesNo prompts with a y/N question. Returns false on EOF or any non-"y"
// reply. Matches `display_util.yesno(prompt, default=False)` semantics.
func (i *Input) YesNo(prompt string) bool {
	return i.YesNoDefault(prompt, false)
}

// YesNoDefault prompts with a y/n question whose default tracks `def`. The
// uppercase letter in the prompt indicates the default. Matches Certbot's
// `display_util.yesno(prompt, default=True|False)`.
func (i *Input) YesNoDefault(prompt string, def bool) bool {
	tag := "[y/N]"
	if def {
		tag = "[Y/n]"
	}
	fmt.Fprintf(i.Out, "%s %s: ", prompt, tag)
	scanner := bufio.NewScanner(i.In)
	if !scanner.Scan() {
		return def
	}
	ans := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if ans == "" {
		return def
	}
	return ans == "y" || ans == "yes"
}

// Notify writes a notification message (no input). Matches Certbot's
// display_util.notification — used for "Successfully …" status lines.
func (i *Input) Notify(msg string) {
	fmt.Fprintln(i.Out, msg)
}

// Email prompts for an email address. Matches Certbot's
// `display_ops.get_email`: a blank reply is returned to the caller so
// register can decide whether to switch to unsafely-without-email mode.
// A single retry on a blank line is permitted (the first blank prints a
// hint, the second blank returns "").
func (i *Input) Email(prompt string) string {
	scanner := bufio.NewScanner(i.In)
	blanks := 0
	for {
		fmt.Fprint(i.Out, prompt+" ")
		if !scanner.Scan() {
			return ""
		}
		s := strings.TrimSpace(scanner.Text())
		if s != "" {
			return s
		}
		blanks++
		if blanks >= 1 {
			return ""
		}
		fmt.Fprintln(i.Out, "(blank skips email; press Enter again to confirm)")
	}
}

// YesNo is the package-level shortcut on Default.
func YesNo(prompt string) bool { return Default.YesNo(prompt) }

// YesNoDefault is the package-level shortcut.
func YesNoDefault(prompt string, def bool) bool { return Default.YesNoDefault(prompt, def) }

// Email is the package-level shortcut on Default.
func Email(prompt string) string { return Default.Email(prompt) }

// Notify is the package-level shortcut.
func Notify(msg string) { Default.Notify(msg) }

// Menu prompts the user to pick one option from items. Returns the 0-based
// index of the chosen item, or -1 if the user aborted (EOF or empty input).
// Mirrors `display_util.menu(prompt, choices, default=None, force_interactive)`.
// In non-interactive mode (`In == nil` or EOF) returns def (default index).
func (i *Input) Menu(prompt string, items []string, def int) int {
	fmt.Fprintln(i.Out, prompt)
	for n, item := range items {
		fmt.Fprintf(i.Out, "%d: %s\n", n+1, item)
	}
	for {
		mark := ""
		if def >= 0 && def < len(items) {
			mark = fmt.Sprintf(" [%d]", def+1)
		}
		fmt.Fprintf(i.Out, "Enter the number of an entry%s: ", mark)
		scanner := bufio.NewScanner(i.In)
		if !scanner.Scan() {
			return def
		}
		s := strings.TrimSpace(scanner.Text())
		if s == "" {
			return def
		}
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n >= 1 && n <= len(items) {
			return n - 1
		}
		fmt.Fprintln(i.Out, "Invalid selection, try again.")
	}
}

// Checklist prompts the user to pick a subset of items. The user enters a
// comma- or space-separated list of 1-based indices, or `all` for everything.
// Returns the 0-based indices of selected items. Mirrors
// `display_util.checklist`.
func (i *Input) Checklist(prompt string, items []string) []int {
	fmt.Fprintln(i.Out, prompt)
	for n, item := range items {
		fmt.Fprintf(i.Out, "%d: %s\n", n+1, item)
	}
	for {
		fmt.Fprint(i.Out, "Enter numbers separated by space/comma, or `all`: ")
		scanner := bufio.NewScanner(i.In)
		if !scanner.Scan() {
			return nil
		}
		s := strings.TrimSpace(scanner.Text())
		if s == "" {
			return nil
		}
		if strings.EqualFold(s, "all") {
			out := make([]int, len(items))
			for n := range items {
				out[n] = n
			}
			return out
		}
		var out []int
		ok := true
		for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ' '
		}) {
			var n int
			if _, err := fmt.Sscanf(tok, "%d", &n); err != nil || n < 1 || n > len(items) {
				ok = false
				break
			}
			out = append(out, n-1)
		}
		if ok {
			return out
		}
		fmt.Fprintln(i.Out, "Invalid selection, try again.")
	}
}

// DirectorySelect prompts for a directory path. Validates that the path
// exists and is a directory before returning. Mirrors
// `display_ops.choose_dir`. Returns "" on EOF or `default_value` when the
// user just hits enter.
func (i *Input) DirectorySelect(prompt, defaultValue string) string {
	for {
		mark := ""
		if defaultValue != "" {
			mark = fmt.Sprintf(" [%s]", defaultValue)
		}
		fmt.Fprintf(i.Out, "%s%s: ", prompt, mark)
		scanner := bufio.NewScanner(i.In)
		if !scanner.Scan() {
			return ""
		}
		s := strings.TrimSpace(scanner.Text())
		if s == "" {
			s = defaultValue
		}
		if s == "" {
			fmt.Fprintln(i.Out, "(a directory is required)")
			continue
		}
		info, err := osStat(s)
		if err == nil && info.IsDir() {
			return s
		}
		fmt.Fprintf(i.Out, "%s is not a directory; try again.\n", s)
	}
}

// osStat is wired through a var so tests can override.
var osStat = func(p string) (fileInfo, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	return st, nil
}

type fileInfo interface {
	IsDir() bool
}

// Menu / Checklist / DirectorySelect package-level shortcuts.
func Menu(prompt string, items []string, def int) int { return Default.Menu(prompt, items, def) }
func Checklist(prompt string, items []string) []int   { return Default.Checklist(prompt, items) }
func DirectorySelect(prompt, defaultValue string) string {
	return Default.DirectorySelect(prompt, defaultValue)
}
