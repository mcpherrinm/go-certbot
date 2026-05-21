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
	"regexp"
	"strings"
)

// emailPattern is Certbot's safe_email validator (util.py:522-530): an at
// sign separates a non-empty local part from a non-empty domain; neither
// side may contain whitespace.
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Input controls where prompts read from and write to. Defaults to os.Stdin/
// os.Stderr; tests override.
type Input struct {
	In  io.Reader
	Out io.Writer
}

// Default reads from os.Stdin and writes to os.Stdout — Certbot's
// display_util.notify defaults to stdout (obj.py:424-435 with
// outfile=sys.stdout), so script pipelines piping `certbot ... | tee log`
// still capture the success lines.
var Default = &Input{In: os.Stdin, Out: os.Stdout}

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
// `display_ops.get_email` (ops.py:33-46):
//
//   - A blank line returns "" immediately (caller switches to
//     unsafely-without-email mode).
//   - A non-empty value is validated against util.safe_email; on failure
//     the user is re-prompted with the "There is a problem with your email
//     address. " prefix.
func (i *Input) Email(prompt string) string {
	scanner := bufio.NewScanner(i.In)
	invalidPrefix := ""
	for {
		fmt.Fprint(i.Out, invalidPrefix+prompt+" ")
		if !scanner.Scan() {
			return ""
		}
		s := strings.TrimSpace(scanner.Text())
		if s == "" {
			return ""
		}
		if emailPattern.MatchString(s) {
			return s
		}
		invalidPrefix = "There is a problem with your email address. "
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
		// configobj's checklist treats a blank line as "select all"
		// — but blank already returned nil above (kept for parity with
		// non-interactive contexts). `all` is also explicit.
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
