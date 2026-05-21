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

// Email prompts for an email address until the user supplies a non-empty
// string. Matches `display_ops.get_email`. Empty replies are rejected.
func (i *Input) Email(prompt string) string {
	scanner := bufio.NewScanner(i.In)
	for {
		fmt.Fprint(i.Out, prompt+" ")
		if !scanner.Scan() {
			return ""
		}
		s := strings.TrimSpace(scanner.Text())
		if s != "" {
			return s
		}
		fmt.Fprintln(i.Out, "(an email address is required)")
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
