package display

import (
	"bytes"
	"strings"
	"testing"
)

func TestYesNo(t *testing.T) {
	cases := map[string]bool{
		"y\n":   true,
		"Y\n":   true,
		"yes\n": true,
		"n\n":   false,
		"\n":    false,
		"":      false,
	}
	for in, want := range cases {
		out := &bytes.Buffer{}
		d := &Input{In: strings.NewReader(in), Out: out}
		got := d.YesNo("ok?")
		if got != want {
			t.Errorf("YesNo(%q) = %v want %v", in, got, want)
		}
	}
}

func TestEmail(t *testing.T) {
	out := &bytes.Buffer{}
	// A real address on the first line returns it.
	d := &Input{In: strings.NewReader("user@example.com\n"), Out: out}
	got := d.Email("Email:")
	if got != "user@example.com" {
		t.Errorf("Email got %q", got)
	}
}

func TestEmailBlankSkips(t *testing.T) {
	out := &bytes.Buffer{}
	// A blank line returns "" — caller switches to unsafely-without-email
	// mode (matches Certbot display_ops.get_email).
	d := &Input{In: strings.NewReader("\n"), Out: out}
	if got := d.Email("Email:"); got != "" {
		t.Errorf("blank line should return empty; got %q", got)
	}
}
