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
	// Empty line followed by a real address.
	d := &Input{In: strings.NewReader("\nuser@example.com\n"), Out: out}
	got := d.Email("Email:")
	if got != "user@example.com" {
		t.Errorf("Email got %q", got)
	}
	if !strings.Contains(out.String(), "email address is required") {
		t.Errorf("expected retry prompt, got %q", out.String())
	}
}
