package cmd

import (
	"reflect"
	"testing"
)

func TestNormalizeDomains(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{}, []string{}},
		{[]string{"example.com"}, []string{"example.com"}},
		// Trailing dot stripped.
		{[]string{"example.com."}, []string{"example.com"}},
		// Lowercase.
		{[]string{"Example.COM"}, []string{"example.com"}},
		// Combined trailing dot + uppercase.
		{[]string{"Example.COM."}, []string{"example.com"}},
		// Dedupe preserving first-seen order; case-insensitive.
		{[]string{"a.example", "A.Example", "b.example"}, []string{"a.example", "b.example"}},
		// Trim surrounding whitespace.
		{[]string{"  example.com  "}, []string{"example.com"}},
		// Skip empty.
		{[]string{"", "example.com", ""}, []string{"example.com"}},
	} {
		got := normalizeDomains(tc.in)
		// Treat nil-vs-empty as equivalent — both are "no domains".
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("normalizeDomains(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
