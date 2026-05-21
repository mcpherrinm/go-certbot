package verbs

import "testing"

func TestLookupReason(t *testing.T) {
	tests := []struct {
		in   string
		want uint
		err  bool
	}{
		{"", 0, false},
		{"unspecified", 0, false},
		{"keycompromise", 1, false},
		{"KeyCompromise", 1, false},
		{"superseded", 4, false},
		{"cessationofoperation", 5, false},
		{"affiliationchanged", 3, false},
		{"bogus", 0, true},
	}
	for _, tc := range tests {
		got, err := lookupReason(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("lookupReason(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("lookupReason(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("lookupReason(%q): got %d want %d", tc.in, got, tc.want)
		}
	}
}
