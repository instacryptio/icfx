package validate

import (
	"strings"
	"testing"
)

func TestValidateNoControlChars(t *testing.T) {
	ok := []string{"Alice", "José", "a.b-c_d", "emoji 🔒 ok"}
	for _, s := range ok {
		if err := ValidateNoControlChars("f", s); err != nil {
			t.Errorf("%q should pass: %v", s, err)
		}
	}
	bad := []string{"a\x1b[2Kb", "line1\nline2", "carriage\rreturn", "tab\there", "nul\x00", "del\x7f", "c1\x9b"}
	for _, s := range bad {
		if err := ValidateNoControlChars("f", s); err == nil {
			t.Errorf("%q should be rejected", s)
		}
	}
}

func TestValidateName(t *testing.T) {
	ok := []string{"alice", "work-key", "id_2", "José"}
	for _, s := range ok {
		if err := ValidateName(s); err != nil {
			t.Errorf("%q should pass: %v", s, err)
		}
	}
	bad := map[string]string{
		"empty":       "",
		"slash":       "a/b",
		"backslash":   `a\b`,
		"dotdot":      "..",
		"dotdot-path": "../etc",
		"embedded":    "a..b",
		"dot":         ".",
		"absolute":    "/etc/passwd",
		"control":     "a\x1bb",
		"overlong":    strings.Repeat("x", 129),
		"bidi-rlo":    "alice\u202eevil",
		"bidi-rli":    "alice\u2066evil",
		"zero-width":  "ali\u200bce",
		"bom":         "alice\ufeff",
	}
	for name, s := range bad {
		if err := ValidateName(s); err == nil {
			t.Errorf("%s (%q) should be rejected", name, s)
		}
	}
}
