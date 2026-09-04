package validate

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// maxNameLen bounds identity/contact names used both as labels and as
// filesystem path components.
const maxNameLen = 128

// ValidateNoControlChars rejects C0 (0x00–0x1F), DEL (0x7F), and C1
// (0x80–0x9F) control characters in a user-facing string. These are the
// terminal-escape / line-forging bytes (ESC, CR, LF, …) that let attacker-
// controlled contact fields spoof CLI output; rejecting them at ingest keeps
// poisoned locks out of both clients. field names the checked field for errors.
func ValidateNoControlChars(field, s string) error {
	for i, r := range s {
		// A raw C1 byte (0x80–0x9F) is invalid UTF-8 and decodes to
		// RuneError with width 1 — reject those too, so a lone 0x9b can't
		// slip past the code-point check below.
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size <= 1 {
				return fmt.Errorf("%s contains an invalid or control byte", field)
			}
		}
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return fmt.Errorf("%s contains a disallowed control character", field)
		}
		if isBidiOrZeroWidth(r) {
			return fmt.Errorf("%s contains a disallowed bidirectional or zero-width character", field)
		}
	}
	return nil
}

// isBidiOrZeroWidth reports whether r is a Unicode bidirectional-control or
// zero-width / byte-order-mark code point. These render invisibly (or reorder
// surrounding text) and enable "Trojan Source"-style spoofing — a hostile
// contact/lock name that displays identically to a trusted one, undermining the
// human fingerprint-comparison trust anchor. Rejected at ingest alongside the
// control characters above.
func isBidiOrZeroWidth(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0x200B || r == 0x200C || r == 0x200D: // ZWSP, ZWNJ, ZWJ
		return true
	case r == 0x200E || r == 0x200F: // LRM, RLM
		return true
	case r == 0xFEFF: // ZWNBSP / BOM
		return true
	default:
		return false
	}
}

// ValidateName validates an identity or contact name that is ALSO used as a
// filesystem path component (keystore/meta/challenge files). It rejects empty,
// overlong, control-char, and any path-traversal forms so a hostile bundle
// name can't escape its directory.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("name is too long (max %d characters)", maxNameLen)
	}
	if err := ValidateNoControlChars("name", name); err != nil {
		return err
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("name must not contain path separators")
	}
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return fmt.Errorf("name must not contain %q", "..")
	}
	if filepath.IsAbs(name) {
		return fmt.Errorf("name must not be an absolute path")
	}
	return nil
}
