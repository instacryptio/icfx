package validate

import "testing"

func TestAlias(t *testing.T) {
	valid := []string{"", "ictest", "ic-test", "ic_test", "a", "user123", "a1_b2-c3"}
	for _, s := range valid {
		if err := Alias(s); err != nil {
			t.Errorf("Alias(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"Ic Test",   // uppercase + space
		"has space", // space
		"UPPER",     // uppercase
		"dot.dot",   // '.' not allowed
		"emoji😀",    // non-ASCII
		"slash/y",   // path separator
		"tab\tchar", // control char
		"way-too-long-alias-that-exceeds-the-thirty-two-char-limit", // > 32
	}
	for _, s := range invalid {
		if err := Alias(s); err == nil {
			t.Errorf("Alias(%q) = nil, want error", s)
		}
	}
}

func TestNormalizeAlias(t *testing.T) {
	cases := map[string]string{
		"ictest":     "ictest",
		"  ICTest  ": "ictest", // lowercased + trimmed
		"IC_Test":    "ic_test",
		"":           "",
		"has space":  "", // non-conforming → dropped
		"dot.dot":    "",
		"a\x1b[2Kb":  "", // control char → dropped
		"WAY-TOO-LONG-alias-that-exceeds-the-thirty-two": "", // > 32
	}
	for in, want := range cases {
		if got := NormalizeAlias(in); got != want {
			t.Errorf("NormalizeAlias(%q) = %q, want %q", in, got, want)
		}
	}
}
