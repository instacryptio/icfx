package format

import (
	"bytes"
	"strings"
	"testing"
)

func TestArmorRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		label string
	}{
		{"lock label", []byte(`{"name":"alice","enc_pub_key":"abc123"}`), ArmorLockLabel},
		{"key label", []byte("some-encrypted-binary-data\x00\x01\x02"), ArmorIdentityLabel},
		{"empty payload", []byte{}, ArmorLockLabel},
		{"large payload", bytes.Repeat([]byte("A"), 1000), ArmorIdentityLabel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			armored := ArmorEncode(tt.data, tt.label)
			payload, label, err := ArmorDecode(armored)
			if err != nil {
				t.Fatalf("ArmorDecode error: %v", err)
			}
			if label != tt.label {
				t.Errorf("label = %q, want %q", label, tt.label)
			}
			if !bytes.Equal(payload, tt.data) {
				t.Errorf("payload mismatch: got %d bytes, want %d bytes", len(payload), len(tt.data))
			}
		})
	}
}

func TestArmorDecodeExpect(t *testing.T) {
	data := []byte("some-encrypted-binary-data\x00\x01\x02")

	// Matching label → payload returned.
	armored := ArmorEncode(data, ArmorIdentityLabel)
	payload, err := ArmorDecodeExpect(armored, ArmorIdentityLabel)
	if err != nil {
		t.Fatalf("ArmorDecodeExpect(matching) error: %v", err)
	}
	if !bytes.Equal(payload, data) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(payload), len(data))
	}

	// Wrong label (e.g. a lock fed to identity import) → rejected.
	lock := ArmorEncode(data, ArmorLockLabel)
	if _, err := ArmorDecodeExpect(lock, ArmorIdentityLabel); err == nil {
		t.Error("ArmorDecodeExpect accepted a non-matching label, want error")
	}

	// Multiple allowed labels → any match passes.
	if _, err := ArmorDecodeExpect(lock, ArmorIdentityLabel, ArmorLockLabel); err != nil {
		t.Errorf("ArmorDecodeExpect(multi) rejected an allowed label: %v", err)
	}
}

func TestArmorEncodeLineWrapping(t *testing.T) {
	data := bytes.Repeat([]byte("X"), 100)
	armored := string(ArmorEncode(data, ArmorLockLabel))
	lines := strings.Split(strings.TrimSpace(armored), "\n")

	// Skip header and footer
	for _, line := range lines[1 : len(lines)-1] {
		if len(line) > 76 {
			t.Errorf("line exceeds 76 chars: %d chars", len(line))
		}
	}
}

func TestIsArmored(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"armored lock", []byte("-----BEGIN ICFX LOCK-----\nabc\n-----END ICFX LOCK-----\n"), true},
		{"armored identity", []byte("-----BEGIN ICFX IDENTITY-----\nabc\n-----END ICFX IDENTITY-----\n"), true},
		{"leading whitespace", []byte("\n  -----BEGIN ICFX LOCK-----\nabc\n-----END ICFX LOCK-----\n"), true},
		{"plain json", []byte(`{"name":"alice"}`), false},
		{"age file", []byte("age-encryption.org"), false},
		{"empty", []byte{}, false},
		{"random pem", []byte("-----BEGIN RSA KEY-----"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsArmored(tt.data); got != tt.want {
				t.Errorf("IsArmored() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArmorDecodeCRLF(t *testing.T) {
	armored := "-----BEGIN ICFX LOCK-----\r\nYWJj\r\n-----END ICFX LOCK-----\r\n"
	payload, label, err := ArmorDecode([]byte(armored))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != ArmorLockLabel {
		t.Errorf("label = %q, want %q", label, ArmorLockLabel)
	}
	if string(payload) != "abc" {
		t.Errorf("payload = %q, want %q", payload, "abc")
	}
}

func TestArmorEncodeDecodeWithHeaders(t *testing.T) {
	data := []byte("payload bytes")
	headers := map[string]string{
		"Fingerprint": "a1b2c3d4e5f6g7h8",
		"Comment":     "test signature",
	}
	armored := ArmorEncodeWithHeaders(data, "ICFX GIT SIGNATURE", headers)

	// Headers must come before a blank line, then base64
	armoredStr := string(armored)
	if !strings.Contains(armoredStr, "Fingerprint: a1b2c3d4e5f6g7h8\n") {
		t.Errorf("expected fingerprint header in output:\n%s", armoredStr)
	}
	if !strings.Contains(armoredStr, "Comment: test signature\n") {
		t.Errorf("expected comment header in output:\n%s", armoredStr)
	}

	payload, label, gotHeaders, err := ArmorDecodeWithHeaders(armored)
	if err != nil {
		t.Fatalf("ArmorDecodeWithHeaders: %v", err)
	}
	if label != "ICFX GIT SIGNATURE" {
		t.Errorf("label = %q", label)
	}
	if !bytes.Equal(payload, data) {
		t.Errorf("payload = %q, want %q", payload, data)
	}
	if gotHeaders["Fingerprint"] != "a1b2c3d4e5f6g7h8" {
		t.Errorf("Fingerprint header = %q", gotHeaders["Fingerprint"])
	}
	if gotHeaders["Comment"] != "test signature" {
		t.Errorf("Comment header = %q", gotHeaders["Comment"])
	}
}

func TestArmorDecodeWithHeaders_NoHeaders(t *testing.T) {
	armored := ArmorEncode([]byte("data"), "ICFX LOCK")
	_, _, headers, err := ArmorDecodeWithHeaders(armored)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(headers) != 0 {
		t.Errorf("expected empty headers map, got %v", headers)
	}
}

func TestArmorDecode_SkipsHeadersGracefully(t *testing.T) {
	// ArmorDecode (no headers variant) should still work on input with headers.
	armored := ArmorEncodeWithHeaders([]byte("x"), "ICFX LOCK", map[string]string{"K": "V"})
	payload, label, err := ArmorDecode(armored)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "ICFX LOCK" {
		t.Errorf("label = %q", label)
	}
	if string(payload) != "x" {
		t.Errorf("payload = %q", payload)
	}
}

func TestArmorEncodeWithHeaders_NilHeadersMatchesPlain(t *testing.T) {
	data := []byte("hello world")
	a := ArmorEncode(data, "ICFX LOCK")
	b := ArmorEncodeWithHeaders(data, "ICFX LOCK", nil)
	if !bytes.Equal(a, b) {
		t.Errorf("nil headers should match plain ArmorEncode:\nplain=%q\nnil=  %q", a, b)
	}
}

func TestArmorEncodeWithHeaders_DeterministicOrder(t *testing.T) {
	data := []byte("data")
	headers := map[string]string{
		"Z-Last":  "z",
		"A-First": "a",
		"M-Mid":   "m",
	}
	a := string(ArmorEncodeWithHeaders(data, "X", headers))
	b := string(ArmorEncodeWithHeaders(data, "X", headers))
	if a != b {
		t.Errorf("output not deterministic")
	}
	// Headers must appear in alphabetical order.
	posA := strings.Index(a, "A-First:")
	posM := strings.Index(a, "M-Mid:")
	posZ := strings.Index(a, "Z-Last:")
	if !(posA < posM && posM < posZ) {
		t.Errorf("headers not in sorted order: A=%d M=%d Z=%d", posA, posM, posZ)
	}
}

func TestArmorDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "empty armored input"},
		{"missing footer", "-----BEGIN ICFX LOCK-----\nYWJj\n", "missing or mismatched footer"},
		{"bad base64", "-----BEGIN ICFX LOCK-----\n!!invalid!!\n-----END ICFX LOCK-----\n", "invalid base64"},
		{"mismatched labels", "-----BEGIN ICFX LOCK-----\nYWJj\n-----END ICFX DATA-----\n", "missing or mismatched footer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ArmorDecode([]byte(tt.input))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
