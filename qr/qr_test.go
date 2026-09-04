package qr

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalParseLockBundle_RoundTrip(t *testing.T) {
	bundle := LockBundle{
		Name:        "alice",
		EncPubKey:   "age1pq1" + strings.Repeat("q", 100),
		SignPubKey:  strings.Repeat("A", 2604),
		Fingerprint: "abc123def456",
		Email:       "alice@example.com",
		Alias:       "ally",
	}

	data, err := MarshalLockBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalLockBundle: %v", err)
	}

	parsed, err := ParseLockBundle(data)
	if err != nil {
		t.Fatalf("ParseLockBundle: %v", err)
	}

	if parsed.Name != bundle.Name {
		t.Errorf("Name: got %q, want %q", parsed.Name, bundle.Name)
	}
	if parsed.EncPubKey != bundle.EncPubKey {
		t.Errorf("EncPubKey mismatch")
	}
	if parsed.SignPubKey != bundle.SignPubKey {
		t.Errorf("SignPubKey mismatch")
	}
	if parsed.Fingerprint != bundle.Fingerprint {
		t.Errorf("Fingerprint mismatch")
	}
	if parsed.Email != bundle.Email {
		t.Errorf("Email mismatch")
	}
	if parsed.Alias != bundle.Alias {
		t.Errorf("Alias mismatch")
	}
}

func TestParseLockBundle_BackwardCompat(t *testing.T) {
	// Old QR format without sign_pub_key
	oldJSON := `{"name":"bob","enc_pub_key":"age1xxx","fingerprint":"fp123"}`

	bundle, err := ParseLockBundle([]byte(oldJSON))
	if err != nil {
		t.Fatalf("ParseLockBundle (old format): %v", err)
	}

	if bundle.Name != "bob" {
		t.Errorf("Name: got %q, want %q", bundle.Name, "bob")
	}
	if bundle.SignPubKey != "" {
		t.Errorf("SignPubKey should be empty for old format, got %q", bundle.SignPubKey)
	}
	if bundle.Email != "" {
		t.Errorf("Email should be empty for old format, got %q", bundle.Email)
	}
}

func TestMarshalLockBundle_OmitsEmptyOptionalFields(t *testing.T) {
	bundle := LockBundle{
		Name:        "charlie",
		Fingerprint: "fp456",
	}

	data, err := MarshalLockBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalLockBundle: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}

	if _, ok := raw["sign_pub_key"]; ok {
		t.Error("sign_pub_key should be omitted when empty")
	}
	if _, ok := raw["enc_pub_key"]; ok {
		t.Error("enc_pub_key should be omitted when empty")
	}
}

func TestFullBundleExceedsQRv40L(t *testing.T) {
	// With hybrid PQ keys, a full bundle no longer fits in a single QR code.
	bundle := LockBundle{
		Name:        "testuser",
		EncPubKey:   "age1pq1" + strings.Repeat("q", 1940), // hybrid recipient ~1946 chars
		SignPubKey:  strings.Repeat("A", 2604),             // ML-DSA-65 ~2604 chars base64
		Fingerprint: strings.Repeat("a", 16),
		Email:       "user@example.com",
		Alias:       "tester",
	}

	data, err := MarshalLockBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalLockBundle: %v", err)
	}

	const qrV40LByteCapacity = 2953
	if len(data) <= qrV40LByteCapacity {
		t.Errorf("expected bundle size %d to exceed QR v40 L capacity %d", len(data), qrV40LByteCapacity)
	}

	t.Logf("full bundle size: %d bytes (QR v40 L capacity: %d) — animated QR required", len(data), qrV40LByteCapacity)
}
