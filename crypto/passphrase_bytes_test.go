package crypto

import (
	"bytes"
	"testing"
)

// TestPassphraseBytesEquivalence: the []byte cores and the string wrappers
// are interchangeable in both directions — a bundle sealed by one opens with
// the other.
func TestPassphraseBytesEquivalence(t *testing.T) {
	data := []byte("plaintext payload")
	pass := "correct horse battery staple"

	ctBytes, err := EncryptWithPassphraseBytes(data, []byte(pass))
	if err != nil {
		t.Fatalf("encrypt bytes: %v", err)
	}
	ctString, err := EncryptWithPassphrase(data, pass)
	if err != nil {
		t.Fatalf("encrypt string: %v", err)
	}

	// bytes-encrypted → string-decrypted
	out, err := DecryptWithPassphrase(ctBytes, pass)
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("string decrypt of bytes ct: %v", err)
	}
	// string-encrypted → bytes-decrypted
	out, err = DecryptWithPassphraseBytes(ctString, []byte(pass))
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("bytes decrypt of string ct: %v", err)
	}

	// Wrong passphrase still fails.
	if _, err := DecryptWithPassphraseBytes(ctBytes, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
}

// TestDeriveHardwareKEKBytesEquivalence: byte and string variants derive the
// same KEK.
func TestDeriveHardwareKEKBytesEquivalence(t *testing.T) {
	hw := []byte("hardware-response-20-bytes!!")
	a, err := DeriveHardwareKEK("pass", hw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveHardwareKEKBytes([]byte("pass"), hw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("KEK mismatch between string and bytes variants")
	}
}
