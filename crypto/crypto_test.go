package crypto

import (
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	if kp.EncryptionIdentity == "" {
		t.Error("EncryptionIdentity is empty")
	}
	if kp.EncryptionRecipient == "" {
		t.Error("EncryptionRecipient is empty")
	}
	if len(kp.SigningPrivateKey) == 0 {
		t.Error("SigningPrivateKey is empty")
	}
	if len(kp.SigningPublicKey) == 0 {
		t.Error("SigningPublicKey is empty")
	}
	if kp.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}
	if len(kp.Fingerprint) != FingerprintHexLen {
		t.Errorf("Fingerprint length = %d, want %d", len(kp.Fingerprint), FingerprintHexLen)
	}

	// Verify hybrid PQ key prefixes
	if !strings.HasPrefix(kp.EncryptionRecipient, "age1pq1") {
		t.Errorf("EncryptionRecipient prefix = %q, want age1pq1...", kp.EncryptionRecipient[:20])
	}
	if !strings.HasPrefix(kp.EncryptionIdentity, "AGE-SECRET-KEY-PQ-1") {
		t.Errorf("EncryptionIdentity prefix = %q, want AGE-SECRET-KEY-PQ-1...", kp.EncryptionIdentity[:30])
	}
}

func TestEncryptDecrypt(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	plaintext := []byte("Hello, Instacrypt!")
	ciphertext, err := Encrypt(plaintext, []string{kp.EncryptionRecipient})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	decrypted, err := Decrypt(ciphertext, kp.EncryptionIdentity)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptMultiRecipient(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(alice) error: %v", err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(bob) error: %v", err)
	}
	carol, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(carol) error: %v", err)
	}

	plaintext := []byte("group secret")
	// Encrypt once to alice + bob (deliberately NOT carol).
	ciphertext, err := Encrypt(plaintext, []string{alice.EncryptionRecipient, bob.EncryptionRecipient})
	if err != nil {
		t.Fatalf("Encrypt(multi) error: %v", err)
	}

	// Both listed recipients decrypt the SAME ciphertext.
	for name, id := range map[string]string{"alice": alice.EncryptionIdentity, "bob": bob.EncryptionIdentity} {
		got, derr := Decrypt(ciphertext, id)
		if derr != nil {
			t.Fatalf("Decrypt(%s) error: %v", name, derr)
		}
		if string(got) != string(plaintext) {
			t.Errorf("Decrypt(%s) = %q, want %q", name, got, plaintext)
		}
	}

	// A non-recipient cannot decrypt.
	if _, derr := Decrypt(ciphertext, carol.EncryptionIdentity); derr == nil {
		t.Error("Decrypt(carol) succeeded, want failure (not a recipient)")
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Error("Encrypt(nil recipients) succeeded, want error")
	}
	if _, err := Encrypt([]byte("x"), []string{}); err == nil {
		t.Error("Encrypt(empty recipients) succeeded, want error")
	}
}

func TestEncryptDecryptWithPassphrase(t *testing.T) {
	plaintext := []byte("Secret data with passphrase")
	passphrase := "test-passphrase-123"

	ciphertext, err := EncryptWithPassphrase(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase() error: %v", err)
	}

	decrypted, err := DecryptWithPassphrase(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("DecryptWithPassphrase() error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("DecryptWithPassphrase() = %q, want %q", decrypted, plaintext)
	}
}

func TestSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	data := []byte("Sign this message")
	signature, err := Sign(data, kp.SigningPrivateKey)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	ok, err := Verify(data, signature, kp.SigningPublicKey)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("Verify() returned false for valid signature")
	}

	// Tampered data should fail
	tampered := []byte("Tampered message")
	ok, err = Verify(tampered, signature, kp.SigningPublicKey)
	if err != nil {
		t.Fatalf("Verify() error on tampered data: %v", err)
	}
	if ok {
		t.Error("Verify() returned true for tampered data")
	}
}

func TestFingerprint(t *testing.T) {
	fp1 := Fingerprint("age1test123", []byte("pubkey1"))
	fp2 := Fingerprint("age1test456", []byte("pubkey2"))

	if fp1 == "" {
		t.Error("Fingerprint is empty")
	}
	if len(fp1) != FingerprintHexLen {
		t.Errorf("Fingerprint length = %d, want %d", len(fp1), FingerprintHexLen)
	}
	if fp1 == fp2 {
		t.Error("Different inputs produced same fingerprint")
	}

	// Same input should produce same fingerprint
	fp3 := Fingerprint("age1test123", []byte("pubkey1"))
	if fp1 != fp3 {
		t.Error("Same inputs produced different fingerprints")
	}
}
