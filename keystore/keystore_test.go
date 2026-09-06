package keystore

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/instacryptio/icfx/crypto"
)

func TestFileStore(t *testing.T) {
	dir, err := os.MkdirTemp("", "icfx-keystore-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fs := NewFileStoreWithDir(dir)

	// Store and load encryption identity
	if err := fs.StoreEncryptionIdentity("test", "AGE-SECRET-KEY-PQ-1TEST123"); err != nil {
		t.Fatalf("StoreEncryptionIdentity error: %v", err)
	}

	encID, err := fs.LoadEncryptionIdentity("test")
	if err != nil {
		t.Fatalf("LoadEncryptionIdentity error: %v", err)
	}
	if encID != "AGE-SECRET-KEY-PQ-1TEST123" {
		t.Errorf("LoadEncryptionIdentity = %q, want AGE-SECRET-KEY-PQ-1TEST123", encID)
	}

	// Store and load signing key
	sigKey := []byte("test-signing-key-bytes")
	if err := fs.StoreSigningKey("test", sigKey); err != nil {
		t.Fatalf("StoreSigningKey error: %v", err)
	}

	loaded, err := fs.LoadSigningKey("test")
	if err != nil {
		t.Fatalf("LoadSigningKey error: %v", err)
	}
	if string(loaded) != string(sigKey) {
		t.Errorf("LoadSigningKey mismatch")
	}

	// HasKeys
	if !fs.HasKeys("test") {
		t.Error("HasKeys(test) = false, want true")
	}
	if fs.HasKeys("nonexistent") {
		t.Error("HasKeys(nonexistent) = true, want false")
	}

	// ListNames
	names, err := fs.ListNames()
	if err != nil {
		t.Fatalf("ListNames error: %v", err)
	}
	if len(names) != 1 || names[0] != "test" {
		t.Errorf("ListNames = %v, want [test]", names)
	}

	// Clear
	if err := fs.Clear("test"); err != nil {
		t.Fatalf("Clear error: %v", err)
	}
	if fs.HasKeys("test") {
		t.Error("HasKeys(test) after Clear = true")
	}
}

func TestEncryptedFileStore(t *testing.T) {
	dir, err := os.MkdirTemp("", "icfx-encrypted-keystore-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	passphrase := "test-passphrase-123"
	fs := NewEncryptedFileStoreWithDir(dir, func() ([]byte, error) {
		return []byte(passphrase), nil
	})

	// Store and load encryption identity
	if err := fs.StoreEncryptionIdentity("test", "AGE-SECRET-KEY-PQ-1TEST123"); err != nil {
		t.Fatalf("StoreEncryptionIdentity error: %v", err)
	}

	encID, err := fs.LoadEncryptionIdentity("test")
	if err != nil {
		t.Fatalf("LoadEncryptionIdentity error: %v", err)
	}
	if encID != "AGE-SECRET-KEY-PQ-1TEST123" {
		t.Errorf("LoadEncryptionIdentity = %q, want AGE-SECRET-KEY-PQ-1TEST123", encID)
	}

	// Store and load signing key
	sigKey := []byte("test-signing-key-bytes")
	if err := fs.StoreSigningKey("test", sigKey); err != nil {
		t.Fatalf("StoreSigningKey error: %v", err)
	}

	loaded, err := fs.LoadSigningKey("test")
	if err != nil {
		t.Fatalf("LoadSigningKey error: %v", err)
	}
	if string(loaded) != string(sigKey) {
		t.Errorf("LoadSigningKey mismatch")
	}

	// Verify on-disk bytes are NOT plaintext
	encData, err := os.ReadFile(filepath.Join(dir, "test.enc"))
	if err != nil {
		t.Fatalf("reading enc file: %v", err)
	}
	if strings.Contains(string(encData), "AGE-SECRET-KEY-PQ-1TEST123") {
		t.Error("on-disk .enc file contains plaintext secret key")
	}
	if !isAgeEncrypted(encData) {
		t.Error("on-disk .enc file is not age-encrypted")
	}

	signData, err := os.ReadFile(filepath.Join(dir, "test.sign"))
	if err != nil {
		t.Fatalf("reading sign file: %v", err)
	}
	if !isAgeEncrypted(signData) {
		t.Error("on-disk .sign file is not age-encrypted")
	}

	// Verify wrong passphrase fails
	wrongFS := NewEncryptedFileStoreWithDir(dir, func() ([]byte, error) {
		return []byte("wrong-passphrase"), nil
	})
	_, err = wrongFS.LoadEncryptionIdentity("test")
	if err == nil {
		t.Error("LoadEncryptionIdentity with wrong passphrase should fail")
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Errorf("error should mention wrong passphrase, got: %v", err)
	}
}

func TestEncryptedFileStoreMigration(t *testing.T) {
	dir, err := os.MkdirTemp("", "icfx-migration-keystore-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Write with plaintext store
	plainFS := NewFileStoreWithDir(dir)
	if err := plainFS.StoreEncryptionIdentity("test", "AGE-SECRET-KEY-PQ-1LEGACY"); err != nil {
		t.Fatalf("StoreEncryptionIdentity error: %v", err)
	}
	if err := plainFS.StoreSigningKey("test", []byte("legacy-signing-key")); err != nil {
		t.Fatalf("StoreSigningKey error: %v", err)
	}

	// Read with encrypted store — should handle plaintext files gracefully when
	// the caller opts into migration (default is to reject a plaintext key).
	encFS := NewEncryptedFileStoreWithDir(dir, func() ([]byte, error) {
		return []byte("some-passphrase"), nil
	})
	encFS.AllowPlaintextMigration()

	encID, err := encFS.LoadEncryptionIdentity("test")
	if err != nil {
		t.Fatalf("LoadEncryptionIdentity (migration) error: %v", err)
	}
	if encID != "AGE-SECRET-KEY-PQ-1LEGACY" {
		t.Errorf("LoadEncryptionIdentity = %q, want AGE-SECRET-KEY-PQ-1LEGACY", encID)
	}

	sigKey, err := encFS.LoadSigningKey("test")
	if err != nil {
		t.Fatalf("LoadSigningKey (migration) error: %v", err)
	}
	if string(sigKey) != "legacy-signing-key" {
		t.Errorf("LoadSigningKey mismatch after migration")
	}
}

// TestEncryptedFileStoreByteCallbackBackwardCompat pins the S0 invariant: the
// switch from a string PassphraseFunc to a []byte one did NOT change the
// on-disk format. A key file written by the pre-migration string API
// (crypto.EncryptWithPassphrase) must still decrypt through the current
// []byte-based FileStore given the same passphrase. If this ever fails, every
// keystore written by an older build has become unreadable.
func TestEncryptedFileStoreByteCallbackBackwardCompat(t *testing.T) {
	dir := t.TempDir()
	const pass = "legacy-passphrase-123"
	const secret = "AGE-SECRET-KEY-PQ-1LEGACY"
	signKey := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}

	// Synthesize the exact bytes the old string-based keystore wrote to disk:
	//   .enc  = Encrypt(identityString)
	//   .sign = Encrypt(base64(signingKey))
	oldEnc, err := crypto.EncryptWithPassphrase([]byte(secret), pass)
	if err != nil {
		t.Fatalf("legacy .enc encrypt: %v", err)
	}
	oldSign, err := crypto.EncryptWithPassphrase([]byte(base64.StdEncoding.EncodeToString(signKey)), pass)
	if err != nil {
		t.Fatalf("legacy .sign encrypt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "legacy.enc"), oldEnc, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "legacy.sign"), oldSign, 0600); err != nil {
		t.Fatal(err)
	}

	// The current []byte-callback store must read both back unchanged.
	fs := NewEncryptedFileStoreWithDir(dir, func() ([]byte, error) { return []byte(pass), nil })

	gotID, err := fs.LoadEncryptionIdentity("legacy")
	if err != nil {
		t.Fatalf("new store failed to load legacy-format .enc: %v", err)
	}
	if gotID != secret {
		t.Fatalf("decrypted encryption identity %q, want %q", gotID, secret)
	}

	gotSign, err := fs.LoadSigningKey("legacy")
	if err != nil {
		t.Fatalf("new store failed to load legacy-format .sign: %v", err)
	}
	if !bytes.Equal(gotSign, signKey) {
		t.Fatalf("decrypted signing key %x, want %x", gotSign, signKey)
	}
}
