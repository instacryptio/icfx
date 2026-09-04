package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	fs := NewEncryptedFileStoreWithDir(dir, func() (string, error) {
		return passphrase, nil
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
	wrongFS := NewEncryptedFileStoreWithDir(dir, func() (string, error) {
		return "wrong-passphrase", nil
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
	encFS := NewEncryptedFileStoreWithDir(dir, func() (string, error) {
		return "some-passphrase", nil
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
