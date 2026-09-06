package keystore

import (
	"testing"
)

// An encrypted-mode store must, by default, REFUSE to load a plaintext (non-age)
// key file — a downgraded/tampered key — rather than silently returning it.
func TestEncryptedStore_RejectsPlaintextByDefault(t *testing.T) {
	dir := t.TempDir()

	plain := NewFileStoreWithDir(dir)
	if err := plain.StoreEncryptionIdentity("test", "AGE-SECRET-KEY-PQ-1LEGACY"); err != nil {
		t.Fatalf("seed plaintext key: %v", err)
	}

	enc := NewEncryptedFileStoreWithDir(dir, func() ([]byte, error) { return []byte("pw"), nil })
	// No AllowPlaintextMigration() → must reject.
	if _, err := enc.LoadEncryptionIdentity("test"); err == nil {
		t.Fatal("encrypted-mode store loaded a plaintext key without opting into migration; want rejection")
	}
}
