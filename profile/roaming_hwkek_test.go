package profile_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/profile"
)

// memKeychain is an in-memory keystore.Keystore standing in for an OS
// keychain (or the Android Keystore adapter) in roaming tests.
type memKeychain struct {
	enc  map[string]string
	sign map[string][]byte
}

func newMemKeychain() *memKeychain {
	return &memKeychain{enc: map[string]string{}, sign: map[string][]byte{}}
}

func (m *memKeychain) StoreEncryptionIdentity(name, id string) error {
	m.enc[name] = id
	return nil
}

func (m *memKeychain) LoadEncryptionIdentity(name string) (string, error) {
	v, ok := m.enc[name]
	if !ok {
		return "", fmt.Errorf("no enc key for %q", name)
	}
	return v, nil
}

func (m *memKeychain) StoreSigningKey(name string, key []byte) error {
	m.sign[name] = key
	return nil
}

func (m *memKeychain) LoadSigningKey(name string) ([]byte, error) {
	v, ok := m.sign[name]
	if !ok {
		return nil, fmt.Errorf("no sign key for %q", name)
	}
	return v, nil
}

func (m *memKeychain) HasKeys(name string) bool {
	_, e := m.enc[name]
	_, s := m.sign[name]
	return e && s
}

func (m *memKeychain) Clear(name string) error {
	delete(m.enc, name)
	delete(m.sign, name)
	return nil
}

func (m *memKeychain) ListNames() ([]string, error) {
	names := []string{}
	for n := range m.enc {
		names = append(names, n)
	}
	return names, nil
}

// TestHWKEKConventionRoams reproduces the desktop-keychain → file-device HW
// roam: the ciphertext travels verbatim, so the imported index entry must
// keep the ORIGIN's KEK convention (empty passphrase) even though it now
// lives in the file backend.
func TestHWKEKConventionRoams(t *testing.T) {
	// --- origin device: keychain-backed HW identity -------------------------
	originDir := t.TempDir()
	originKeys := filepath.Join(originDir, "keys")
	if err := os.MkdirAll(originKeys, 0700); err != nil {
		t.Fatal(err)
	}
	kc := newMemKeychain()
	// The keychain holds the HW-decorated ciphertext (what the decorator
	// wrote); content is opaque to roaming.
	encCipher := []byte("hw-encrypted-enc-key-bytes")
	signCipher := []byte("hw-encrypted-sign-key-bytes")
	challenge := []byte("32-byte-hw-challenge-material...")
	if err := kc.StoreEncryptionIdentity("alice", string(encCipher)); err != nil {
		t.Fatal(err)
	}
	if err := kc.StoreSigningKey("alice", signCipher); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(originKeys, "alice.hwchallenge"), challenge, 0600); err != nil {
		t.Fatal(err)
	}

	// Origin index: legacy row (no explicit HWKEK) — convention inferred
	// from the keychain backend.
	originIdx := identity.IdentityIndex{Name: "alice", Backend: identity.BackendKeychain, HWKey: true}
	if got := originIdx.HWKEKConvention(); got != identity.HWKEKNone {
		t.Fatalf("keychain-backend inference: want %q, got %q", identity.HWKEKNone, got)
	}

	entry, err := profile.RoamingExportFn(originKeys, kc)(originIdx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if entry.Protection != profile.ProtectionHW {
		t.Fatalf("protection: %v", entry.Protection)
	}
	if entry.HWKEK != identity.HWKEKNone {
		t.Fatalf("exported HWKEK: want %q, got %q", identity.HWKEKNone, entry.HWKEK)
	}
	if !bytes.Equal(entry.Enc, encCipher) || !bytes.Equal(entry.Sign, signCipher) {
		t.Fatal("ciphertext must travel verbatim")
	}

	// --- destination device: file backend ----------------------------------
	destDir := t.TempDir()
	destKeys := filepath.Join(destDir, "keys")
	if err := os.MkdirAll(destKeys, 0700); err != nil {
		t.Fatal(err)
	}
	importFn := profile.RoamingImportFn(profile.RoamingImportOptions{
		KeysDir:     destKeys,
		DestBackend: identity.BackendFile,
	})
	backend, err := importFn("alice", entry)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if backend != identity.BackendFile {
		t.Fatalf("dest backend: %s", backend)
	}
	onDisk, err := os.ReadFile(filepath.Join(destKeys, "alice.enc"))
	if err != nil || !bytes.Equal(onDisk, encCipher) {
		t.Fatalf("imported ciphertext mismatch (err %v)", err)
	}

	// The index row a real import records (profile.ImportIdentitiesFromBytes
	// copies ManifestIdentity.HWKEK verbatim): file storage, origin KEK.
	destIdx := identity.IdentityIndex{Name: "alice", Backend: backend, HWKey: true, HWKEK: entry.HWKEK}
	if got := destIdx.HWKEKConvention(); got != identity.HWKEKNone {
		t.Fatalf("roamed convention: want %q (origin), got %q", identity.HWKEKNone, got)
	}

	// Contrast: a LEGACY import (no HWKEK field) would infer "passphrase"
	// from the file backend — the exact cross-device bug this fixes.
	legacyIdx := identity.IdentityIndex{Name: "alice", Backend: backend, HWKey: true}
	if got := legacyIdx.HWKEKConvention(); got != identity.HWKEKPassphrase {
		t.Fatalf("legacy inference: want %q, got %q", identity.HWKEKPassphrase, got)
	}
}

// TestFileOriginHWKEKRoams covers the reverse direction: a file-origin HW
// identity (session-passphrase KEK) keeps its convention when landing on a
// keychain device.
func TestFileOriginHWKEKRoams(t *testing.T) {
	originDir := t.TempDir()
	originKeys := filepath.Join(originDir, "keys")
	if err := os.MkdirAll(originKeys, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"bob.enc":         []byte("cipher-enc"),
		"bob.sign":        []byte("cipher-sign"),
		"bob.hwchallenge": []byte("challenge"),
	} {
		if err := os.WriteFile(filepath.Join(originKeys, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	originIdx := identity.IdentityIndex{Name: "bob", Backend: identity.BackendFile, HWKey: true}
	entry, err := profile.RoamingExportFn(originKeys, nil)(originIdx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if entry.HWKEK != identity.HWKEKPassphrase {
		t.Fatalf("exported HWKEK: want %q, got %q", identity.HWKEKPassphrase, entry.HWKEK)
	}

	// Keychain-destination import stores the ciphertext in the injected
	// keychain; the convention stays "passphrase".
	kc := newMemKeychain()
	importFn := profile.RoamingImportFn(profile.RoamingImportOptions{
		KeysDir:     t.TempDir(),
		DestBackend: identity.BackendKeychain,
		Keychain:    kc,
	})
	backend, err := importFn("bob", entry)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if backend != identity.BackendKeychain {
		t.Fatalf("dest backend: %s", backend)
	}
	if got, _ := kc.LoadEncryptionIdentity("bob"); got != "cipher-enc" {
		t.Fatalf("keychain ciphertext mismatch: %q", got)
	}
	destIdx := identity.IdentityIndex{Name: "bob", Backend: backend, HWKey: true, HWKEK: entry.HWKEK}
	if got := destIdx.HWKEKConvention(); got != identity.HWKEKPassphrase {
		t.Fatalf("roamed convention: want %q (origin), got %q", identity.HWKEKPassphrase, got)
	}
}
