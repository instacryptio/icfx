package cloud

import (
	"errors"
	"testing"
)

func TestFileEncKeyStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewFileEncKeyStore(dir, func() (string, error) { return "keystore-pass", nil })

	key := []byte("0123456789abcdef0123456789abcdef")
	if err := store.Save("alice@example.com", key); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.Load("alice@example.com")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != string(key) {
		t.Fatal("round-trip mismatch")
	}

	// Per-account isolation: another email misses.
	if _, err := store.Load("bob@example.com"); !errors.Is(err, ErrEncKeyMissing) {
		t.Fatalf("want ErrEncKeyMissing for other account, got %v", err)
	}

	// Clear removes; second clear is a no-op.
	if err := store.Clear("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("alice@example.com"); !errors.Is(err, ErrEncKeyMissing) {
		t.Fatalf("want ErrEncKeyMissing after clear, got %v", err)
	}
	if err := store.Clear("alice@example.com"); err != nil {
		t.Fatalf("clear must be idempotent: %v", err)
	}
}

func TestFileEncKeyStoreWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	saver := NewFileEncKeyStore(dir, func() (string, error) { return "right-pass", nil })
	if err := saver.Save("a@b.c", []byte("secret-key-material")); err != nil {
		t.Fatal(err)
	}
	loader := NewFileEncKeyStore(dir, func() (string, error) { return "wrong-pass", nil })
	if _, err := loader.Load("a@b.c"); err == nil {
		t.Fatal("wrong passphrase must fail to decrypt")
	}
}

// fakeStore records Save/Clear calls for the SDK-hook tests.
type fakeStore struct {
	saved   map[string][]byte
	cleared []string
}

func (f *fakeStore) Save(email string, key []byte) error {
	if f.saved == nil {
		f.saved = map[string][]byte{}
	}
	f.saved[email] = append([]byte(nil), key...)
	return nil
}

func (f *fakeStore) Load(email string) ([]byte, error) {
	k, ok := f.saved[email]
	if !ok {
		return nil, ErrEncKeyMissing
	}
	return k, nil
}

func (f *fakeStore) Clear(email string) error {
	f.cleared = append(f.cleared, email)
	delete(f.saved, email)
	return nil
}

func TestClientEncKeyStoreResolution(t *testing.T) {
	c, _ := New("http://localhost:0")
	store := &fakeStore{}
	c.SetEncKeyStore(store)

	// No email set → missing.
	if _, _, err := c.sessionOrStoredEncKey(); !errors.Is(err, ErrEncKeyMissing) {
		t.Fatalf("want missing without email, got %v", err)
	}

	// Email + stored key → resolved fromStore.
	c.SetAccountEmail("x@y.z")
	_ = store.Save("x@y.z", []byte("stored-key"))
	key, fromStore, err := c.sessionOrStoredEncKey()
	if err != nil || !fromStore || string(key) != "stored-key" {
		t.Fatalf("stored resolution wrong: key=%q fromStore=%v err=%v", key, fromStore, err)
	}

	// In-memory session key wins over the store.
	c.setAuthState("x@y.z", []byte("session-key"))
	key, fromStore, err = c.sessionOrStoredEncKey()
	if err != nil || fromStore || string(key) != "session-key" {
		t.Fatalf("session resolution wrong: key=%q fromStore=%v err=%v", key, fromStore, err)
	}

	// persistEncKey saves the session key through the store.
	c.persistEncKey()
	if string(store.saved["x@y.z"]) != "session-key" {
		t.Fatalf("persist did not save session key: %q", store.saved["x@y.z"])
	}

	// clearStoredEncKey wipes it.
	c.clearStoredEncKey()
	if len(store.saved) != 0 || len(store.cleared) != 1 {
		t.Fatalf("clear not propagated: %+v", store)
	}
}
