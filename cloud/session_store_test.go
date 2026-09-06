package cloud

import (
	"errors"
	"testing"
	"time"
)

func testTokens() *Tokens {
	return &Tokens{
		AccessToken:      "access-abc",
		RefreshToken:     "refresh-xyz",
		ExpiresAt:        time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		RefreshExpiresAt: time.Now().Add(720 * time.Hour).UTC().Truncate(time.Second),
	}
}

func TestFileSessionStoreTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := DefaultSessionStore(dir, false, func() ([]byte, error) { return []byte("keystore-pass"), nil }, nil)

	if store.HasSession("alice@example.com") {
		t.Fatal("no session should exist yet")
	}
	tok := testTokens()
	if err := store.SaveTokens("alice@example.com", tok); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !store.HasSession("alice@example.com") {
		t.Fatal("HasSession should be true after save (without decrypting)")
	}
	got, err := store.LoadTokens("alice@example.com")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.AccessToken != tok.AccessToken || got.RefreshToken != tok.RefreshToken {
		t.Fatalf("token round-trip mismatch: %+v", got)
	}

	// Per-account isolation + signed-out sentinel.
	if _, err := store.LoadTokens("bob@example.com"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession for other account, got %v", err)
	}

	// Clear removes tokens (+ positions); idempotent.
	if err := store.Clear("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if store.HasSession("alice@example.com") {
		t.Fatal("session must be gone after clear")
	}
	if _, err := store.LoadTokens("alice@example.com"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession after clear, got %v", err)
	}
	if err := store.Clear("alice@example.com"); err != nil {
		t.Fatalf("clear must be idempotent: %v", err)
	}
}

func TestFileSessionStoreWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	saver := DefaultSessionStore(dir, false, func() ([]byte, error) { return []byte("right"), nil }, nil)
	if err := saver.SaveTokens("a@b.c", testTokens()); err != nil {
		t.Fatal(err)
	}
	loader := DefaultSessionStore(dir, false, func() ([]byte, error) { return []byte("wrong"), nil }, nil)
	// Wrong passphrase can't decrypt the tokens...
	if _, err := loader.LoadTokens("a@b.c"); err == nil {
		t.Fatal("wrong passphrase must fail to decrypt tokens")
	}
	// ...but HasSession is passphrase-free (checks presence, not contents).
	if !loader.HasSession("a@b.c") {
		t.Fatal("HasSession must not need the passphrase")
	}
}

func TestSessionStorePositionsAreNotSecret(t *testing.T) {
	dir := t.TempDir()
	// Deliberately give a failing passFn: positions must be readable WITHOUT it.
	store := DefaultSessionStore(dir, false, func() ([]byte, error) {
		return nil, errors.New("locked")
	}, nil)

	pos := SyncPositions{
		Versions:       map[string]int64{"settings": 7},
		Identities:     IdentitiesSyncState{Version: 3, Digest: "d3"},
		Contacts:       ContactsSyncState{Seq: 9, SnapshotVersion: 2},
		SettingsDigest: "sd",
	}
	if err := store.SavePositions("p@x.y", pos); err != nil {
		t.Fatalf("save positions: %v", err)
	}
	got, err := store.LoadPositions("p@x.y")
	if err != nil {
		t.Fatalf("load positions (must not need passphrase): %v", err)
	}
	if got.Versions["settings"] != 7 || got.Identities.Version != 3 ||
		got.Contacts.Seq != 9 || got.SettingsDigest != "sd" {
		t.Fatalf("positions round-trip mismatch: %+v", got)
	}
	// Missing positions load as an empty (non-nil map) value, not an error.
	empty, err := store.LoadPositions("nobody@x.y")
	if err != nil || empty.Versions == nil {
		t.Fatalf("missing positions should be empty, not error: %+v %v", empty, err)
	}
}

func TestClientSessionStoreAutoPersistAndRestore(t *testing.T) {
	dir := t.TempDir()
	store := DefaultSessionStore(dir, false, func() ([]byte, error) { return []byte("kp"), nil }, nil)

	// A client that "logs in": email + SetTokens should auto-persist.
	c, _ := New("http://localhost:0")
	c.SetSessionStore(store)
	c.SetAccountEmail("u@x.y")
	c.SetTokens(testTokens())
	if !store.HasSession("u@x.y") {
		t.Fatal("SetTokens with a store + email must persist the session")
	}

	// A fresh client restores without re-login.
	c2, _ := New("http://localhost:0")
	c2.SetSessionStore(store)
	if err := c2.RestoreSession("u@x.y"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if c2.Tokens() == nil || c2.Tokens().AccessToken != "access-abc" {
		t.Fatalf("restored tokens wrong: %+v", c2.Tokens())
	}

	// Restore for an unknown account is a clean signed-out signal.
	c3, _ := New("http://localhost:0")
	c3.SetSessionStore(store)
	if err := c3.RestoreSession("ghost@x.y"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession restoring unknown account, got %v", err)
	}
}
