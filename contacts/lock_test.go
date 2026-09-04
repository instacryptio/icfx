package contacts

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// TestSaveFromLock_RejectsHostileLabels covers F1: the labels are NOT covered by
// the self-signature, so SaveFromLock must reject control/oversized labels at
// ingest even though the lock's signature verifies.
func TestSaveFromLock_RejectsHostileLabels(t *testing.T) {
	store := NewStoreWithPath(filepath.Join(t.TempDir(), "contacts.json"))

	lb := sealedLB(t, "eve")
	lb.Alias = "eve\x1b[2K\rlogin:" // ANSI + CR terminal-spoof
	if _, _, err := SaveFromLock(store, lb); err == nil {
		t.Fatal("SaveFromLock must reject a control-char alias")
	}

	lb2 := sealedLB(t, "eve2")
	lb2.Alias = strings.Repeat("a", 100) // over the 32-char alias bound
	if _, _, err := SaveFromLock(store, lb2); err == nil {
		t.Fatal("SaveFromLock must reject an oversized alias")
	}

	if list, _ := store.Load(); len(list) != 0 {
		t.Fatalf("no hostile contact should have been stored, got %d", len(list))
	}
}

// TestSaveFromLock_NormalizesAlias covers F1: a non-conforming published alias
// (spaces/case) is not used as the contact's selector — it falls back to the
// display name — while a conforming one is lowercased and kept.
func TestSaveFromLock_NormalizesAlias(t *testing.T) {
	store := NewStoreWithPath(filepath.Join(t.TempDir(), "contacts.json"))

	// Non-conforming alias (spaces) → falls back to Name.
	spaced := sealedLB(t, "Eve Display")
	spaced.Alias = "eve the great"
	alias, _, err := SaveFromLock(store, spaced)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if alias != "Eve Display" {
		t.Fatalf("non-conforming alias must fall back to Name, got %q", alias)
	}

	// Conforming (uppercase) alias → lowercased and used.
	conf := sealedLB(t, "Frank Display")
	conf.Alias = "FRANK"
	alias, _, err = SaveFromLock(store, conf)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if alias != "frank" {
		t.Fatalf("conforming alias must be lowercased+used, got %q", alias)
	}
}

// rawSigner signs with a raw ML-DSA-65 private key (test helper).
type rawSigner struct{ key []byte }

func (r rawSigner) Sign(data []byte) ([]byte, error) { return crypto.Sign(data, r.key) }

// sealedLB builds a real, self-signed lock bundle for a fresh identity. A
// fixed fingerprint can no longer be forced — it is bound to the keys — so
// callers that need distinct identities just pass distinct names.
func sealedLB(t *testing.T, name string) qr.LockBundle {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	lb := qr.LockBundle{
		ID:          "ic-" + name,
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
		Email:       name + "@x.io",
	}
	sealed, err := qr.SealLock(rawSigner{kp.SigningPrivateKey}, lb)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

func TestSaveFromLock(t *testing.T) {
	store := NewStoreWithPath(filepath.Join(t.TempDir(), "contacts.json"))

	alice := sealedLB(t, "alice")

	// New contact → alias from the bundle name; marked as a cloud contact.
	alias, updated, err := SaveFromLock(store, alice)
	if err != nil || updated || alias != "alice" {
		t.Fatalf("add: alias=%q updated=%v err=%v", alias, updated, err)
	}
	list, _ := store.Load()
	if len(list) != 1 || !list[0].Cloud {
		t.Fatalf("cloud flag must be set: %+v", list)
	}

	// Same identity again with an edited label → update in place, alias kept.
	// Email is NOT covered by the self-sig, so the original Sig still verifies.
	upd := alice
	upd.Email = "alice-new@x.io"
	alias, updated, err = SaveFromLock(store, upd)
	if err != nil || !updated || alias != "alice" {
		t.Fatalf("update: alias=%q updated=%v err=%v", alias, updated, err)
	}
	list, _ = store.Load()
	if len(list) != 1 || list[0].Email != "alice-new@x.io" {
		t.Fatalf("update must be in place: %+v", list)
	}

	// A DIFFERENT identity that happens to share the alias "alice" → suffixed.
	other := sealedLB(t, "alice")
	alias, updated, err = SaveFromLock(store, other)
	if err != nil || updated {
		t.Fatalf("collision add: updated=%v err=%v", updated, err)
	}
	if alias == "alice" {
		t.Fatalf("alias collision must be suffixed, got %q", alias)
	}
	list, _ = store.Load()
	if len(list) != 2 {
		t.Fatalf("want 2 contacts, got %d", len(list))
	}

	// An unsigned lock is rejected outright.
	unsigned := sealedLB(t, "bob")
	unsigned.Sig = ""
	if _, _, err := SaveFromLock(store, unsigned); err == nil {
		t.Fatal("unsigned lock must be rejected")
	}
}

// TestSaveFromLock_AliasFromPublisher_NicknamePreserved covers the swapped
// semantics: Contact.Alias is the PUBLISHER's self-set handle (from the lock),
// while Contact.Nickname is the user's LOCAL shortcut — never populated or
// overwritten by a lock.
func TestSaveFromLock_AliasFromPublisher_NicknamePreserved(t *testing.T) {
	store := NewStoreWithPath(filepath.Join(t.TempDir(), "contacts.json"))

	// Publisher has a real alias; Name differs. Alias isn't signed, so setting
	// it on the sealed bundle keeps the self-sig valid.
	lock := sealedLB(t, "Alice Full Name")
	lock.Alias = "icalice"

	alias, updated, err := SaveFromLock(store, lock)
	if err != nil || updated {
		t.Fatalf("add: updated=%v err=%v", updated, err)
	}
	if alias != "icalice" {
		t.Fatalf("contact alias must come from the publisher's alias, got %q", alias)
	}
	list, _ := store.Load()
	if list[0].Nickname != "" {
		t.Fatalf("nickname must start empty (local shortcut), got %q", list[0].Nickname)
	}

	// The user assigns a local shortcut.
	list[0].Nickname = "al"
	if err := store.Save(list); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Their alias changes and the lock is re-imported → alias refreshes, but the
	// user's local nickname is preserved.
	lock.Alias = "icalice2"
	if _, updated, err = SaveFromLock(store, lock); err != nil || !updated {
		t.Fatalf("update: updated=%v err=%v", updated, err)
	}
	list, _ = store.Load()
	if list[0].Alias != "icalice2" {
		t.Fatalf("alias must refresh from lock, got %q", list[0].Alias)
	}
	if list[0].Nickname != "al" {
		t.Fatalf("local nickname must be preserved, got %q", list[0].Nickname)
	}
}
