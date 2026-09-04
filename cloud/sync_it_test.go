//go:build integration

package cloud_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/profile"
)

// memResourceIO is an in-memory ResourceIO so the engine's three-way logic is
// exercised against a real server without touching real config/contact stores.
type memResourceIO struct{ data map[string][]byte }

func (m *memResourceIO) Load(resource string) ([]byte, error) {
	b, ok := m.data[resource]
	if !ok {
		return nil, fmt.Errorf("unknown resource %q", resource)
	}
	return b, nil
}

func (m *memResourceIO) Apply(resource string, data []byte) error {
	m.data[resource] = append([]byte(nil), data...)
	return nil
}

// TestSyncEngine drives the shared engine through the push-new / up-to-date /
// push / adopt-cloud paths with two "devices" on one account.
func TestSyncEngine(t *testing.T) {
	ctx := context.Background()
	deviceA, _ := cloud.New(baseURL())
	mustSignUp(t, deviceA, randEmail(), validPW)
	crypter, _ := newCrypter(t)

	ioA := &memResourceIO{data: map[string][]byte{"contacts": []byte(`["a1"]`)}}
	versA := map[string]int64{}

	// First sync on A → pushed (new).
	oc, err := cloud.SyncResource(ctx, deviceA, crypter, "contacts", ioA, versA)
	if err != nil {
		t.Fatalf("push-new: %v", err)
	}
	if oc.Action != cloud.SyncPushedNew || oc.Version != 1 {
		t.Fatalf("want pushed-new v1, got %+v", oc)
	}

	// Unchanged → up to date.
	oc, err = cloud.SyncResource(ctx, deviceA, crypter, "contacts", ioA, versA)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Action != cloud.SyncUpToDate {
		t.Fatalf("want up-to-date, got %+v", oc)
	}

	// Device B (same account/session, fresh state) → adopts the cloud copy.
	// Same crypter: blobs are sealed to the account holder's identity lock.
	ioB := &memResourceIO{data: map[string][]byte{"contacts": []byte(`[]`)}}
	versB := map[string]int64{}
	oc, err = cloud.SyncResource(ctx, deviceA, crypter, "contacts", ioB, versB)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Action != cloud.SyncPulled || oc.CloudWasNewer {
		t.Fatalf("want pulled (first sync, no baseline warning), got %+v", oc)
	}
	if string(ioB.data["contacts"]) != `["a1"]` {
		t.Fatalf("B did not adopt cloud copy: %s", ioB.data["contacts"])
	}

	// Local change on A → pushed.
	ioA.data["contacts"] = []byte(`["a1","a2"]`)
	oc, err = cloud.SyncResource(ctx, deviceA, crypter, "contacts", ioA, versA)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Action != cloud.SyncPushed || oc.Version != 2 {
		t.Fatalf("want pushed v2, got %+v", oc)
	}

	// B changed locally too, but cloud moved past B's baseline → cloud wins
	// (last-writer-wins MVP) and the overwrite is flagged.
	ioB.data["contacts"] = []byte(`["b-local"]`)
	oc, err = cloud.SyncResource(ctx, deviceA, crypter, "contacts", ioB, versB)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Action != cloud.SyncPulled || !oc.CloudWasNewer {
		t.Fatalf("want pulled with cloud-was-newer, got %+v", oc)
	}
	if string(ioB.data["contacts"]) != `["a1","a2"]` {
		t.Fatalf("B did not adopt newer cloud copy: %s", ioB.data["contacts"])
	}
	if versB["contacts"] != 2 {
		t.Fatalf("B version not advanced: %d", versB["contacts"])
	}
}

// TestEncKeyStoreAcrossClients proves identities sync works from a NEW client
// holding only tokens + the persisted encKey (no password re-entry), and that
// a stale stored key (password changed elsewhere) surfaces ErrEncKeyStale.
func TestEncKeyStoreAcrossClients(t *testing.T) {
	// Isolate identity index/config so export/import see an empty device.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	ctx := context.Background()
	email := randEmail()
	store := &memEncKeyStore{}

	// Client A: fresh signup with the store wired → key persisted.
	a, _ := cloud.New(baseURL())
	a.SetEncKeyStore(store)
	mustSignUp(t, a, email, validPW)
	if _, err := store.Load(email); err != nil {
		t.Fatalf("signup did not persist encKey: %v", err)
	}
	// Seed the identities blob (empty device export is fine).
	if err := a.PushIdentities(ctx, func(idx identity.IdentityIndex) (profile.RoamingEntry, error) {
		return profile.RoamingEntry{}, fmt.Errorf("no identities on test device")
	}); err != nil {
		t.Fatalf("seed push: %v", err)
	}

	// Client B: tokens + email + store ONLY — no password, no in-memory key.
	b, _ := cloud.New(baseURL())
	b.SetTokens(a.Tokens())
	b.SetAccountEmail(email)
	b.SetEncKeyStore(store)
	if b.HasEncryptionKey() {
		t.Fatal("client B must not hold an in-memory key")
	}
	if err := b.PullIdentities(ctx, func(name string, e profile.RoamingEntry) (string, error) {
		return "file", nil
	}); err != nil {
		t.Fatalf("pull with stored key failed: %v", err)
	}

	// Stale key: replace the stored key with a wrong-but-valid one.
	_ = store.Save(email, []byte("0123456789abcdef0123456789abcdef"))
	c, _ := cloud.New(baseURL())
	c.SetTokens(a.Tokens())
	c.SetAccountEmail(email)
	c.SetEncKeyStore(store)
	err := c.PullIdentities(ctx, func(name string, e profile.RoamingEntry) (string, error) {
		return "file", nil
	})
	if !errors.Is(err, cloud.ErrEncKeyStale) {
		t.Fatalf("want ErrEncKeyStale with wrong stored key, got %v", err)
	}
}

// memEncKeyStore is an in-memory EncKeyStore for integration tests.
type memEncKeyStore struct{ m map[string][]byte }

func (s *memEncKeyStore) Save(email string, key []byte) error {
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[email] = append([]byte(nil), key...)
	return nil
}

func (s *memEncKeyStore) Load(email string) ([]byte, error) {
	k, ok := s.m[email]
	if !ok {
		return nil, cloud.ErrEncKeyMissing
	}
	return k, nil
}

func (s *memEncKeyStore) Clear(email string) error {
	delete(s.m, email)
	return nil
}
