package cloud

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/instacryptio/icfx/contacts"
)

func mkContact(alias, email string) contacts.Contact {
	return contacts.Contact{
		Alias:       alias,
		Email:       email,
		EncPubKey:   "enc-" + alias,
		SignPubKey:  "sign-" + alias,
		Fingerprint: "fp-" + alias,
		AddedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestDiffContactsGeneratesOps(t *testing.T) {
	alice := mkContact("alice", "a@x.io")
	bob := mkContact("bob", "b@x.io")
	carol := mkContact("carol", "c@x.io")
	bobEdited := bob
	bobEdited.Email = "bob-new@x.io"

	// shadow: alice+bob; live: bob(edited)+carol → put bob, put carol, del alice.
	ops := diffContacts(
		[]contacts.Contact{alice, bob},
		[]contacts.Contact{bobEdited, carol},
	)
	if len(ops) != 3 {
		t.Fatalf("want 3 ops, got %d: %+v", len(ops), ops)
	}
	byID := map[string]ContactOp{}
	for _, op := range ops {
		byID[op.ID] = op
	}
	if byID["alice"].Op != "del" {
		t.Fatalf("alice: want del, got %+v", byID["alice"])
	}
	if byID["bob"].Op != "put" || byID["carol"].Op != "put" {
		t.Fatalf("want puts for bob+carol: %+v", byID)
	}
	var round contacts.Contact
	if err := json.Unmarshal(byID["bob"].Contact, &round); err != nil {
		t.Fatal(err)
	}
	if round.Email != "bob-new@x.io" {
		t.Fatalf("bob put must carry the edit, got %q", round.Email)
	}
}

func TestDiffContactsEmptyWhenUnchanged(t *testing.T) {
	set := []contacts.Contact{mkContact("alice", "a@x.io"), mkContact("bob", "b@x.io")}
	if ops := diffContacts(set, set); len(ops) != 0 {
		t.Fatalf("identical sets must produce no ops, got %+v", ops)
	}
}

// identityCrypter is a no-op SelfCrypter for unit tests: "ciphertext" is the
// plaintext op JSON, so tests can build Ops without real encryption.
type identityCrypter struct{}

func (identityCrypter) EncryptToSelf(p []byte) ([]byte, error) { return p, nil }
func (identityCrypter) Decrypt(c []byte) ([]byte, error)       { return c, nil }

func opFor(t *testing.T, seq int64, cop ContactOp) Op {
	t.Helper()
	raw, err := json.Marshal(cop)
	if err != nil {
		t.Fatal(err)
	}
	return Op{Seq: seq, Ciphertext: raw}
}

// TestApplyGapOps covers the race-gap merge: ops that landed between this
// device's fetch and append are applied only if seq < firstSeq and their id
// wasn't just written locally (skip) — our higher-seq write must win.
func TestApplyGapOps(t *testing.T) {
	putRaw, _ := json.Marshal(mkContact("bob", "b@x.io"))
	base := contactsByID([]contacts.Contact{mkContact("alice", "a@x.io")})

	gap := []Op{
		opFor(t, 2, ContactOp{Op: "put", ID: "bob", Contact: putRaw}),    // applied
		opFor(t, 3, ContactOp{Op: "put", ID: "alice", Contact: putRaw}),  // skipped: locally touched
		opFor(t, 5, ContactOp{Op: "put", ID: "future", Contact: putRaw}), // skipped: seq >= firstSeq
	}
	touched := map[string]bool{"alice": true}

	if err := applyGapOps(identityCrypter{}, base, gap, 5, touched); err != nil {
		t.Fatalf("applyGapOps: %v", err)
	}
	if _, ok := base["bob"]; !ok {
		t.Fatal("gap op (seq 2) must be applied")
	}
	if base["alice"].Email != "a@x.io" {
		t.Fatal("touched id must keep the local version, not the gap op")
	}
	if _, ok := base["future"]; ok {
		t.Fatal("op with seq >= firstSeq must not be applied (it's our own append)")
	}
}

func TestApplyPlainOpLWW(t *testing.T) {
	base := contactsByID([]contacts.Contact{mkContact("alice", "a@x.io")})

	// Later put overrides.
	edited := mkContact("alice", "alice-2@x.io")
	raw, _ := json.Marshal(edited)
	applyPlainOp(base, ContactOp{Op: "put", ID: "alice", Contact: raw})
	if base["alice"].Email != "alice-2@x.io" {
		t.Fatalf("put must overwrite, got %q", base["alice"].Email)
	}

	// Tombstone wins over the earlier put.
	applyPlainOp(base, ContactOp{Op: "del", ID: "alice"})
	if _, ok := base["alice"]; ok {
		t.Fatal("del must remove the contact")
	}

	// A put after the del resurrects (LWW by order).
	applyPlainOp(base, ContactOp{Op: "put", ID: "alice", Contact: raw})
	if _, ok := base["alice"]; !ok {
		t.Fatal("put after del must re-add")
	}

	// Malformed put is skipped, not fatal.
	applyPlainOp(base, ContactOp{Op: "put", ID: "alice", Contact: []byte("{broken")})
	if base["alice"].Email != "alice-2@x.io" {
		t.Fatal("malformed op must leave the entry untouched")
	}
}

func TestContactsSortedDeterministic(t *testing.T) {
	m := contactsByID([]contacts.Contact{
		mkContact("zed", "z@x.io"), mkContact("alice", "a@x.io"), mkContact("mia", "m@x.io"),
	})
	got := contactsSorted(m)
	want := []string{"alice", "mia", "zed"}
	for i, ct := range got {
		if ct.Alias != want[i] {
			t.Fatalf("order mismatch at %d: got %q want %q", i, ct.Alias, want[i])
		}
	}
}

func TestContactsActionTable(t *testing.T) {
	cases := []struct {
		boot           bool
		pulled, pushed int
		want           string
	}{
		{false, 0, 0, SyncUpToDate},
		{false, 2, 0, SyncPulled},
		{true, 0, 0, SyncPulled},
		{false, 0, 3, SyncPushed},
		{false, 1, 1, SyncSynced},
		{true, 0, 1, SyncSynced},
	}
	for _, tc := range cases {
		if got := contactsAction(tc.boot, tc.pulled, tc.pushed); got != tc.want {
			t.Errorf("contactsAction(%v,%d,%d) = %q, want %q", tc.boot, tc.pulled, tc.pushed, got, tc.want)
		}
	}
}
