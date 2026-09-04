//go:build integration

package cloud_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/profile"
)

// useDevice points the global icfx dirs at one simulated device's tree.
// Devices in these tests are sequential — swap before each device's turn.
func useDevice(dir string) {
	config.SetConfigDir(filepath.Join(dir, "config"))
	config.SetDataPath(filepath.Join(dir, "data"))
	config.SetKeyPath(filepath.Join(dir, "keys"))
}

func testContact(alias, email string) contacts.Contact {
	return contacts.Contact{
		Alias:       alias,
		Email:       email,
		EncPubKey:   "enc-" + alias,
		SignPubKey:  "sign-" + alias,
		Fingerprint: "fp-" + alias,
		AddedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func saveLocalContacts(t *testing.T, list []contacts.Contact) {
	t.Helper()
	store, err := contacts.NewStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(list); err != nil {
		t.Fatal(err)
	}
}

func loadLocalContacts(t *testing.T) map[string]contacts.Contact {
	t.Helper()
	store, err := contacts.NewStore()
	if err != nil {
		t.Fatal(err)
	}
	list, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]contacts.Contact{}
	for _, ct := range list {
		out[ct.Alias] = ct
	}
	return out
}

func syncContacts(t *testing.T, c *cloud.Client, u cloud.SelfCrypter, st *cloud.ContactsSyncState) cloud.SyncOutcome {
	t.Helper()
	state, err := c.FetchSyncState(context.Background())
	if err != nil {
		t.Fatalf("sync state: %v", err)
	}
	oc, err := cloud.SyncContactsOps(context.Background(), c, u, st, state)
	if err != nil {
		t.Fatalf("contacts sync: %v", err)
	}
	return oc
}

// TestContactsOpsTwoDeviceFlow drives the full op-log lifecycle: op-only
// pushes (no blob), pull-only convergence, add/add preservation (the
// conflict whole-blob LWW loses), delete tombstones, loop-death, forced
// compaction, and fresh-device bootstrap from snapshot + tail.
func TestContactsOpsTwoDeviceFlow(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	upgradeAccount(t, mustSignUp(t, c, randEmail(), validPW), "ultimate")
	crypter, _ := newCrypter(t)

	dirA, dirB := t.TempDir(), t.TempDir()
	var stA, stB cloud.ContactsSyncState

	// A adds two contacts → ops only, NO contacts blob upload.
	useDevice(dirA)
	saveLocalContacts(t, []contacts.Contact{testContact("alice", "a@x.io"), testContact("bob", "b@x.io")})
	oc := syncContacts(t, c, crypter, &stA)
	if oc.Action != cloud.SyncPushed || stA.Seq != 2 {
		t.Fatalf("A push: want pushed seq=2, got %+v st=%+v", oc, stA)
	}
	if _, err := c.GetBlob(ctx, "contacts"); !cloud.IsNotFound(err) {
		t.Fatalf("routine sync must NOT upload a contacts blob, got err=%v", err)
	}

	// B pulls the two ops.
	useDevice(dirB)
	oc = syncContacts(t, c, crypter, &stB)
	if oc.Action != cloud.SyncPulled || stB.Seq != 2 {
		t.Fatalf("B pull: want pulled seq=2, got %+v st=%+v", oc, stB)
	}
	got := loadLocalContacts(t)
	if len(got) != 2 || got["alice"].Email != "a@x.io" {
		t.Fatalf("B store mismatch: %+v", got)
	}

	// Loop-death: both devices immediately report up-to-date.
	if oc = syncContacts(t, c, crypter, &stB); oc.Action != cloud.SyncUpToDate {
		t.Fatalf("B resync: want up-to-date, got %+v", oc)
	}
	useDevice(dirA)
	if oc = syncContacts(t, c, crypter, &stA); oc.Action != cloud.SyncUpToDate {
		t.Fatalf("A resync: want up-to-date, got %+v", oc)
	}

	// Add/add: A adds carol, B adds dave, both keep both (whole-blob LWW
	// would silently drop one — the reason this engine exists).
	saveLocalContacts(t, []contacts.Contact{got["alice"], got["bob"], testContact("carol", "c@x.io")})
	syncContacts(t, c, crypter, &stA)
	useDevice(dirB)
	bList := loadLocalContacts(t)
	saveLocalContacts(t, []contacts.Contact{bList["alice"], bList["bob"], testContact("dave", "d@x.io")})
	syncContacts(t, c, crypter, &stB) // pulls carol, pushes dave
	useDevice(dirA)
	syncContacts(t, c, crypter, &stA) // pulls dave
	got = loadLocalContacts(t)
	if len(got) != 4 {
		t.Fatalf("add/add lost a contact: %+v", got)
	}

	// Edit + delete on B propagate to A.
	useDevice(dirB)
	bList = loadLocalContacts(t)
	edited := bList["alice"]
	edited.Email = "alice-new@x.io"
	saveLocalContacts(t, []contacts.Contact{edited, bList["carol"], bList["dave"]}) // bob deleted
	oc = syncContacts(t, c, crypter, &stB)
	if oc.Action != cloud.SyncPushed {
		t.Fatalf("B edit/del: want pushed, got %+v", oc)
	}
	useDevice(dirA)
	syncContacts(t, c, crypter, &stA)
	got = loadLocalContacts(t)
	if len(got) != 3 || got["alice"].Email != "alice-new@x.io" {
		t.Fatalf("A did not converge on edit+delete: %+v", got)
	}
	if _, ok := got["bob"]; ok {
		t.Fatal("tombstone did not delete bob on A")
	}

	// Forced compaction: threshold 1 → next pushing sync compacts.
	old := cloud.ContactsCompactThreshold
	cloud.ContactsCompactThreshold = 1
	defer func() { cloud.ContactsCompactThreshold = old }()

	saveLocalContacts(t, []contacts.Contact{got["alice"], got["carol"], got["dave"], testContact("erin", "e@x.io")})
	oc = syncContacts(t, c, crypter, &stA)
	if stA.SnapshotVersion == 0 {
		t.Fatalf("compaction did not run: %+v st=%+v", oc, stA)
	}
	state, err := c.FetchSyncState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b := state.Blob("contacts"); b.ThroughSeq != stA.Seq || b.Version != stA.SnapshotVersion {
		t.Fatalf("snapshot meta mismatch: %+v vs st=%+v", b, stA)
	}
	// The compacting device stays loop-dead afterwards.
	if oc = syncContacts(t, c, crypter, &stA); oc.Action != cloud.SyncUpToDate {
		t.Fatalf("A post-compact: want up-to-date, got %+v", oc)
	}

	// Fresh device C bootstraps from the snapshot (+ empty tail).
	dirC := t.TempDir()
	useDevice(dirC)
	var stC cloud.ContactsSyncState
	oc = syncContacts(t, c, crypter, &stC)
	if oc.Action != cloud.SyncPulled {
		t.Fatalf("C bootstrap: want pulled, got %+v", oc)
	}
	got = loadLocalContacts(t)
	if len(got) != 4 || got["erin"].Email != "e@x.io" {
		t.Fatalf("C bootstrap mismatch: %+v", got)
	}

	// B is behind the truncation point → snapshot rebase, then converges.
	useDevice(dirB)
	oc = syncContacts(t, c, crypter, &stB)
	got = loadLocalContacts(t)
	if len(got) != 4 {
		t.Fatalf("B rebase mismatch (%s): %+v", oc.Action, got)
	}
}

// TestShadowClearOnAccountSwitch is the session-boundary regression: after
// syncing with account A, logging out and into account B must re-upload the
// full local contact set. The shadow says "the server already has these" —
// true only for A's server-side state — so the logout path MUST clear it
// (cloud.RemoveContactsShadow); without that, B receives nothing, silently.
func TestShadowClearOnAccountSwitch(t *testing.T) {
	crypter, _ := newCrypter(t)
	useDevice(t.TempDir())

	// Account A syncs two contacts.
	a, _ := cloud.New(baseURL())
	upgradeAccount(t, mustSignUp(t, a, randEmail(), validPW), "ultimate")
	saveLocalContacts(t, []contacts.Contact{testContact("alice", "a@x.io"), testContact("bob", "b@x.io")})
	var stA cloud.ContactsSyncState
	if oc := syncContacts(t, a, crypter, &stA); oc.Action != cloud.SyncPushed {
		t.Fatalf("A: want pushed, got %+v", oc)
	}

	// "Logout": what every session-clearing path now does.
	if err := cloud.RemoveContactsShadow(); err != nil {
		t.Fatalf("remove shadow: %v", err)
	}

	// Account B on the same device: the full local set must push again.
	b, _ := cloud.New(baseURL())
	upgradeAccount(t, mustSignUp(t, b, randEmail(), validPW), "ultimate")
	var stB cloud.ContactsSyncState
	if oc := syncContacts(t, b, crypter, &stB); stB.Seq != 2 {
		t.Fatalf("B must receive both contacts as ops (got seq=%d, action=%s) — shadow leak suppressed the upload", stB.Seq, oc.Action)
	}
}

// TestSyncIdentitiesStateful proves the feedback loop is dead: an unchanged
// device does nothing, a pull-only pass does NOT push back, and only real
// local changes push.
func TestSyncIdentitiesStateful(t *testing.T) {
	useDevice(t.TempDir()) // empty identity set is fine for the decision table

	ctx := context.Background()
	email := randEmail()
	a, _ := cloud.New(baseURL())
	upgradeAccount(t, mustSignUp(t, a, email, validPW), "ultimate")

	exportFn := func(idx identity.IdentityIndex) (profile.RoamingEntry, error) {
		return profile.RoamingEntry{}, nil
	}
	importFn := func(name string, e profile.RoamingEntry) (string, error) {
		return "file", nil
	}

	var st cloud.IdentitiesSyncState
	fetch := func() cloud.ServerBlobMeta {
		s, err := a.FetchSyncState(ctx)
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		return s.Blob("identities")
	}

	// First sync: nothing in the cloud → pushed-new.
	action, err := cloud.SyncIdentities(ctx, a, exportFn, importFn, &st, fetch(), nil)
	if err != nil || action != cloud.SyncPushedNew {
		t.Fatalf("want pushed-new, got %q err=%v", action, err)
	}
	if st.Version == 0 || st.Digest == "" {
		t.Fatalf("state not recorded: %+v", st)
	}

	// Unchanged both sides → up-to-date, and the version must not move
	// (an up-to-date pass that pushed would bump it — the old loop).
	before := fetch()
	action, err = cloud.SyncIdentities(ctx, a, exportFn, importFn, &st, before, nil)
	if err != nil || action != cloud.SyncUpToDate {
		t.Fatalf("want up-to-date, got %q err=%v", action, err)
	}
	if after := fetch(); after.Version != before.Version {
		t.Fatalf("up-to-date pass moved the version %d→%d — loop not dead", before.Version, after.Version)
	}

	// Remote moves (another device pushes) → pull only, NO push-back.
	if err := a.PushIdentities(ctx, exportFn); err != nil {
		t.Fatalf("simulate other device: %v", err)
	}
	moved := fetch()
	if moved.Version == before.Version {
		t.Fatal("test setup: version should have moved")
	}
	action, err = cloud.SyncIdentities(ctx, a, exportFn, importFn, &st, moved, nil)
	if err != nil || action != cloud.SyncPulled {
		t.Fatalf("want pulled, got %q err=%v", action, err)
	}
	if after := fetch(); after.Version != moved.Version {
		t.Fatalf("pull-only pass pushed back (%d→%d) — ping-pong lives", moved.Version, after.Version)
	}
	if st.Version != moved.Version {
		t.Fatalf("state version not recorded: %+v", st)
	}

	// And now it's quiet again.
	action, err = cloud.SyncIdentities(ctx, a, exportFn, importFn, &st, fetch(), nil)
	if err != nil || action != cloud.SyncUpToDate {
		t.Fatalf("want up-to-date after pull, got %q err=%v", action, err)
	}
}

// TestContactsSyncCapGate: the plan's contact limit is enforced at the
// cloud boundary — the server can't count ciphertext contacts, so a local
// set larger than the plan hard-blocks the contacts leg with a clear error
// until trimmed (or the plan upgraded). Free tier caps at 2.
func TestContactsSyncCapGate(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	mustSignUp(t, c, randEmail(), validPW) // stays free: MaxContacts = 2
	crypter, _ := newCrypter(t)
	useDevice(t.TempDir())
	var st cloud.ContactsSyncState

	saveLocalContacts(t, []contacts.Contact{
		testContact("a", "a@x.io"), testContact("b", "b@x.io"), testContact("c", "c@x.io"),
	})
	state, err := c.FetchSyncState(ctx)
	if err != nil {
		t.Fatalf("sync state: %v", err)
	}
	_, err = cloud.SyncContactsOps(ctx, c, crypter, &st, state)
	if err == nil || !strings.Contains(err.Error(), "exceeds your plan's limit") {
		t.Fatalf("want contact-cap error, got %v", err)
	}

	// Trim to the cap → the same account syncs fine.
	saveLocalContacts(t, []contacts.Contact{testContact("a", "a@x.io"), testContact("b", "b@x.io")})
	oc := syncContacts(t, c, crypter, &st)
	if oc.Action != cloud.SyncPushed {
		t.Fatalf("post-trim sync: %+v", oc)
	}
}
