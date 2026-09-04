package cloud

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeView(t *testing.T, b []byte) syncView {
	t.Helper()
	var v syncView
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func viewByID(v syncView) map[string]Notification {
	m := map[string]Notification{}
	for _, n := range v.Items {
		m[n.ID] = n
	}
	return m
}

func TestMergeMonotonicAndDismissed(t *testing.T) {
	t0 := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	local := mustJSON(t, syncView{Items: []Notification{
		{ID: "share:a", Kind: NotifShare, CreatedAt: t0, FileName: "a.txt"},
		{ID: "share:b", Kind: NotifShare, CreatedAt: t0, Seen: true},
	}})
	remote := mustJSON(t, syncView{
		Items: []Notification{
			{ID: "share:a", Kind: NotifShare, CreatedAt: t0, Seen: true, Retired: true}, // flags flipped elsewhere
		},
		Dismissed: []string{"share:b"}, // dismissed on the other device
	})

	merged, err := MergeNotifications(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	v := decodeView(t, merged)
	m := viewByID(v)

	if _, ok := m["share:b"]; ok {
		t.Fatal("dismissed item must not survive the merge")
	}
	a, ok := m["share:a"]
	if !ok {
		t.Fatal("share:a should survive")
	}
	if !a.Seen || !a.Retired {
		t.Fatalf("monotonic flags must OR to true: %+v", a)
	}
	if a.FileName != "a.txt" {
		t.Fatalf("content should be kept: %+v", a)
	}
	if !contains(v.Dismissed, "share:b") {
		t.Fatal("dismissed tombstone must be retained")
	}
}

func TestMergeCommutative(t *testing.T) {
	t0 := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	a := mustJSON(t, syncView{
		Items:     []Notification{{ID: "x", Kind: NotifShare, CreatedAt: t0, Seen: true}},
		Dismissed: []string{"y"},
	})
	b := mustJSON(t, syncView{
		Items:     []Notification{{ID: "y", Kind: NotifShare, CreatedAt: t0}, {ID: "z", Kind: NotifInvite, CreatedAt: t0}},
		Dismissed: []string{"x"},
	})

	ab, err := MergeNotifications(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := MergeNotifications(b, a)
	if err != nil {
		t.Fatal(err)
	}
	// Both x and y are dismissed by one side → only z survives, both orders.
	for _, merged := range [][]byte{ab, ba} {
		m := viewByID(decodeView(t, merged))
		if len(m) != 1 {
			t.Fatalf("want only z surviving, got %d: %+v", len(m), m)
		}
		if _, ok := m["z"]; !ok {
			t.Fatalf("z must survive: %+v", m)
		}
	}
}

func TestMergeIdempotent(t *testing.T) {
	t0 := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	v := mustJSON(t, syncView{Items: []Notification{{ID: "x", Kind: NotifShare, CreatedAt: t0, Seen: true}}})
	once, err := MergeNotifications(v, v)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := MergeNotifications(once, once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("merge not idempotent:\n%s\n%s", once, twice)
	}
}

func newStore(t *testing.T) *NotificationStore {
	t.Helper()
	return NewNotificationStore(filepath.Join(t.TempDir(), "cloud_notifications.json"))
}

func TestReconcileSharesAddRetireDismiss(t *testing.T) {
	s := newStore(t)
	t0 := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	inbox := []ShareInboxItem{
		{ShareID: "abc", FileName: "secret.txt", FileSize: 10, CreatedAt: t0, SenderName: "Bob", RecipientFingerprint: "fp1"},
	}
	if err := s.ReconcileShares(inbox); err != nil {
		t.Fatal(err)
	}
	list := s.List()
	if len(list) != 1 || list[0].ID != "share:abc" || list[0].Sender != "Bob" || list[0].Retired {
		t.Fatalf("want one live Bob share, got %+v", list)
	}
	if s.RecipientFor("abc") != "fp1" {
		t.Fatalf("recipient hint not stored")
	}

	// Share leaves the inbox → retired, kept.
	if err := s.ReconcileShares(nil); err != nil {
		t.Fatal(err)
	}
	list = s.List()
	if len(list) != 1 || !list[0].Retired {
		t.Fatalf("gone share must be retired+kept, got %+v", list)
	}

	// Dismiss → gone + tombstoned → not re-added even if it reappears.
	if err := s.Dismiss("share:abc"); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("dismissed share must not list")
	}
	if err := s.ReconcileShares(inbox); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("dismissed share must stay gone after re-poll, got %+v", s.List())
	}
}

func TestSeedSelfShareSeenAndHandled(t *testing.T) {
	s := newStore(t)
	if err := s.SeedSelfShare("xyz", "vault.txt", 42, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	list := s.List()
	if len(list) != 1 || list[0].ID != "share:xyz" || !list[0].Seen || list[0].Sender != "My devices" {
		t.Fatalf("self-share seed wrong: %+v", list)
	}
	if s.UnseenCount() != 0 {
		t.Fatalf("self-share must be pre-seen (no badge), got %d", s.UnseenCount())
	}
	if err := s.MarkHandled("share:xyz"); err != nil {
		t.Fatal(err)
	}
	if !s.List()[0].Handled {
		t.Fatal("MarkHandled did not stick")
	}
}

func TestReconcilePendingAddPruneCount(t *testing.T) {
	s := newStore(t)
	pending := []PendingItem{
		{ID: "r1", Kind: KindContactRequest},
		{ID: "r2", Kind: KindContactRequest},
		{ID: "x", Kind: "other"},
	}
	invites, err := s.ReconcilePending(pending)
	if err != nil {
		t.Fatal(err)
	}
	if invites != 2 {
		t.Fatalf("want 2 invites, got %d", invites)
	}
	if len(s.List()) != 2 {
		t.Fatalf("want 2 invite rows, got %+v", s.List())
	}
	// r1 resolved → prune it.
	invites, err = s.ReconcilePending([]PendingItem{{ID: "r2", Kind: KindContactRequest}})
	if err != nil {
		t.Fatal(err)
	}
	if invites != 1 || len(s.List()) != 1 || s.List()[0].RequestID != "r2" {
		t.Fatalf("want only r2 left, got invites=%d %+v", invites, s.List())
	}
}

func TestSyncStripsHandledFromBlob(t *testing.T) {
	s := newStore(t)
	if err := s.SeedSelfShare("h", "f", 1, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkHandled("share:h"); err != nil {
		t.Fatal(err)
	}
	d := s.load()
	blob := mustJSON(t, syncView{Items: stripHandled(d.Items), Dismissed: d.Dismissed})
	v := decodeView(t, blob)
	if len(v.Items) != 1 || v.Items[0].Handled {
		t.Fatalf("Handled must be stripped from the synced blob: %+v", v.Items)
	}
	// Local still has Handled.
	if !s.List()[0].Handled {
		t.Fatal("local Handled must be preserved")
	}
}
