package cloud

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Notification kinds. Shares come from the file-share inbox; the rest are
// derived from the contact/pending machinery (a friend request waiting, or a
// drain event applied).
const (
	NotifShare    = "share"
	NotifInvite   = "invite"
	NotifAccepted = "accepted"
	NotifRotated  = "rotated"
	NotifRevoked  = "revoked"
)

// notifCaps bound the persisted store.
const (
	maxNotifications = 200
	maxDismissed     = 500
)

// Notification is one drawer row. The library owns the model + lifecycle so
// every client (app, agent, third parties) renders the same thing. Presentation
// (icons, buttons, copy) is the client's; this is data only.
//
// State flags Seen and Retired are MONOTONIC (only ever flip true) and SYNC
// across devices via the CRDT merge. Content fields sync too. Handled ("this
// device already downloaded the share") is PER-DEVICE — each device downloads
// independently — so it is stripped from the synced blob and preserved locally.
type Notification struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`

	Seen    bool `json:"seen,omitempty"`    // synced (badge)
	Retired bool `json:"retired,omitempty"` // synced ("no longer available")
	Handled bool `json:"handled,omitempty"` // PER-DEVICE (stripped from the blob)

	// share content (synced)
	ShareID   string `json:"share_id,omitempty"`
	FileName  string `json:"file_name,omitempty"`
	FileSize  int64  `json:"file_size,omitempty"`
	Sender    string `json:"sender,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339, "" = never
	SingleUse bool   `json:"single_use,omitempty"`

	// invite / drain content (synced)
	Alias     string `json:"alias,omitempty"`
	RequestID string `json:"request_id,omitempty"`

	// RecipientFP is the per-device decrypt hint (which local identity a share
	// is sealed to). Never persisted on the item nor synced; the store keeps it
	// in a side map and List overlays it.
	RecipientFP string `json:"-"`
}

// notifData is the on-disk store: the visible items, the dismissed tombstones
// (removed rows the user won't see again — synced so a dismissal reflects
// everywhere), and the per-device decrypt hints.
type notifData struct {
	Items        []Notification    `json:"items"`
	Dismissed    []string          `json:"dismissed,omitempty"`
	RecipientFPs map[string]string `json:"recipient_fps,omitempty"`
}

// NotificationStore is the client-agnostic notification engine: a local,
// self-locking JSON store plus reconciliation against the server-authoritative
// sources (share inbox, pending inbox, drain reports) and zero-knowledge
// cross-device sync. Open it once per account (like SessionStore) on a private
// file path.
type NotificationStore struct {
	path string
	mu   sync.Mutex
}

// NewNotificationStore opens (lazily) the store at path. The file is created on
// first write.
func NewNotificationStore(path string) *NotificationStore {
	return &NotificationStore{path: path}
}

// DefaultNotificationStore places the store next to the other per-account cloud
// files, in dir.
func DefaultNotificationStore(dir string) *NotificationStore {
	return NewNotificationStore(filepath.Join(dir, "cloud_notifications.json"))
}

// --- persistence (mu held) --------------------------------------------------

func (s *NotificationStore) load() notifData {
	d := notifData{RecipientFPs: map[string]string{}}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return d
	}
	_ = json.Unmarshal(raw, &d)
	if d.RecipientFPs == nil {
		d.RecipientFPs = map[string]string{}
	}
	return d
}

func (s *NotificationStore) save(d notifData) error {
	if len(d.Items) > maxNotifications {
		d.Items = d.Items[:maxNotifications]
	}
	if len(d.Dismissed) > maxDismissed {
		d.Dismissed = d.Dismissed[len(d.Dismissed)-maxDismissed:]
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0600)
}

// --- query ------------------------------------------------------------------

// List returns the visible rows (dismissed rows excluded), newest first, with
// each share's per-device decrypt hint overlaid.
func (s *NotificationStore) List() []Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	out := make([]Notification, 0, len(d.Items))
	for _, n := range d.Items {
		if n.ShareID != "" {
			n.RecipientFP = d.RecipientFPs[n.ShareID]
		}
		out = append(out, n)
	}
	return out
}

// UnseenCount is the badge count.
func (s *NotificationStore) UnseenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	n := 0
	for _, it := range d.Items {
		if !it.Seen {
			n++
		}
	}
	return n
}

// RecipientFor returns the per-device decrypt hint for a share, if known.
func (s *NotificationStore) RecipientFor(shareID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load().RecipientFPs[shareID]
}

// --- mutations --------------------------------------------------------------

// MarkAllSeen clears the badge (drawer opened). Syncs.
func (s *NotificationStore) MarkAllSeen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	changed := false
	for i := range d.Items {
		if !d.Items[i].Seen {
			d.Items[i].Seen = true
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.save(d)
}

// Dismiss removes a row and tombstones its id so no re-poll (or another device)
// resurrects it. Syncs.
func (s *NotificationStore) Dismiss(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	kept := d.Items[:0]
	removed := false
	for _, n := range d.Items {
		if n.ID == id {
			removed = true
			continue
		}
		kept = append(kept, n)
	}
	d.Items = kept
	if !removed && contains(d.Dismissed, id) {
		return nil
	}
	if !contains(d.Dismissed, id) {
		d.Dismissed = append(d.Dismissed, id)
	}
	return s.save(d)
}

// MarkHandled records that THIS device downloaded the share (per-device — not
// synced). Also marks it seen.
func (s *NotificationStore) MarkHandled(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	changed := false
	for i := range d.Items {
		if d.Items[i].ID == id {
			d.Items[i].Handled = true
			d.Items[i].Seen = true
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.save(d)
}

// SeedSelfShare pre-seeds the sending device's drawer with a freshly uploaded
// self-share (pre-Seen, so the uploader gets no badge ping). Keyed identically
// to the inbox-derived row so the two never double up.
func (s *NotificationStore) SeedSelfShare(shareID, fileName string, size int64, expiresAt time.Time, singleUse bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	id := "share:" + shareID
	if contains(d.Dismissed, id) {
		return nil
	}
	for _, n := range d.Items {
		if n.ID == id {
			return nil
		}
	}
	expires := ""
	if !expiresAt.IsZero() {
		expires = expiresAt.Format(time.RFC3339)
	}
	d.Items = append([]Notification{{
		ID:        id,
		Kind:      NotifShare,
		Seen:      true,
		CreatedAt: time.Now().UTC(),
		ShareID:   shareID,
		FileName:  fileName,
		FileSize:  size,
		Sender:    "My devices",
		ExpiresAt: expires,
		SingleUse: singleUse,
	}}, d.Items...)
	return s.save(d)
}

// --- reconciliation with server-authoritative sources -----------------------

// ReconcileShares folds the live share inbox into the drawer: new shares become
// rows; a row whose share is gone from the inbox is RETIRED (kept as history,
// "no longer available", loses its Decrypt button) — the keep-and-reflect
// behavior. Dismissed shares are never re-added.
func (s *NotificationStore) ReconcileShares(inbox []ShareInboxItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	dismissed := set(d.Dismissed)
	have := map[string]bool{}
	for _, n := range d.Items {
		have[n.ID] = true
	}
	live := map[string]bool{}
	for _, it := range inbox {
		live[it.ShareID] = true
	}
	changed := false
	for i, n := range d.Items {
		if n.Kind == NotifShare && !n.Retired && !live[n.ShareID] {
			d.Items[i].Retired = true
			changed = true
		}
	}
	for _, it := range inbox {
		id := "share:" + it.ShareID
		if _, gone := dismissed[id]; gone || have[id] {
			continue
		}
		sender := it.SenderName
		if sender == "" {
			sender = it.SenderEmail
		}
		if sender == "" {
			sender = "someone"
		}
		if it.ToSelf {
			sender = "My devices"
		}
		expires := ""
		if !it.TTLExpiresAt.IsZero() {
			expires = it.TTLExpiresAt.Format(time.RFC3339)
		}
		d.Items = append(d.Items, Notification{
			ID:        id,
			Kind:      NotifShare,
			CreatedAt: it.CreatedAt,
			ShareID:   it.ShareID,
			FileName:  it.FileName,
			FileSize:  it.FileSize,
			Sender:    sender,
			ExpiresAt: expires,
			SingleUse: it.SingleUse,
		})
		d.RecipientFPs[it.ShareID] = it.RecipientFingerprint
		changed = true
	}
	if !changed {
		return nil
	}
	sortByCreated(d.Items)
	return s.save(d)
}

// ReconcilePending folds waiting contact requests into the drawer and returns
// the live invite count. Resolved requests (no longer pending) leave the drawer
// — an acceptance surfaces separately as a drain notice. Dismissed invites are
// never re-added.
func (s *NotificationStore) ReconcilePending(pending []PendingItem) (invites int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	dismissed := set(d.Dismissed)
	have := map[string]bool{}
	for _, n := range d.Items {
		have[n.ID] = true
	}
	stillPending := map[string]bool{}
	changed := false
	for _, it := range pending {
		if it.Kind != KindContactRequest {
			continue
		}
		invites++
		stillPending[it.ID] = true
		id := "invite:" + it.ID
		if _, gone := dismissed[id]; gone || have[id] {
			continue
		}
		d.Items = append(d.Items, Notification{
			ID:        id,
			Kind:      NotifInvite,
			CreatedAt: time.Now().UTC(),
			RequestID: it.ID,
		})
		changed = true
	}
	kept := d.Items[:0]
	for _, n := range d.Items {
		if n.Kind == NotifInvite && !stillPending[n.RequestID] {
			changed = true
			continue
		}
		kept = append(kept, n)
	}
	d.Items = kept
	if changed {
		sortByCreated(d.Items)
		if serr := s.save(d); serr != nil {
			return invites, serr
		}
	}
	return invites, nil
}

// ApplyDrainReport records applied contact-drain events (they accepted our
// request, or rotated/revoked a key) as drawer history.
func (s *NotificationStore) ApplyDrainReport(rep DrainReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	add := func(kind, alias string) {
		d.Items = append([]Notification{{
			ID:        "drain:" + uuid.NewString(),
			Kind:      kind,
			Alias:     alias,
			CreatedAt: time.Now().UTC(),
		}}, d.Items...)
	}
	for _, a := range rep.Accepted {
		add(NotifAccepted, a)
	}
	for _, a := range rep.Rotated {
		add(NotifRotated, a)
	}
	for _, a := range rep.Revoked {
		add(NotifRevoked, a)
	}
	if len(rep.Accepted)+len(rep.Rotated)+len(rep.Revoked) == 0 {
		return nil
	}
	return s.save(d)
}

// --- CRDT merge + zero-knowledge sync ---------------------------------------

// syncView is the subset that crosses the wire: items (Handled stripped — it is
// per-device) plus the dismissed tombstones. RecipientFPs stay local.
type syncView struct {
	Items     []Notification `json:"items"`
	Dismissed []string       `json:"dismissed,omitempty"`
}

// MergeNotifications converges two encoded notification blobs. It is
// commutative and idempotent: items union by ID, monotonic flags (Seen,
// Retired) OR together, content is taken from whichever side has it, dismissed
// tombstones union (and win — a dismissed row is dropped), and the result is
// capped by recency. Handled is not present in the blob (per-device).
func MergeNotifications(localBytes, remoteBytes []byte) ([]byte, error) {
	var a, b syncView
	if len(localBytes) > 0 {
		if err := json.Unmarshal(localBytes, &a); err != nil {
			return nil, err
		}
	}
	if len(remoteBytes) > 0 {
		if err := json.Unmarshal(remoteBytes, &b); err != nil {
			return nil, err
		}
	}
	dismissed := set(a.Dismissed)
	for _, id := range b.Dismissed {
		dismissed[id] = struct{}{}
	}

	byID := map[string]Notification{}
	order := []string{}
	merge := func(items []Notification) {
		for _, n := range items {
			if _, gone := dismissed[n.ID]; gone {
				continue
			}
			cur, ok := byID[n.ID]
			if !ok {
				byID[n.ID] = n
				order = append(order, n.ID)
				continue
			}
			byID[n.ID] = mergeRecord(cur, n)
		}
	}
	merge(a.Items)
	merge(b.Items)

	out := make([]Notification, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	sortByCreated(out)
	if len(out) > maxNotifications {
		out = out[:maxNotifications]
	}
	tomb := keys(dismissed)
	sort.Strings(tomb)
	if len(tomb) > maxDismissed {
		tomb = tomb[len(tomb)-maxDismissed:]
	}
	return json.Marshal(syncView{Items: out, Dismissed: tomb})
}

// mergeRecord converges two copies of the same notification: monotonic OR of the
// state flags, content from whichever has it, earliest CreatedAt.
func mergeRecord(a, b Notification) Notification {
	out := a
	out.Seen = a.Seen || b.Seen
	out.Retired = a.Retired || b.Retired
	if out.FileName == "" {
		out.FileName = b.FileName
	}
	if out.Sender == "" {
		out.Sender = b.Sender
	}
	if out.FileSize == 0 {
		out.FileSize = b.FileSize
	}
	if out.ExpiresAt == "" {
		out.ExpiresAt = b.ExpiresAt
	}
	if out.Alias == "" {
		out.Alias = b.Alias
	}
	if out.RequestID == "" {
		out.RequestID = b.RequestID
	}
	out.SingleUse = a.SingleUse || b.SingleUse
	if !b.CreatedAt.IsZero() && (out.CreatedAt.IsZero() || b.CreatedAt.Before(out.CreatedAt)) {
		out.CreatedAt = b.CreatedAt
	}
	return out
}

// Sync converges this device's notifications with the account's encrypted blob
// (zero-knowledge: sealed to the caller's own lock; the server sees ciphertext).
// Per-device Handled + RecipientFPs are preserved locally across the round trip.
// SealSource returns the exact plaintext bytes Sync seals to the cloud, so a
// re-key (cloud.RekeySelfLock) can reseal the notifications blob under a new
// identity byte-identically.
func (s *NotificationStore) SealSource() ([]byte, error) {
	s.mu.Lock()
	d := s.load()
	out, err := json.Marshal(syncView{Items: stripHandled(d.Items), Dismissed: d.Dismissed})
	s.mu.Unlock()
	return out, err
}

func (s *NotificationStore) Sync(ctx context.Context, c *Client, u SelfCrypter) error {
	s.mu.Lock()
	d := s.load()
	local, err := json.Marshal(syncView{Items: stripHandled(d.Items), Dismissed: d.Dismissed})
	s.mu.Unlock()
	if err != nil {
		return err
	}

	merged, err := c.SyncMergedBlob(ctx, u, "notifications", local, MergeNotifications)
	if err != nil {
		return err
	}

	var mv syncView
	if err := json.Unmarshal(merged, &mv); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.load() // reload: local edits may have landed during the round trip
	handled := map[string]bool{}
	for _, n := range cur.Items {
		if n.Handled {
			handled[n.ID] = true
		}
	}
	// Re-apply per-device Handled onto the converged items.
	for i := range mv.Items {
		if handled[mv.Items[i].ID] {
			mv.Items[i].Handled = true
		}
	}
	cur.Items = mv.Items
	cur.Dismissed = mv.Dismissed
	sortByCreated(cur.Items)
	return s.save(cur)
}

// --- helpers ----------------------------------------------------------------

func stripHandled(in []Notification) []Notification {
	out := make([]Notification, len(in))
	copy(out, in)
	for i := range out {
		out[i].Handled = false
	}
	return out
}

func sortByCreated(items []Notification) {
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func set(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
