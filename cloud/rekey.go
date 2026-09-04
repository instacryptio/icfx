package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/instacryptio/icfx/groups"
)

// ErrNoLocalToRecover is returned by the reseal helpers when the cloud copy of a
// self-lock resource exists but this device holds no authoritative local data to
// re-seal from (an empty/default source — e.g. a freshly imported identity with
// no contacts yet). Re-sealing would OVERWRITE the good cloud copy with nothing,
// so we refuse: runSelfLock maps it to a non-destructive "recover from the device
// that has the original data" outcome, and the re-key orchestrators skip the
// resource rather than fail the whole run.
var ErrNoLocalToRecover = errors.New("cloud: no local copy to recover this resource from on this device")

// localSourceHasData reports whether the local plaintext for a self-lock resource
// carries real user data — the authoritative-copy test that gates destructive
// recovery. Contacts/groups/notifications are "empty" when they hold no entries,
// so an empty local source must never overwrite a populated cloud copy. Settings
// are NOT guarded: they have no empty state (every device holds a complete, valid
// value), so re-sealing them is a legitimate low-stakes LWW write, and guarding
// them would leave default-valued settings sealed to an old key permanently
// unrecoverable (no device would ever present "non-default" settings to recover
// from). An unparseable source is treated as data (never block on doubt).
func localSourceHasData(name string, local []byte) bool {
	switch name {
	case "contacts":
		var list []json.RawMessage
		if json.Unmarshal(local, &list) != nil {
			return true
		}
		return len(list) > 0
	case "groups":
		var g struct {
			Groups  []json.RawMessage `json:"groups"`
			Deleted []string          `json:"deleted"`
		}
		if json.Unmarshal(local, &g) != nil {
			return true
		}
		return len(g.Groups) > 0 || len(g.Deleted) > 0
	case "notifications":
		var n struct {
			Items     []json.RawMessage `json:"items"`
			Dismissed []string          `json:"dismissed"`
		}
		if json.Unmarshal(local, &n) != nil {
			return true
		}
		return len(n.Items) > 0 || len(n.Dismissed) > 0
	}
	return true // settings + anything else: always resealable (no empty state)
}

// RekeySelfLock re-seals every self-lock cloud resource (settings, groups,
// notifications, contacts) to newU, sourcing each from intact LOCAL plaintext —
// the only source that still works when the OLD default's key is already gone
// (we cannot decrypt the old cloud copy under a mismatch; we only read its
// server version as the optimistic-concurrency token). Used by the
// delete/set-default/rotate orchestrators and, per resource, by the runSelfLock
// recovery hook. gstore/nstore may be nil for a host that doesn't sync that
// resource; io may be nil to skip settings + contacts.
func RekeySelfLock(ctx context.Context, c *Client, newU SelfCrypter, io ResourceIO, gstore *groups.Store, nstore *NotificationStore, st *SyncPositions) error {
	if st.Versions == nil {
		st.Versions = map[string]int64{}
	}
	state, err := c.FetchSyncState(ctx)
	if err != nil {
		return fmt.Errorf("fetch sync state: %w", err)
	}

	// A resource this device has no local data for is skipped (not fatal): the
	// guard leaves its cloud copy sealed to the old key rather than wiping it —
	// safer than aborting the whole re-key. Another device that HAS the data
	// recovers it later.
	skip := func(err error) error {
		if errors.Is(err, ErrNoLocalToRecover) {
			return nil
		}
		return err
	}
	// Settings has no empty state, so (unlike the other resources) it can't be
	// content-guarded against a fresh device overwriting the cloud copy with its
	// defaults. Gate it on "this device has synced settings before"
	// (SettingsDigest) — the same authoritative-copy signal canRecoverLocally
	// uses — so a create/import re-key never clobbers another device's settings.
	if io != nil && st.SettingsDigest != "" {
		if err := skip(resealFromLocal(ctx, c, newU, "settings", func() ([]byte, error) { return io.Load("settings") }, state, st.Versions)); err != nil {
			return err
		}
	}
	if gstore != nil {
		if err := skip(resealFromLocal(ctx, c, newU, "groups", gstore.SyncBytes, state, st.Versions)); err != nil {
			return err
		}
	}
	if nstore != nil {
		if err := skip(resealFromLocal(ctx, c, newU, "notifications", nstore.SealSource, state, st.Versions)); err != nil {
			return err
		}
	}
	if io != nil {
		if err := skip(resealContacts(ctx, c, newU, io, state, st)); err != nil {
			return err
		}
	}
	return nil
}

// RekeyDefaultSelfLock loads this device's persisted sync positions, re-keys
// every self-lock resource to newU, and persists the updated positions. It is
// the convenience entrypoint the identity hand-off / rotation orchestrators use
// (they hold no session state of their own). gstore/nstore may be nil.
func (c *Client) RekeyDefaultSelfLock(ctx context.Context, newU SelfCrypter, io ResourceIO, gstore *groups.Store, nstore *NotificationStore) error {
	if c.sessionStore == nil {
		var pos SyncPositions
		return RekeySelfLock(ctx, c, newU, io, gstore, nstore, &pos)
	}
	pos, err := c.sessionStore.LoadPositions(c.email)
	if err != nil {
		return fmt.Errorf("load sync positions: %w", err)
	}
	if err := RekeySelfLock(ctx, c, newU, io, gstore, nstore, &pos); err != nil {
		return err
	}
	return c.sessionStore.SavePositions(c.email, pos)
}

// resealFromLocal reseals a single-blob self-lock resource from its local
// plaintext under u, at the resource's current server version.
func resealFromLocal(ctx context.Context, c *Client, u SelfCrypter, name string, load func() ([]byte, error), state ServerSyncState, versions map[string]int64) error {
	local, err := load()
	if err != nil {
		return fmt.Errorf("load local %q: %w", name, err)
	}
	return resealBlob(ctx, c, u, name, local, state.Blob(name).Version, versions)
}

// resealBlob force-overwrites a self-lock blob with plaintext sealed to u,
// retrying on optimistic-concurrency conflict by re-reading the current version.
// Shared by RekeySelfLock and the runSelfLock recovery hook.
func resealBlob(ctx context.Context, c *Client, u SelfCrypter, name string, plaintext []byte, curVersion int64, versions map[string]int64) error {
	for attempt := 0; attempt < mergeBlobMaxAttempts; attempt++ {
		// Data-loss guard: an existing cloud blob must never be overwritten with an
		// empty/default local source (see ErrNoLocalToRecover). Re-checked each
		// attempt because a conflict re-read below can reveal a blob that another
		// device just created (curVersion 0 → N) — we must not clobber it either.
		if curVersion > 0 && !localSourceHasData(name, plaintext) {
			return ErrNoLocalToRecover
		}
		res, err := c.SealBlob(ctx, u, name, plaintext, curVersion)
		if err == nil {
			if versions != nil {
				versions[name] = res.Version
			}
			return nil
		}
		if IsConflict(err) {
			b, gerr := c.GetBlob(ctx, name)
			if IsNotFound(gerr) {
				curVersion = 0
				continue
			}
			if gerr != nil {
				return fmt.Errorf("reseal %q: re-read version: %w", name, gerr)
			}
			curVersion = b.Version
			continue
		}
		return fmt.Errorf("reseal %q: %w", name, err)
	}
	return fmt.Errorf("reseal %q: too many version conflicts", name)
}

// resealContacts recompacts the contacts op-log under the new key: it seals a
// fresh snapshot from the local contacts list (same JSON shape compactContacts
// produces) and truncates EVERY op sealed to the old key (throughSeq = server
// MaxSeq), then resets the device's contacts sync state so it doesn't re-fetch
// the now-gone ops. Force-overwrites, retrying if another device compacts in
// between.
func resealContacts(ctx context.Context, c *Client, u SelfCrypter, io ResourceIO, state ServerSyncState, st *SyncPositions) error {
	local, err := io.Load("contacts") // json.Marshal([]contacts.Contact) — matches compactContacts
	if err != nil {
		return fmt.Errorf("load local contacts: %w", err)
	}
	for attempt := 0; attempt < mergeBlobMaxAttempts; attempt++ {
		// Data-loss guard: never truncate the server op-log + overwrite the snapshot
		// with an empty local list when the cloud actually holds contacts (see
		// ErrNoLocalToRecover). This is the most destructive reseal — CompactOps
		// drops every op — so it must never run from a device without the data.
		// Re-checked each attempt because the conflict re-fetch below can reveal
		// contacts another device just wrote.
		if (state.Blob("contacts").Version > 0 || state.MaxSeq("contacts") > 0) && !localSourceHasData("contacts", local) {
			return ErrNoLocalToRecover
		}
		ct, serr := u.EncryptToSelf(local)
		if serr != nil {
			return fmt.Errorf("seal contacts snapshot: %w", serr)
		}
		// throughSeq is the op-log head captured at pass start (state). We do NOT
		// re-fetch it to a later head: seq-based truncation can't distinguish
		// old-key ops from concurrent NEW-key ops another device just appended, so
		// truncating through a newer head could drop good contacts. Old-key ops
		// only outlive this seq if a device is still appending under the superseded
		// key — which can't happen once that identity is deleted/rotated away.
		throughSeq := state.MaxSeq("contacts")
		ver, cerr := c.CompactOps(ctx, "contacts", ct, throughSeq, state.Blob("contacts").Version)
		if cerr == nil {
			st.Contacts.Seq = throughSeq
			st.Contacts.SnapshotVersion = ver
			if rerr := RemoveContactsShadow(); rerr != nil {
				return fmt.Errorf("clearing contacts shadow: %w", rerr)
			}
			return nil
		}
		if IsConflict(cerr) {
			// Another device compacted between our FetchSyncState and now —
			// re-read and retry so our reseal (to the new key) still lands.
			state, err = c.FetchSyncState(ctx)
			if err != nil {
				return fmt.Errorf("contacts recompact re-fetch: %w", err)
			}
			continue
		}
		return fmt.Errorf("recompact contacts: %w", cerr)
	}
	return fmt.Errorf("recompact contacts: too many version conflicts")
}
