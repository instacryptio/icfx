package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
)

// Contacts sync via the encrypted op-log. Instead of shipping the whole
// contacts blob on every change, each pass transfers only per-contact ops
// (put/del), giving O(change) bandwidth and — the real win — per-contact
// last-writer-wins with tombstones: two devices adding different contacts
// concurrently BOTH keep their adds, and a delete can't be resurrected by a
// stale snapshot. The snapshot blob remains only as a bootstrap/compaction
// artifact.
//
// The engine keeps a local SHADOW copy of the contact set as of the last
// sync (contacts_shadow.json beside the contact store). Diffing the live
// store against the shadow is how local edits become ops without hooking
// every mutation site.

// ContactsSyncState is the persisted op-log position for this device: the
// last op seq applied/appended and the snapshot blob version last seen.
type ContactsSyncState struct {
	Seq             int64 `json:"seq"`
	SnapshotVersion int64 `json:"snapshot_version"`
}

// ContactsCompactThreshold is the op-log length (beyond the snapshot's
// through-seq) at which the syncing device uploads a fresh snapshot and
// truncates the log. Tunable; the default suits contact-sized ops.
var ContactsCompactThreshold int64 = 200

// SyncContactsOps performs one contacts sync pass against the op log.
// remote is the account's FetchSyncState result (fetched once per sync run,
// shared across resources). st is updated in place; the caller persists it.
func SyncContactsOps(ctx context.Context, c *Client, u SelfCrypter, st *ContactsSyncState, remote ServerSyncState) (SyncOutcome, error) {
	store, err := contacts.NewStore()
	if err != nil {
		return SyncOutcome{}, err
	}
	local, err := store.Load()
	if err != nil {
		return SyncOutcome{}, err
	}

	// Tier gate: contacts are ciphertext server-side (zero-knowledge — the
	// server can never count them), so the plan's contact limit is enforced
	// HERE, at the cloud boundary. Local contacts stay unlimited; a set
	// larger than the plan simply doesn't sync until trimmed or upgraded.
	plan, err := c.GetPlan(ctx)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("checking plan: %w", err)
	}
	if plan.Limits.MaxContacts > 0 && len(local) > plan.Limits.MaxContacts {
		return SyncOutcome{}, fmt.Errorf(
			"contact sync blocked: %d contacts exceeds your plan's limit of %d — remove contacts or upgrade",
			len(local), plan.Limits.MaxContacts)
	}

	shadow, hasShadow, err := loadContactsShadow()
	if err != nil {
		return SyncOutcome{}, err
	}

	localOps := diffContacts(shadow, local)
	snap := remote.Blob("contacts")
	maxSeq := remote.MaxSeq("contacts")

	// Idle path: nothing moved on either side → done. One tiny GET (already
	// made by the caller), zero downloads, zero crypto.
	if snap.Version == st.SnapshotVersion && maxSeq == st.Seq && len(localOps) == 0 && hasShadow {
		return SyncOutcome{Resource: "contacts", Action: SyncUpToDate, Version: snap.Version}, nil
	}

	// Working set: the last-synced state, then remote ops, then local edits.
	base := contactsByID(shadow)

	// Bootstrap/rebase: the snapshot version moved (someone compacted) or
	// this device has never synced. A device whose seq already covers the
	// snapshot's through-seq holds everything the snapshot contains — it
	// records the version WITHOUT downloading. Only a fresh device (no
	// shadow) or one behind the truncation point pulls the blob.
	bootstrapped := false
	if snap.Version != st.SnapshotVersion || !hasShadow {
		if snap.Version != 0 && (!hasShadow || st.Seq < snap.ThroughSeq) {
			plain, _, oerr := c.OpenBlob(ctx, u, "contacts")
			if oerr != nil {
				return SyncOutcome{}, fmt.Errorf("contacts snapshot: %w", oerr)
			}
			var snapList []contacts.Contact
			if uerr := json.Unmarshal(plain, &snapList); uerr != nil {
				return SyncOutcome{}, fmt.Errorf("parsing contacts snapshot: %w", uerr)
			}
			base = contactsByID(snapList)
			st.Seq = snap.ThroughSeq
			bootstrapped = true
		}
		st.SnapshotVersion = snap.Version
	}

	// Pull: fetch ops after our seq, decrypt, apply in order (LWW by seq).
	pulledOps := 0
	if maxSeq > st.Seq {
		ops, ferr := c.FetchOpsSince(ctx, "contacts", st.Seq)
		if ferr != nil {
			return SyncOutcome{}, ferr
		}
		for _, op := range ops {
			if aerr := applyContactOp(u, base, op); aerr != nil {
				return SyncOutcome{}, aerr
			}
			st.Seq = op.Seq
		}
		pulledOps = len(ops)
	}

	// Local edits win this round: they're appended AFTER everything we just
	// applied, so every other device converges to them by the same LWW rule.
	touched := make(map[string]bool, len(localOps))
	for _, op := range localOps {
		touched[op.ID] = true
		applyPlainOp(base, op)
	}

	// Push: encrypt + append the local ops.
	if len(localOps) > 0 {
		encrypted := make([][]byte, len(localOps))
		for i, op := range localOps {
			plain, merr := json.Marshal(op)
			if merr != nil {
				return SyncOutcome{}, merr
			}
			ct, eerr := u.EncryptToSelf(plain)
			if eerr != nil {
				return SyncOutcome{}, fmt.Errorf("sealing contact op: %w", eerr)
			}
			encrypted[i] = ct
		}
		res, aerr := c.AppendOps(ctx, "contacts", encrypted)
		if aerr != nil {
			return SyncOutcome{}, aerr
		}
		// Ops landed between our fetch and our append (another device raced
		// us): pick them up now so this device doesn't skip them forever.
		// Ids we just wrote keep our version — our ops carry the higher seq.
		if res.FirstSeq > st.Seq+1 {
			gap, gerr := c.FetchOpsSince(ctx, "contacts", st.Seq)
			if gerr != nil {
				return SyncOutcome{}, gerr
			}
			if aerr := applyGapOps(u, base, gap, res.FirstSeq, touched); aerr != nil {
				return SyncOutcome{}, aerr
			}
		}
		st.Seq = res.LastSeq
	}

	// Persist the converged set as both the live store and the new shadow.
	merged := contactsSorted(base)
	if err := store.Save(merged); err != nil {
		return SyncOutcome{}, err
	}
	if err := saveContactsShadow(merged); err != nil {
		return SyncOutcome{}, err
	}

	// Compaction: when the tail past the snapshot grows long, upload a full
	// snapshot and truncate. A conflict means another device compacted first
	// — fine, the next pass picks up its version.
	if st.Seq-snap.ThroughSeq > ContactsCompactThreshold {
		if cerr := compactContacts(ctx, c, u, st, merged); cerr != nil {
			return SyncOutcome{}, cerr
		}
	}

	return SyncOutcome{Resource: "contacts", Action: contactsAction(bootstrapped, pulledOps, len(localOps)), Version: st.SnapshotVersion}, nil
}

func contactsAction(bootstrapped bool, pulled, pushed int) string {
	switch {
	case (bootstrapped || pulled > 0) && pushed > 0:
		return SyncSynced
	case pushed > 0:
		return SyncPushed
	case bootstrapped || pulled > 0:
		return SyncPulled
	default:
		// Only bookkeeping moved (shadow created / version recorded).
		return SyncUpToDate
	}
}

func compactContacts(ctx context.Context, c *Client, u SelfCrypter, st *ContactsSyncState, merged []contacts.Contact) error {
	plain, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	ct, err := u.EncryptToSelf(plain)
	if err != nil {
		return fmt.Errorf("sealing contacts snapshot: %w", err)
	}
	ver, err := c.CompactOps(ctx, "contacts", ct, st.Seq, st.SnapshotVersion)
	if IsConflict(err) {
		return nil // another device compacted first
	}
	if err != nil {
		return fmt.Errorf("compacting contacts ops: %w", err)
	}
	st.SnapshotVersion = ver
	return nil
}

// contactOpID keys ops by the store's own uniqueness key: the alias.
func contactOpID(ct contacts.Contact) string { return ct.Alias }

// diffContacts turns (last-synced shadow → live store) into ops: a put for
// every new or changed contact, a del tombstone for every removed one.
func diffContacts(shadow, local []contacts.Contact) []ContactOp {
	prev := contactsByID(shadow)
	var out []ContactOp
	seen := make(map[string]bool, len(local))
	for _, ct := range local {
		id := contactOpID(ct)
		seen[id] = true
		old, ok := prev[id]
		if ok && contactsEqual(old, ct) {
			continue
		}
		raw, err := json.Marshal(ct)
		if err != nil {
			continue // unmarshalable contact can't sync; skip, keep the rest
		}
		out = append(out, ContactOp{Op: "put", ID: id, Contact: raw})
	}
	for id := range prev {
		if !seen[id] {
			out = append(out, ContactOp{Op: "del", ID: id})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func contactsEqual(a, b contacts.Contact) bool {
	ja, err := json.Marshal(a)
	if err != nil {
		return false
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ja, jb)
}

func contactsByID(list []contacts.Contact) map[string]contacts.Contact {
	m := make(map[string]contacts.Contact, len(list))
	for _, ct := range list {
		m[contactOpID(ct)] = ct
	}
	return m
}

func contactsSorted(m map[string]contacts.Contact) []contacts.Contact {
	out := make([]contacts.Contact, 0, len(m))
	for _, ct := range m {
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return contactOpID(out[i]) < contactOpID(out[j]) })
	return out
}

func applyContactOp(u SelfCrypter, base map[string]contacts.Contact, op Op) error {
	return applyContactOpSkipping(u, base, op, nil)
}

// applyContactOpSkipping decrypts + applies one fetched op, ignoring ids in
// skip (used for race-gap ops that our own later ops already override).
// applyGapOps merges the ops that raced our append: it applies each op with
// seq < firstSeq (ops at/after firstSeq are our own append and already in
// base), skipping ids we just wrote (skip) so our higher-seq versions win.
// Extracted from the push path so this subtle convergence step is unit-testable.
func applyGapOps(u SelfCrypter, base map[string]contacts.Contact, gap []Op, firstSeq int64, skip map[string]bool) error {
	for _, op := range gap {
		if op.Seq >= firstSeq {
			break
		}
		if err := applyContactOpSkipping(u, base, op, skip); err != nil {
			return err
		}
	}
	return nil
}

func applyContactOpSkipping(u SelfCrypter, base map[string]contacts.Contact, op Op, skip map[string]bool) error {
	plain, err := u.Decrypt(op.Ciphertext)
	if err != nil {
		return fmt.Errorf("decrypting contact op %d: %w", op.Seq, err)
	}
	var cop ContactOp
	if err := json.Unmarshal(plain, &cop); err != nil {
		return fmt.Errorf("parsing contact op %d: %w", op.Seq, err)
	}
	if skip[cop.ID] {
		return nil
	}
	applyPlainOp(base, cop)
	return nil
}

func applyPlainOp(base map[string]contacts.Contact, op ContactOp) {
	switch op.Op {
	case "put":
		var ct contacts.Contact
		if err := json.Unmarshal(op.Contact, &ct); err != nil {
			return // malformed op: skip rather than poison the whole sync
		}
		base[op.ID] = ct
	case "del":
		delete(base, op.ID)
	}
}

// RemoveContactsShadow deletes the shadow file. Call it whenever the cloud
// session is cleared (logout, server switch): the shadow means "this is what
// the CURRENT server already has", so keeping it across a session boundary
// makes the next sync silently skip uploading everything it lists. With the
// shadow gone the device counts as never-synced — the full local set pushes
// as ops and merges cleanly with whatever the next account/server holds.
func RemoveContactsShadow() error {
	p, err := contactsShadowPath()
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// contactsShadowPath is the shadow file beside the contact store.
func contactsShadowPath() (string, error) {
	p, err := config.ContactsFilePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "contacts_shadow.json"), nil
}

func loadContactsShadow() ([]contacts.Contact, bool, error) {
	p, err := contactsShadowPath()
	if err != nil {
		return nil, false, err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading contacts shadow: %w", err)
	}
	var list []contacts.Contact
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, false, fmt.Errorf("parsing contacts shadow: %w", err)
	}
	return list, true, nil
}

func saveContactsShadow(list []contacts.Contact) error {
	p, err := contactsShadowPath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0600)
}
