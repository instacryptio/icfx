package contacts

import (
	"fmt"
	"time"

	"github.com/instacryptio/icfx/qr"
	"github.com/instacryptio/icfx/validate"
)

// SaveFromLock adds (or idempotently updates) a contact from a lock bundle
// and reports the alias used. Matching is by fingerprint — the stable key of
// the lock itself — so re-adding the same person refreshes their labels
// instead of duplicating them. An alias collision with a DIFFERENT
// fingerprint gets a fingerprint-suffixed alias. This is the ONE contact
// write path for cloud discovery (search results, friend requests, accepts),
// shared by every client so dedup and alias rules never diverge.
func SaveFromLock(store *Store, lb qr.LockBundle) (alias string, updated bool, err error) {
	// The lock's advisory labels (Name/Alias/Email) are NOT covered by the
	// self-signature, so a signed lock can still carry attacker-controlled
	// terminal-escape / bidi bytes or oversized strings. Reject them at this
	// write chokepoint (not only at ParseDirectoryLock) before anything is
	// persisted or displayed. ValidateLockBundle ALSO verifies the self-sig when
	// one is present (so we don't re-verify below).
	if err := validate.ValidateLockBundle(lb); err != nil {
		return "", false, fmt.Errorf("invalid lock: %w", err)
	}
	// Every lock reaching this path arrives over a peer/cloud channel, so it
	// must carry a self-signature — that's what makes a directory/friend-request
	// lock trustworthy rather than self-asserted. ValidateLockBundle permits an
	// unsigned-but-fingerprint-bound lock (manual entry); require a signature
	// here. (The signature itself was already verified above.)
	if lb.Sig == "" {
		return "", false, fmt.Errorf("unauthenticated lock: missing self-signature")
	}

	// Hold the store lock across the whole load-modify-save so a concurrent
	// cloud sync / UI action can't interleave and drop this upsert.
	store.mu.Lock()
	defer store.mu.Unlock()

	// Propagate load errors: Store.Load returns empty+nil for a missing file,
	// so a non-nil error means a real read failure or a corrupt contacts.json.
	// Swallowing it here would overwrite the file with just this one contact,
	// destroying every existing contact.
	existing, err := store.loadLocked()
	if err != nil {
		return "", false, fmt.Errorf("loading contacts: %w", err)
	}

	// Alias is the PUBLISHER's self-set handle (from the lock). Only accept it
	// as the contact's alias when it conforms to the alias charset (lowercased);
	// an attacker-shaped value (spaces, look-alike suffix, uppercase) is dropped
	// in favor of their display name, then a short fingerprint.
	pubAlias := validate.NormalizeAlias(lb.Alias)
	if pubAlias == "" {
		pubAlias = lb.Name
	}
	if pubAlias == "" {
		pubAlias = shortFP(lb.Fingerprint)
	}

	for i := range existing {
		if existing[i].Fingerprint != lb.Fingerprint {
			continue
		}
		existing[i].ID = lb.ID
		// Refresh the publisher's alias; DO NOT touch Nickname — that's the
		// user's own local shortcut for this contact, not from the lock.
		existing[i].Alias = pubAlias
		existing[i].Email = lb.Email
		existing[i].EncPubKey = lb.EncPubKey
		existing[i].SignPubKey = lb.SignPubKey
		existing[i].Cloud = true
		if err := store.saveLocked(existing); err != nil {
			return "", false, fmt.Errorf("saving contacts: %w", err)
		}
		return existing[i].Alias, true, nil
	}

	alias = pubAlias
	// Aliases are globally non-unique; keep the local index unambiguous by
	// suffixing a short fingerprint on a clash with a DIFFERENT contact.
	if _, err := FindByAlias(existing, alias); err == nil {
		alias = alias + " (" + shortFP(lb.Fingerprint) + ")"
	}
	contact := Contact{
		ID:    lb.ID,
		Alias: alias,
		// Nickname (the user's local shortcut) starts empty — it's set later
		// via edit, never populated from the lock.
		Email:       lb.Email,
		EncPubKey:   lb.EncPubKey,
		SignPubKey:  lb.SignPubKey,
		Fingerprint: lb.Fingerprint,
		AddedAt:     time.Now(),
		Cloud:       true,
	}
	if err := store.saveLocked(append(existing, contact)); err != nil {
		return "", false, fmt.Errorf("saving contacts: %w", err)
	}
	return alias, false, nil
}

func shortFP(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "..."
}
