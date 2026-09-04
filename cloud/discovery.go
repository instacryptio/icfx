package cloud

import (
	"context"
	"fmt"

	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/qr"
	"github.com/instacryptio/icfx/validate"
)

// This file is the shared contact-discovery flow logic (ic-cli and ic-app):
// validating directory hits, sending/accepting friend requests, and draining
// the pending inbox. UI (prompts, dialogs, rendering) stays in each client;
// the decisions and the crypto-relevant checks live here so they can never
// diverge between clients.

// ParseDirectoryLock decodes and validates a search result's armored lock
// bundle and cross-checks the bundle's fingerprint against the directory row
// it came from — a mismatch means the row is inconsistent and must not be
// trusted. Every client MUST add directory contacts through this check.
func ParseDirectoryLock(entry DirectoryEntry) (qr.LockBundle, error) {
	data := []byte(entry.LockArmored)
	if format.IsArmored(data) {
		payload, err := format.ArmorDecodeExpect(data, format.ArmorLockLabel)
		if err != nil {
			return qr.LockBundle{}, fmt.Errorf("not a lock: %w", err)
		}
		data = payload
	}
	lb, err := qr.ParseLockBundle(data)
	if err != nil {
		return qr.LockBundle{}, fmt.Errorf("this directory entry does not contain a valid lock (public key) and cannot be added — it may have been published by an old or broken client: %w", err)
	}
	if err := validate.ValidateLockBundle(lb); err != nil {
		return qr.LockBundle{}, fmt.Errorf("invalid lock: %w", err)
	}
	// A directory lock is a peer-published lock and MUST be self-signed and
	// fingerprint-bound — otherwise a malicious/broken row could carry keys
	// that don't match the fingerprint others verify out-of-band.
	if err := qr.VerifyLockSelfSig(lb); err != nil {
		return qr.LockBundle{}, fmt.Errorf("unauthenticated directory lock: %w", err)
	}
	if lb.Fingerprint != entry.Fingerprint {
		return qr.LockBundle{}, fmt.Errorf("directory entry is inconsistent: lock fingerprint %s does not match listing %s", shortDiscoveryFP(lb.Fingerprint), shortDiscoveryFP(entry.Fingerprint))
	}
	return lb, nil
}

// DirectorySearchResult is a directory search hit annotated with whether it is
// already one of the caller's contacts, so clients can disable "add" for it.
// DirectoryEntry is embedded so the JSON keeps its original fields (display_name,
// fingerprint, lock_armored, …) plus the annotations.
type DirectorySearchResult struct {
	DirectoryEntry
	// AlreadyAdded is true when this identity's fingerprint matches an existing
	// contact (current or a rotated-away previous key).
	AlreadyAdded bool `json:"already_added"`
	// ContactAlias is the existing contact's alias when AlreadyAdded (for a
	// "already a contact (alias)" label); empty otherwise.
	ContactAlias string `json:"contact_alias,omitempty"`
}

// SearchDirectoryForContacts searches the cloud directory and annotates each hit
// with whether it's already a contact (matched by fingerprint against
// contactList). The server already excludes the caller's own identities; this
// adds the client-side "already added" signal so clients don't offer to re-add
// someone already in the contact list. Contacts are zero-knowledge, so this
// dedup can only happen client-side.
func SearchDirectoryForContacts(ctx context.Context, c *Client, query string, limit int, contactList []contacts.Contact) ([]DirectorySearchResult, error) {
	entries, err := c.SearchDirectory(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	out := make([]DirectorySearchResult, len(entries))
	for i, e := range entries {
		r := DirectorySearchResult{DirectoryEntry: e}
		if existing, ok := contacts.FindByFingerprint(contactList, e.Fingerprint); ok {
			r.AlreadyAdded = true
			r.ContactAlias = existing.Alias
		}
		out[i] = r
	}
	return out, nil
}

// SendFriendRequest queues the encrypted contact request for a directory hit,
// addressed by the target's published fingerprint so this client never learns
// their account id. myLock is the sending identity's lock bundle — it travels
// (with the reply account id) only inside the E2E ciphertext. The caller
// saves the target as a local contact separately.
func SendFriendRequest(ctx context.Context, c *Client, myLock qr.LockBundle, entry DirectoryEntry, target qr.LockBundle) error {
	return sendConnectRequest(ctx, c, myLock, entry.Fingerprint, target.EncPubKey)
}

// InviteContact sends a connect invite straight to a lock obtained
// out-of-band (QR scan, file import) — no directory entry needed: the lock
// itself carries the routing fingerprint and encryption key. Delivery still
// requires the recipient to have PUBLISHED that identity on the cloud
// (IsNotFound otherwise — not a user, or not listed; the two are
// indistinguishable by design).
func InviteContact(ctx context.Context, c *Client, myLock qr.LockBundle, target qr.LockBundle) error {
	return sendConnectRequest(ctx, c, myLock, target.Fingerprint, target.EncPubKey)
}

// sendConnectRequest is the shared core of SendFriendRequest/InviteContact:
// wrap my lock (+ reply account id) in E2E ciphertext and post it to the
// target fingerprint.
func sendConnectRequest(ctx context.Context, c *Client, myLock qr.LockBundle, fingerprint, encPubKey string) error {
	info, err := c.AccountInfo(ctx)
	if err != nil {
		return err
	}
	if info.AccountID == "" {
		return fmt.Errorf("server did not return your account id — is ic-cloud up to date?")
	}
	payload, err := MarshalContactRequest(info.AccountID, myLock)
	if err != nil {
		return err
	}
	_, err = c.SendToFingerprint(ctx, fingerprint, encPubKey, KindContactRequest, payload)
	return err
}

// AcceptContactRequest sends the encrypted accept-back (this identity's lock
// bundle) to the reply account carried inside the request payload, then acks
// the inbox item. Returns whether the requester was notified (a request
// without a reply address can only be added silently). The caller saves the
// requester as a local contact separately.
func AcceptContactRequest(ctx context.Context, c *Client, upd AppliedUpdate, myLock qr.LockBundle, itemID string) (notified bool, err error) {
	if upd.ReplyAccountID != "" {
		myRaw, merr := qr.MarshalLockBundle(myLock)
		if merr != nil {
			return false, fmt.Errorf("marshaling own lock: %w", merr)
		}
		if _, serr := c.SendToRecipient(ctx, upd.ReplyAccountID, upd.Lock.EncPubKey, upd.Lock.Fingerprint, KindContactAccept, myRaw); serr != nil {
			return false, serr
		}
		notified = true
	}
	if aerr := c.AckPending(ctx, itemID); aerr != nil {
		return notified, aerr
	}
	return notified, nil
}

// DrainReport summarizes one DrainPending pass; aliases are local contact
// aliases. Clients render it (CLI lines, app notices) — nothing here prints.
type DrainReport struct {
	// RequestsWaiting counts contact_request items left in the inbox — they
	// need an explicit human accept/decline and are NEVER auto-applied.
	RequestsWaiting int
	Accepted        []string // contact_accept applied: they accepted OUR request
	Rotated         []string // key rotation applied (old key kept in PreviousKeys)
	Revoked         []string // key revocation applied (key cleared, kept in PreviousKeys)
	Ignored         int      // items for unknown contacts, acked and dropped
	Skipped         int      // items we could not decrypt this pass (left in inbox)
	Rejected        int      // items that failed signature verification — acked and dropped (attack or corruption; retrying can't help)
}

// DrainPending processes the pending inbox non-interactively — the shared
// sync-time pass for both clients:
//
//	contact_request      → counted, LEFT in the inbox (explicit consent only)
//	contact_accept       → save their lock as a contact, ack
//	rotation             → apply to the matching contact (old key → PreviousKeys), ack
//	revocation           → clear the contact's key (kept in PreviousKeys), ack
//
// unlockFor resolves the local identity for an item's routing fingerprint
// (empty = default identity); items it cannot unlock are skipped and stay in
// the inbox for a later pass. Rotation/revocation for senders that are not in
// the contact store are acked and ignored.
func DrainPending(ctx context.Context, c *Client, store *contacts.Store, unlockFor func(fingerprint string) (SelfCrypter, error)) (DrainReport, error) {
	var rep DrainReport
	items, err := c.ListPending(ctx)
	if err != nil {
		return rep, err
	}

	for _, it := range items {
		if it.Kind == KindContactRequest {
			rep.RequestsWaiting++
			continue
		}

		item, ferr := c.FetchPending(ctx, it.ID)
		if ferr != nil {
			rep.Skipped++
			continue
		}
		u, uerr := unlockFor(item.ToFingerprint)
		if uerr != nil {
			rep.Skipped++
			continue
		}
		upd, aerr := ApplyPending(u, item)
		if aerr != nil {
			rep.Skipped++
			continue
		}

		switch upd.Kind {
		case KindContactAccept:
			if upd.Lock == nil {
				rep.Skipped++
				continue
			}
			// A contact_accept carries the accepter's sealed lock. A missing
			// or invalid self-signature is a permanent failure (forged or
			// corrupt) — ack, drop, and count as rejected.
			if verr := qr.VerifyLockSelfSig(*upd.Lock); verr != nil {
				if aerr := c.AckPending(ctx, item.ID); aerr != nil {
					return rep, aerr
				}
				rep.Rejected++
				continue
			}
			alias, _, serr := contacts.SaveFromLock(store, *upd.Lock)
			if serr != nil {
				return rep, serr
			}
			// The accept completes the mutual exchange handshake — this is
			// the ONLY place "connected" is set on the inviter's side.
			if merr := store.MarkConnectedByFingerprint(upd.Lock.Fingerprint); merr != nil {
				return rep, merr
			}
			if aerr := c.AckPending(ctx, item.ID); aerr != nil {
				return rep, aerr
			}
			rep.Accepted = append(rep.Accepted, alias)

		case KindRotation, KindRevocation:
			if upd.Bundle == nil {
				rep.Skipped++
				continue
			}
			alias, outcome, perr := applyBundleToContacts(store, upd.Bundle)
			if perr != nil {
				return rep, perr
			}
			// Everything but a transient store error is permanent → ack+drop.
			if aerr := c.AckPending(ctx, item.ID); aerr != nil {
				return rep, aerr
			}
			recordDrainOutcome(&rep, upd.Kind, alias, outcome)

		default:
			rep.Skipped++
		}
	}
	return rep, nil
}

// recordDrainOutcome tallies a rotation/revocation apply result into the report.
func recordDrainOutcome(rep *DrainReport, kind, alias string, outcome applyOutcome) {
	switch outcome {
	case applyRejected:
		rep.Rejected++
	case applyIgnored:
		rep.Ignored++
	case applyDone:
		if kind == KindRotation {
			rep.Rotated = append(rep.Rotated, alias)
			return
		}
		rep.Revoked = append(rep.Revoked, alias)
	}
}

// applyOutcome distinguishes how a rotation/revocation was handled so the
// caller can count it correctly.
type applyOutcome int

const (
	applyIgnored  applyOutcome = iota // unknown sender / not our contact — nothing to do
	applyDone                         // verified and applied
	applyRejected                     // signature/continuity verification failed
)

// applyBundleToContacts verifies then applies a rotation/revocation bundle to
// the matching contact. Verification is against the key ALREADY stored for the
// contact (continuity), so a stranger cannot substitute or revoke keys. The old
// key material ALWAYS lands in PreviousKeys (bundle.ApplyUpdate / ApplyRevoke).
// Unknown senders yield applyIgnored; failed verification yields applyRejected.
func applyBundleToContacts(store *contacts.Store, parsed *bundle.ParsedBundle) (alias string, outcome applyOutcome, err error) {
	existing, err := store.Load()
	if err != nil {
		return "", applyIgnored, err
	}
	result, err := bundle.ProcessImport(parsed, existing)
	if err != nil {
		// Malformed bundle — permanent, treat like a failed verification.
		return "", applyRejected, nil
	}
	if result.Contact == nil {
		return "", applyIgnored, nil
	}

	switch result.Action {
	case bundle.ActionUpdate:
		if verr := bundle.VerifyRotation(parsed, result.Contact); verr != nil {
			return "", applyRejected, nil
		}
		bundle.ApplyUpdate(result.Contact, result.NewKeys)
	case bundle.ActionRevoke:
		if verr := bundle.VerifyRevocation(parsed, result.Contact); verr != nil {
			return "", applyRejected, nil
		}
		bundle.ApplyRevoke(result.Contact)
	default:
		return "", applyIgnored, nil
	}
	if err := store.Save(existing); err != nil {
		return "", applyIgnored, err
	}
	return result.Contact.Alias, applyDone, nil
}

func shortDiscoveryFP(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "..."
}
