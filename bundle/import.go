package bundle

import (
	"fmt"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/qr"
	"github.com/instacryptio/icfx/validate"
)

// ImportAction describes what action the client should take.
type ImportAction int

const (
	ActionAdd    ImportAction = iota // New contact — no existing match
	ActionUpdate                     // Existing contact — keys need updating
	ActionRevoke                     // Revocation only — no new keys
)

// ImportResult is returned by ProcessImport. The client reads it
// and handles UI (prompts, dialogs) — no prompt logic in the library.
type ImportResult struct {
	Action     ImportAction
	Contact    *contacts.Contact // existing contact if matched (nil for ActionAdd)
	NewKeys    *qr.LockBundle    // new keys to apply (nil for ActionRevoke)
	Revocation *RevocationBundle // revocation info (nil for ActionAdd)
	Message    string            // human-readable description for the client
}

// ProcessImport analyzes a parsed bundle against existing contacts and returns
// what action is needed. It validates that the pointers required by the bundle
// type are present (the fields are optional pointers, so a hand-built
// ParsedBundle could omit them) and returns an error rather than panicking.
func ProcessImport(parsed *ParsedBundle, existing []contacts.Contact) (*ImportResult, error) {
	if parsed == nil {
		return nil, fmt.Errorf("nil bundle")
	}
	switch parsed.Type {
	case BundleLock:
		if parsed.Lock == nil {
			return nil, fmt.Errorf("lock bundle has no lock")
		}
		if err := validate.ValidateLockBundle(*parsed.Lock); err != nil {
			return nil, err
		}
		return processLockImport(parsed.Lock, existing), nil
	case BundleRevoke:
		if parsed.Revocation == nil {
			return nil, fmt.Errorf("revocation bundle has no revocation")
		}
		return processRevokeImport(parsed.Revocation, existing), nil
	case BundleRotate:
		if parsed.Lock == nil || parsed.Revocation == nil {
			return nil, fmt.Errorf("rotation bundle missing lock or revocation")
		}
		// The rotated-in lock's labels are attacker-controlled (unsigned); reject
		// control/bidi bytes and oversized labels before they refresh a contact.
		if err := validate.ValidateLockBundle(*parsed.Lock); err != nil {
			return nil, err
		}
		return processRotateImport(parsed.Lock, parsed.Revocation, existing), nil
	default:
		return nil, fmt.Errorf("unknown bundle type %d", parsed.Type)
	}
}

func processLockImport(lock *qr.LockBundle, existing []contacts.Contact) *ImportResult {
	// Check if IC ID matches an existing contact
	if lock.ID != "" {
		c, err := contacts.FindByID(existing, lock.ID)
		if err == nil {
			return &ImportResult{
				Action:  ActionUpdate,
				Contact: c,
				NewKeys: lock,
				Message: fmt.Sprintf("%s has updated their keys. Verify their identity before confirming.", c.Alias),
			}
		}
	}

	// Fall back to matching by the publisher's handle (alias, or their name when
	// they published no alias) or email — handles manually-added contacts that
	// don't have an IC ID yet. The user's local Nickname is never a match key
	// for an incoming lock (it's not carried on the lock).
	handle := lock.Alias
	if handle == "" {
		handle = lock.Name
	}
	c, err := contacts.FindDuplicate(existing, handle, lock.Email, "")
	if err == nil {
		return &ImportResult{
			Action:  ActionUpdate,
			Contact: c,
			NewKeys: lock,
			Message: fmt.Sprintf("Existing contact %q matches. Update their keys?", c.Alias),
		}
	}

	return &ImportResult{
		Action:  ActionAdd,
		NewKeys: lock,
		Message: fmt.Sprintf("New contact: %s", lock.Name),
	}
}

func processRevokeImport(rev *RevocationBundle, existing []contacts.Contact) *ImportResult {
	c, err := contacts.FindByID(existing, rev.ID)
	if err != nil {
		return &ImportResult{
			Action:     ActionRevoke,
			Revocation: rev,
			Message:    fmt.Sprintf("Revocation for unknown contact (ID: %s). No action taken.", rev.ID),
		}
	}

	return &ImportResult{
		Action:     ActionRevoke,
		Contact:    c,
		Revocation: rev,
		Message:    fmt.Sprintf("%s has revoked their key. Import their new lock to continue communicating.", c.Alias),
	}
}

func processRotateImport(lock *qr.LockBundle, rev *RevocationBundle, existing []contacts.Contact) *ImportResult {
	c, err := contacts.FindByID(existing, rev.ID)
	if err != nil {
		// No existing contact — treat as new add
		return &ImportResult{
			Action:     ActionAdd,
			NewKeys:    lock,
			Revocation: rev,
			Message:    fmt.Sprintf("New contact: %s (includes key rotation)", lock.Name),
		}
	}

	return &ImportResult{
		Action:     ActionUpdate,
		Contact:    c,
		NewKeys:    lock,
		Revocation: rev,
		Message:    fmt.Sprintf("%s has rotated their keys. Verify their identity before confirming.", c.Alias),
	}
}

// ApplyUpdate moves a contact's current keys to PreviousKeys and updates with new keys.
func ApplyUpdate(c *contacts.Contact, lock *qr.LockBundle) {
	// Move current keys to history
	prev := contacts.PreviousKey{
		EncPubKey:   c.EncPubKey,
		SignPubKey:  c.SignPubKey,
		Fingerprint: c.Fingerprint,
		RevokedAt:   time.Now(),
	}
	c.PreviousKeys = append(c.PreviousKeys, prev)

	// Update with new keys
	c.EncPubKey = lock.EncPubKey
	c.SignPubKey = lock.SignPubKey
	c.Fingerprint = lock.Fingerprint
	// Refresh the publisher's alias (their handle may have changed on rotation);
	// preserve the user's local Nickname — it's not carried on the lock.
	handle := lock.Alias
	if handle == "" {
		handle = lock.Name
	}
	if handle != "" {
		c.Alias = handle
	}
	if lock.Email != "" {
		c.Email = lock.Email
	}
}

// ApplyRevoke moves a contact's current keys to PreviousKeys without replacing.
func ApplyRevoke(c *contacts.Contact) {
	prev := contacts.PreviousKey{
		EncPubKey:   c.EncPubKey,
		SignPubKey:  c.SignPubKey,
		Fingerprint: c.Fingerprint,
		RevokedAt:   time.Now(),
	}
	c.PreviousKeys = append(c.PreviousKeys, prev)
	c.EncPubKey = ""
	c.SignPubKey = ""
	c.Fingerprint = ""
}
