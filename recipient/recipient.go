// Package recipient resolves a user-supplied recipient reference (an alias,
// email, nickname, contact, or your own identity name — or a raw age1pq1 lock)
// to the key material an encrypt or a file-share needs. It owns the resolution
// ORDER so every client resolves recipients identically; the platform-specific
// step of unlocking one of the caller's OWN identities is injected as a callback.
package recipient

import (
	"fmt"
	"strings"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
)

// OpenEncKeyFn returns the (public) EncPubKey of one of the caller's OWN
// identities, unlocking it however the platform requires (a TTY prompt, the
// cached session passphrase, a hardware-key tap). ForEncrypt calls it only for
// an identity index whose name already matched the request. A non-nil error (or
// an empty key) means "couldn't resolve this one" and resolution continues.
type OpenEncKeyFn func(idx identity.IdentityIndex) (encPubKey string, err error)

// ForEncrypt resolves an encrypt recipient's public encryption key. Lookup
// order: a raw age1pq1 hybrid lock is returned as-is; then contacts by alias,
// then by email/nickname; then the caller's own identities by name (unlocked via
// open, since the index stores no public keys). Returns an error if nothing
// matches.
func ForEncrypt(to string, contactList []contacts.Contact, entries []identity.IdentityIndex, open OpenEncKeyFn) (string, error) {
	if strings.HasPrefix(to, "age1pq1") {
		return to, nil
	}

	if c, err := contacts.FindByAlias(contactList, to); err == nil {
		return c.EncPubKey, nil
	}
	if c, err := contacts.FindByEmailOrNickname(contactList, to); err == nil {
		return c.EncPubKey, nil
	}

	// Own identities by name only — email/nickname lookup against own
	// identities would require unlocking each, which we avoid here.
	for _, idx := range entries {
		if idx.Name != to {
			continue
		}
		if encPubKey, err := open(idx); err == nil && encPubKey != "" {
			return encPubKey, nil
		}
	}

	return "", fmt.Errorf("no contact or identity found matching %q", to)
}

// ExpandGroups replaces any reference that names a contact group with that
// group's members' encryption locks (age1pq1...), which then resolve as raw
// recipients via ForEncrypt. This is what makes `--to <name>` (and the app's
// unified contact/group picker) auto-detect groups, identically across clients.
//
// A reference that matches a CONTACT (alias/email/nickname) is left untouched —
// contacts take precedence, so a contact is never shadowed by a same-named
// group. Non-group, non-contact refs (own-identity names, raw locks) pass
// through for ForEncrypt/ForEncryptMany to resolve.
//
// A group's members with no active lock, or whose contact was deleted (dangling
// ID), are skipped — but each skip produces a `warnings` entry (composed here,
// like the share path's ForShareMany) so a client can tell the user some group
// members won't be able to decrypt, rather than silently dropping them. This
// mirrors ForShareMany so encrypt and share behave consistently.
func ExpandGroups(tos []string, groupList []groups.Group, contactList []contacts.Contact) (recipients []string, warnings []string) {
	out := make([]string, 0, len(tos))
	for _, to := range tos {
		if to == "" {
			continue
		}
		if _, err := contacts.FindByAlias(contactList, to); err == nil {
			out = append(out, to)
			continue
		}
		if _, err := contacts.FindByEmailOrNickname(contactList, to); err == nil {
			out = append(out, to)
			continue
		}
		if g, err := groups.FindByName(groupList, to); err == nil {
			added := 0
			for _, mid := range g.MemberIDs {
				c, cerr := contacts.FindByID(contactList, mid)
				if cerr != nil {
					warnings = append(warnings, EncryptWarnMissingMember(g.Name))
					continue
				}
				if c.EncPubKey == "" {
					warnings = append(warnings, EncryptWarnNoLock(c.Alias))
					continue
				}
				out = append(out, c.EncPubKey)
				added++
			}
			if added == 0 {
				warnings = append(warnings, EncryptWarnEmptyGroup(g.Name))
			}
			continue
		}
		out = append(out, to)
	}
	return out, warnings
}

// EncryptWarnNoLock is the user-facing warning for a group member that can't be
// an encryption recipient because it has no active lock (e.g. revoked). Composed
// in icfx so every client renders it identically (clients only print).
func EncryptWarnNoLock(alias string) string {
	return fmt.Sprintf("%s has no active lock (revoked?) and was skipped — they won't be able to decrypt.", alias)
}

// EncryptWarnMissingMember is the warning for a group member whose contact is no
// longer in the local contact list (dangling member ID).
func EncryptWarnMissingMember(groupName string) string {
	return fmt.Sprintf("A member of group %q is no longer in your contacts and was skipped.", groupName)
}

// EncryptWarnEmptyGroup is the warning for a named group that contributed no
// reachable recipients (all members skipped or the group is empty).
func EncryptWarnEmptyGroup(groupName string) string {
	return fmt.Sprintf("Group %q has no members with an active lock — nobody from it was added.", groupName)
}

// ForEncryptMany resolves several encrypt recipient references to their public
// encryption keys (locks), for multi-recipient (group) encryption. Each ref is
// resolved via the same order as ForEncrypt (raw age1pq1 lock, contact alias,
// contact email/nickname, own identity name). Results are deduped by lock, so
// referencing the same person twice — or via different handles — yields one
// recipient. Returns an error on the first ref that resolves to nothing, and an
// error if the final set is empty.
func ForEncryptMany(tos []string, contactList []contacts.Contact, entries []identity.IdentityIndex, open OpenEncKeyFn) ([]string, error) {
	locks := make([]string, 0, len(tos))
	seen := make(map[string]struct{}, len(tos))
	for _, to := range tos {
		if to == "" {
			continue
		}
		lock, err := ForEncrypt(to, contactList, entries, open)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[lock]; dup {
			continue
		}
		seen[lock] = struct{}{}
		locks = append(locks, lock)
	}
	if len(locks) == 0 {
		return nil, fmt.Errorf("no recipients resolved")
	}
	return locks, nil
}

// ShareTarget is one resolved cloud-share recipient: the lock the blob is
// encrypted to, the published directory fingerprint that authorizes the
// download, and the contact alias (for user-facing messages).
type ShareTarget struct {
	Lock        string
	Fingerprint string
	Alias       string
}

// ShareWarnNoFingerprint is the user-facing warning for a contact that can't
// receive a cloud share because it has no active lock / published fingerprint.
// Composed in icfx so every client renders it identically (clients only print).
func ShareWarnNoFingerprint(alias string) string {
	return fmt.Sprintf("%s can't receive a cloud share — they have no published lock/fingerprint.", alias)
}

// ShareWarnUnpublished is the user-facing warning for a recipient whose
// fingerprint isn't currently in the directory: the share is authorized for
// them, but they can't receive it until they publish — and because the email
// notification only fires once at share time (when they weren't reachable),
// they WON'T be emailed even after publishing; the share simply appears in
// their app/inbox once they publish. Composed in icfx.
func ShareWarnUnpublished(alias string) string {
	return fmt.Sprintf("%s isn't published to the directory — they can't receive this until they publish, and they won't be emailed; it'll just be waiting in their app/inbox once they do.", alias)
}

// ForShareMany resolves several share recipient references (contacts and/or
// group names) to their {lock, fingerprint, alias} triples, for multi-recipient
// shares. A cloud share needs each recipient's PUBLISHED directory fingerprint,
// so a recipient with no fingerprint (or no active lock) can't receive one:
//   - a contact/group MEMBER that lacks a fingerprint yields a `warnings`
//     entry (the share still goes to everyone reachable — "skip and warn");
//   - a reference that names neither a known contact nor a group is a hard
//     error (a typo, not an unreachable recipient).
//
// `warnings` are ready-to-render messages (composed here, not by clients).
// Results dedupe by fingerprint (a person in two groups, or a group that
// overlaps a directly-named contact, is shared to once). Errors only if the
// final reachable set is empty.
func ForShareMany(contactList []contacts.Contact, groupList []groups.Group, tos []string) (targets []ShareTarget, warnings []string, err error) {
	seen := map[string]struct{}{}
	add := func(c *contacts.Contact) {
		if _, dup := seen[c.Fingerprint]; dup {
			return
		}
		seen[c.Fingerprint] = struct{}{}
		targets = append(targets, ShareTarget{Lock: c.EncPubKey, Fingerprint: c.Fingerprint, Alias: c.Alias})
	}
	findContact := func(ref string) *contacts.Contact {
		if c, e := contacts.FindByAlias(contactList, ref); e == nil {
			return c
		}
		if c, e := contacts.FindByEmailOrNickname(contactList, ref); e == nil {
			return c
		}
		return nil
	}
	shareable := func(c *contacts.Contact) bool { return c.EncPubKey != "" && c.Fingerprint != "" }

	for _, to := range tos {
		if to == "" {
			continue
		}
		if c := findContact(to); c != nil { // contacts take precedence over a same-named group
			if !shareable(c) {
				warnings = append(warnings, ShareWarnNoFingerprint(c.Alias))
				continue
			}
			add(c)
			continue
		}
		if g, gerr := groups.FindByName(groupList, to); gerr == nil {
			for _, mid := range g.MemberIDs {
				c, cerr := contacts.FindByID(contactList, mid)
				if cerr != nil {
					continue // member's contact was deleted
				}
				if !shareable(c) {
					warnings = append(warnings, ShareWarnNoFingerprint(c.Alias))
					continue
				}
				add(c)
			}
			continue
		}
		return nil, nil, fmt.Errorf("no contact or group named %q", to)
	}
	if len(targets) == 0 {
		return nil, warnings, fmt.Errorf("no reachable recipients (a cloud share needs contacts with a published fingerprint)")
	}
	return targets, warnings, nil
}
