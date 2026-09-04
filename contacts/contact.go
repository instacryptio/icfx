package contacts

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/instacryptio/icfx/crypto"
)

var (
	ErrNotFound      = errors.New("contact not found")
	ErrAlreadyExists = errors.New("contact already exists")
)

// PreviousKey holds a contact's old key material after a key rotation.
type PreviousKey struct {
	EncPubKey   string    `json:"enc_pub_key"`
	SignPubKey  string    `json:"sign_pub_key"`
	Fingerprint string    `json:"fingerprint"`
	RevokedAt   time.Time `json:"revoked_at"`
}

// Contact represents a known recipient's public key information.
//
// Stored as plaintext in contacts.json (mode 0600). Contacts hold only
// the metadata needed to address messages to other people (their public
// keys plus identifying labels for lookup); there's no field designed to
// hold secrets — the previous Notes field was removed in the per-identity-
// backend refactor since contacts have no unlock mechanism, so anything
// "encrypted" there would have had to be encrypted with one of YOUR
// identities' keys, reintroducing the cross-backend brittleness this
// design eliminates.
type Contact struct {
	ID string `json:"id"` // Instacrypt ID
	// Alias is the CONTACT'S OWN self-set public handle (their identity alias),
	// carried in on their lock. Globally non-unique, so the local store may
	// fingerprint-suffix it to stay unambiguous. Used as a recipient selector.
	Alias string `json:"alias"`
	// Nickname is a LOCAL shortcut YOU assign to this contact — short and easy
	// to type — so you can address them (e.g. `-t <nickname>`) even when their
	// alias is long. User-set; never overwritten by a lock refresh.
	Nickname     string        `json:"nickname"`
	FirstName    string        `json:"first_name,omitempty"`
	LastName     string        `json:"last_name,omitempty"`
	Email        string        `json:"email"`
	EncPubKey    string        `json:"enc_pub_key"`
	SignPubKey   string        `json:"sign_pub_key"`
	Fingerprint  string        `json:"fingerprint"`
	AddedAt      time.Time     `json:"added_at"`
	PreviousKeys []PreviousKey `json:"previous_keys,omitempty"`
	// Cloud marks a contact saved via cloud discovery (search, friend
	// request/accept) — i.e. reachable through the directory by fingerprint.
	// Key rotations/revocations are auto-broadcast only to Cloud contacts;
	// manually-added contacts fall back to out-of-band file export.
	Cloud bool `json:"cloud,omitempty"`
	// CloudConnection tracks the mutual-exchange handshake with this
	// contact: "" (never invited), ConnectionInvited (we sent a connect
	// invite; waiting), ConnectionConnected (the handshake completed —
	// they accepted our invite or we accepted theirs; NEVER inferred), or
	// ConnectionUnreachable (an invite bounced: the fingerprint isn't
	// published on the cloud — not a user, or not listed).
	CloudConnection string `json:"cloud_connection,omitempty"`
	// InvitedAt is when the last connect invite was sent (re-invites are
	// offered after it ages).
	InvitedAt time.Time `json:"invited_at,omitempty"`
}

// CloudConnection states.
const (
	ConnectionInvited     = "invited"
	ConnectionConnected   = "connected"
	ConnectionUnreachable = "unreachable"
)

// contactData is the top-level structure for serialized contact storage.
type contactData struct {
	Version  int       `json:"version"`
	Contacts []Contact `json:"contacts"`
}

// EnsureID assigns a stable Instacrypt ID to a contact that lacks one (manually
// added contacts start without an ID), derived deterministically from its keys —
// the same scheme identities use. Returns true if it assigned one. Callers must
// Save the store when it returns true. Groups reference members by this ID.
func EnsureID(c *Contact) bool {
	if c.ID != "" {
		return false
	}
	signPub, err := base64.StdEncoding.DecodeString(c.SignPubKey)
	if err != nil {
		signPub = []byte(c.SignPubKey)
	}
	c.ID = crypto.GenerateInstacryptID(c.EncPubKey, signPub, c.AddedAt)
	return true
}

// FindByID returns the contact with the given Instacrypt ID, or ErrNotFound.
func FindByID(contacts []Contact, id string) (*Contact, error) {
	for i := range contacts {
		if contacts[i].ID == id {
			return &contacts[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindDuplicate checks for an existing contact matching by alias (their public
// handle), email, or nickname (your local shortcut).
func FindDuplicate(contacts []Contact, alias, email, nickname string) (*Contact, error) {
	for i := range contacts {
		if alias != "" && contacts[i].Alias == alias {
			return &contacts[i], nil
		}
		if email != "" && contacts[i].Email == email {
			return &contacts[i], nil
		}
		if nickname != "" && contacts[i].Nickname == nickname {
			return &contacts[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindByAlias returns the contact with the given alias, or ErrNotFound.
func FindByAlias(contacts []Contact, alias string) (*Contact, error) {
	for i := range contacts {
		if contacts[i].Alias == alias {
			return &contacts[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindByEmailOrNickname returns the contact matching the given email or nickname, or ErrNotFound.
func FindByEmailOrNickname(contacts []Contact, query string) (*Contact, error) {
	for i := range contacts {
		if contacts[i].Email == query || contacts[i].Nickname == query {
			return &contacts[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindByFingerprint returns the contact that owns the given fingerprint — matching
// the contact's current Fingerprint OR any rotated-away PreviousKeys entry, so a
// contact stays recognized across key rotations. The empty fingerprint never
// matches (a revoked contact has an empty Fingerprint). Comparison is
// case-insensitive; fingerprints are lowercase hex but callers may pass either.
// Used to detect that a directory search hit is already a contact.
func FindByFingerprint(contacts []Contact, fingerprint string) (*Contact, bool) {
	if fingerprint == "" {
		return nil, false
	}
	for i := range contacts {
		if strings.EqualFold(contacts[i].Fingerprint, fingerprint) {
			return &contacts[i], true
		}
		for _, pk := range contacts[i].PreviousKeys {
			if pk.Fingerprint != "" && strings.EqualFold(pk.Fingerprint, fingerprint) {
				return &contacts[i], true
			}
		}
	}
	return nil, false
}
