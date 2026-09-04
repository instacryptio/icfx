package identity

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrNotFound      = errors.New("identity not found")
	ErrAlreadyExists = errors.New("identity already exists")
	ErrNoPrimary     = errors.New("no primary identity set")
	// ErrAliasTaken is returned when a create/edit would give an identity an
	// alias already held by a DIFFERENT identity in the same local index.
	// Aliases are unique per user profile (locally), even though they are not
	// globally unique in the cloud directory.
	ErrAliasTaken = errors.New("alias already in use by another identity")
	// ErrKeysExist is returned by ImportBytes when the target keystore already
	// holds keys for the bundle's identity name. It distinguishes a genuine
	// duplicate from an orphaned partial import (keys stored but never indexed),
	// letting callers offer a reconcile path instead of failing outright.
	ErrKeysExist = errors.New("identity keys already exist in the keystore")
)

// Identity represents a user's cryptographic identity.
type Identity struct {
	ID   string `json:"id"` // Instacrypt ID (IC-<hash>), stable across rotations
	Name string `json:"name"`
	// Alias is a short, single-word, username-like public handle (was the
	// private "nickname"). It is mirrored into the plaintext index
	// (IdentityIndex.Alias) so it is readable without unlocking, drives backup
	// filenames, doubles as an alternate selector, and (fast-follow) will be
	// published + searchable in the cloud directory. Locally unique; validated
	// by validate.Alias.
	Alias       string `json:"alias"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	Email       string `json:"email"`
	EncPubKey   string `json:"enc_pub_key"`
	SignPubKey  string `json:"sign_pub_key"`
	Fingerprint string `json:"fingerprint"`
	IsPrimary   bool   `json:"is_primary"`
	Status      string `json:"status"`           // "active" or "revoked"
	HWKey       bool   `json:"hw_key,omitempty"` // requires hardware key (slot-2 HMAC-SHA1 challenge-response) to unlock
	// Backend records where this identity's private keys are stored:
	// "keychain" (OS keychain / libsecret / Windows Credential Manager) or
	// "file" (encrypted files in the keys directory). The configured
	// `keystore` setting is the default for NEW identities only — once an
	// identity is created, its Backend is fixed and load operations always
	// look there regardless of the current setting. Empty for legacy
	// identities created before this field existed; loaders treat empty
	// as "look in the configured backend" for backward compatibility.
	Backend   string    `json:"backend,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	// LockSig is the base64 self-signature over this identity's lock
	// (qr.SealLock), computed at creation and rotation while the signing key
	// is in hand, and emitted by LockBundleOf so every published lock is
	// sealed without needing to unlock. Empty for legacy identities created
	// before self-signed locks; such locks fall back to fingerprint binding.
	LockSig string `json:"lock_sig,omitempty"`
}

// Backend constants for the Identity.Backend field.
const (
	BackendKeychain = "keychain"
	BackendFile     = "file"
)

// StatusActive and StatusRevoked are the valid identity statuses.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// FindByID returns the identity with the given Instacrypt ID, or ErrNotFound.
func FindByID(identities []Identity, id string) (*Identity, error) {
	for i := range identities {
		if identities[i].ID == id {
			return &identities[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindDuplicate checks for an existing identity matching by name, email, or alias.
func FindDuplicate(identities []Identity, name, email, alias string) (*Identity, error) {
	for i := range identities {
		if name != "" && identities[i].Name == name {
			return &identities[i], nil
		}
		if email != "" && identities[i].Email == email {
			return &identities[i], nil
		}
		if alias != "" && strings.EqualFold(identities[i].Alias, alias) {
			return &identities[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindByName returns the identity with the given name, or ErrNotFound.
func FindByName(identities []Identity, name string) (*Identity, error) {
	for i := range identities {
		if identities[i].Name == name {
			return &identities[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindPrimary returns the primary identity, or ErrNoPrimary.
func FindPrimary(identities []Identity) (*Identity, error) {
	for i := range identities {
		if identities[i].IsPrimary {
			return &identities[i], nil
		}
	}
	return nil, ErrNoPrimary
}
