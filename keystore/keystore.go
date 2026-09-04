// Package keystore provides storage backends for icfx private key material.
//
// # Direct use vs. identity.Unlock
//
// The Keystore interface exposes raw byte/string access to private keys via
// LoadEncryptionIdentity and LoadSigningKey. This is the low-level primitive
// — it's required for things like in-place re-encryption, export tooling,
// and migration. Most consumers should NOT use these methods directly.
//
// For ordinary cryptographic operations on a private identity (Sign,
// Decrypt, Encrypt, GitSign), use identity.Unlock — which loads the keys
// into memguard enclaves, exposes operations that briefly open and
// immediately wipe the plaintext bytes, and prevents the raw key material
// from being copied into caller-controlled memory.
//
// Calling Load* directly puts the burden of memory hygiene on the caller:
// the returned bytes/string sit in the heap until they're explicitly wiped
// or garbage-collected. Prefer identity.Unlock unless you have a concrete
// reason to need raw access (and then wipe your buffers).
package keystore

// Keystore defines the interface for storing and retrieving encryption and
// signing keys. See package doc for the recommended access pattern via
// identity.Unlock vs direct Load* use.
type Keystore interface {
	// StoreEncryptionIdentity persists the age secret key string for name.
	StoreEncryptionIdentity(name string, identity string) error

	// LoadEncryptionIdentity returns the raw plaintext age secret key for
	// name. The returned string sits in caller-controlled heap memory until
	// the caller explicitly wipes it or it's GC'd. For ordinary use,
	// prefer identity.Unlock which holds keys in memguard.
	LoadEncryptionIdentity(name string) (string, error)

	// StoreSigningKey persists the ML-DSA-65 signing private key bytes for name.
	StoreSigningKey(name string, key []byte) error

	// LoadSigningKey returns the raw plaintext signing key bytes for name.
	// Same caveat as LoadEncryptionIdentity — prefer identity.Unlock for
	// memory-protected access.
	LoadSigningKey(name string) ([]byte, error)

	// HasKeys reports whether both the encryption identity and signing key
	// for name are present in the store.
	HasKeys(name string) bool

	// Clear removes the encryption identity and signing key for name.
	// Idempotent for missing entries.
	Clear(name string) error

	// ListNames returns the names of all identities present in the store.
	ListNames() ([]string, error)
}

// HWChallengeProvider is implemented by keystore decorators that hold a
// hardware-key challenge bytes for a given identity name. identity.Unlock
// uses a runtime type assertion against this interface so an Unlocked handle
// loaded from a HW-decorated keystore automatically carries the challenge —
// avoiding plumbing burden on callers and enabling Export to write HW state
// into the portable bundle without an extra option.
//
// The decorator's challenge is not secret on its own (security comes from
// the device's HMAC secret, not the challenge bytes); exposing it via this
// interface is safe.
type HWChallengeProvider interface {
	Challenge(name string) ([]byte, error)
}
