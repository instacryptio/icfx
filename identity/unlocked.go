package identity

import (
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/keystore"
)

// ErrUnlockedClosed is returned by Unlocked operations after Close has been
// called and the in-memory keys have been wiped.
var ErrUnlockedClosed = errors.New("unlocked: handle is closed")

// Unlocked is an identity with its private keys loaded into memguard
// enclaves. The plaintext key bytes never leave this type — callers get
// operations (Sign / Decrypt / Encrypt / GitSign / Export), not raw access.
//
// The keys are mlock'd, encrypted at rest in process memory using
// memguard's per-process key, and deterministically wiped on Close.
// Operations briefly Open the enclave for the microsecond of the
// underlying crypto call, then Destroy the temporary buffer immediately.
//
// Unlocked is the recommended entry point for all crypto operations on
// a private identity. Direct use of keystore.Keystore.Load* should be
// reserved for export/migration tooling that needs raw bytes (and that
// tooling should still wipe its buffers after use).
type Unlocked struct {
	info   Identity
	encKey *memguard.Enclave
	sigKey *memguard.Enclave

	// hwChallenge is the per-identity hardware-key challenge bytes,
	// auto-attached by Unlock when info.HWKey is true and the keystore
	// implements keystore.HWChallengeProvider. Used by Export to populate
	// the portable bundle's HW state so an HW-protected identity can be
	// imported on another machine. Empty for non-HW identities.
	hwChallenge []byte
}

// Unlock loads the named identity's private keys from the keystore, wraps
// them in memguard immediately (wiping any intermediate buffers), and
// returns a handle. Caller must Close() when done.
//
// info is the identity metadata, typically obtained via identity.Store.Load
// followed by FindByName. It's used for read-only accessors (Fingerprint,
// Name, IsHWBacked) — the keys themselves come from ks.
func Unlock(ks keystore.Keystore, info Identity) (*Unlocked, error) {
	encStr, err := ks.LoadEncryptionIdentity(info.Name)
	if err != nil {
		return nil, fmt.Errorf("loading encryption identity: %w", err)
	}
	sigBytes, err := ks.LoadSigningKey(info.Name)
	if err != nil {
		// Wipe the encryption identity copy we just made before returning.
		wipeString(&encStr)
		return nil, fmt.Errorf("loading signing key: %w", err)
	}

	// Wrap into memguard immediately. NewBufferFromBytes copies and wipes
	// the source slice; for the string we have to copy via a byte slice and
	// wipe the temporary.
	encBuf := []byte(encStr)
	encEnclave := memguard.NewBufferFromBytes(encBuf).Seal()
	wipeBytes(encBuf)
	wipeString(&encStr)

	sigEnclave := memguard.NewBufferFromBytes(sigBytes).Seal()
	// NewBufferFromBytes wipes its input; sigBytes is now zeroed by memguard.

	// If this is an HW-backed identity AND ks is the HW-decorated keystore
	// (it must be, otherwise the loads above would have failed), pull the
	// challenge bytes out so Export can include them in the bundle. Free of
	// charge — the decorator already cached them during the load.
	var hwChallenge []byte
	if info.HWKey {
		if p, ok := ks.(keystore.HWChallengeProvider); ok {
			c, err := p.Challenge(info.Name)
			if err != nil {
				// Destroy the already-sealed key enclaves before bailing —
				// otherwise they leak (reclaimable only by the GC finalizer,
				// defeating the deterministic wipe).
				destroyEnclave(encEnclave)
				destroyEnclave(sigEnclave)
				return nil, fmt.Errorf("reading hardware challenge: %w", err)
			}
			hwChallenge = c
		}
	}

	return &Unlocked{
		info:        info,
		encKey:      encEnclave,
		sigKey:      sigEnclave,
		hwChallenge: hwChallenge,
	}, nil
}

// LoadMeta decrypts this identity's meta file (per-identity rich metadata
// encrypted to its own EncPubKey at create/edit time) and overlays the
// resulting Identity onto u.info, so subsequent calls to Info()/Name()/etc.
// return the full record.
//
// The plaintext encryption identity briefly opens from memguard, decrypts
// the file, and the buffer is wiped — same pattern as Sign/Decrypt.
func (u *Unlocked) LoadMeta(store *Store, idx IdentityIndex) error {
	if u.encKey == nil {
		return ErrUnlockedClosed
	}
	buf, err := u.encKey.Open()
	if err != nil {
		return fmt.Errorf("opening encryption identity enclave: %w", err)
	}
	defer buf.Destroy()
	full, err := store.LoadMeta(idx.Name, string(buf.Bytes()), idx)
	if err != nil {
		return err
	}
	u.info = full
	return nil
}

// destroyEnclave deterministically wipes a sealed enclave (Open + Destroy)
// rather than waiting for the GC finalizer. Nil-safe.
func destroyEnclave(e *memguard.Enclave) {
	if e == nil {
		return
	}
	if buf, err := e.Open(); err == nil {
		buf.Destroy()
	}
}

// Close wipes both enclaves and marks the handle as closed. Subsequent
// operations return ErrUnlockedClosed. Safe to call multiple times.
func (u *Unlocked) Close() {
	destroyEnclave(u.encKey)
	u.encKey = nil
	destroyEnclave(u.sigKey)
	u.sigKey = nil
}

// --- Crypto operations ---

// Sign produces an ML-DSA-65 (FIPS 204) signature over data using the held
// signing private key. The plaintext key bytes are briefly opened from
// the enclave, used for one Sign call, and immediately wiped.
func (u *Unlocked) Sign(data []byte) ([]byte, error) {
	if u.sigKey == nil {
		return nil, ErrUnlockedClosed
	}
	buf, err := u.sigKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening signing key enclave: %w", err)
	}
	defer buf.Destroy()
	return crypto.Sign(data, buf.Bytes())
}

// Decrypt decrypts age-encrypted ciphertext using the held encryption
// identity (age secret key). Plaintext key briefly opened, used, wiped.
func (u *Unlocked) Decrypt(ciphertext []byte) ([]byte, error) {
	if u.encKey == nil {
		return nil, ErrUnlockedClosed
	}
	buf, err := u.encKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening encryption identity enclave: %w", err)
	}
	defer buf.Destroy()
	return crypto.Decrypt(ciphertext, string(buf.Bytes()))
}

// DecryptStream returns a reader that decrypts ciphertext streamed from r
// using the held encryption identity — no full-payload buffer materializes
// (large file shares). The enclave is opened only to construct the age
// identity and is wiped before returning.
func (u *Unlocked) DecryptStream(r io.Reader) (io.Reader, error) {
	if u.encKey == nil {
		return nil, ErrUnlockedClosed
	}
	buf, err := u.encKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening encryption identity enclave: %w", err)
	}
	dr, err := crypto.DecryptStream(r, string(buf.Bytes()))
	buf.Destroy()
	return dr, err
}

// Encrypt encrypts plaintext for the given recipient hybrid PQ public keys
// (age1pq1...). Encrypting to multiple recipients yields one ciphertext any one
// of them can decrypt. The held private keys are not used for this operation —
// it's exposed as a method on Unlocked for API symmetry, since most callers
// already have an Unlocked handle when they want to encrypt to a recipient.
func (u *Unlocked) Encrypt(plaintext []byte, recipients []string) ([]byte, error) {
	if u.encKey == nil {
		// Closed handle — fail rather than silently working without auth context.
		return nil, ErrUnlockedClosed
	}
	return crypto.Encrypt(plaintext, recipients)
}

// EncryptToSelf is a convenience wrapper that encrypts to this identity's
// own public encryption key (from Info().EncPubKey). Useful for "encrypt
// for myself" / personal vault flows.
func (u *Unlocked) EncryptToSelf(plaintext []byte) ([]byte, error) {
	if u.encKey == nil {
		return nil, ErrUnlockedClosed
	}
	return crypto.Encrypt(plaintext, []string{u.info.EncPubKey})
}

// GitSign reads commit content from r, signs with the held ML-DSA-65 key,
// and writes an armored signature (with embedded fingerprint header) to w.
// Used by ic-cli's git-sign integration.
func (u *Unlocked) GitSign(r io.Reader, w io.Writer) error {
	if u.sigKey == nil {
		return ErrUnlockedClosed
	}
	buf, err := u.sigKey.Open()
	if err != nil {
		return fmt.Errorf("opening signing key enclave: %w", err)
	}
	defer buf.Destroy()
	return crypto.GitSign(r, w, buf.Bytes(), u.info.Fingerprint)
}

// --- Read-only metadata accessors ---

// Info returns a copy of the identity metadata. Modifying it does not affect
// the Unlocked handle.
func (u *Unlocked) Info() Identity { return u.info }

// Fingerprint returns the identity's public-key fingerprint.
func (u *Unlocked) Fingerprint() string { return u.info.Fingerprint }

// Name returns the identity's name (the keystore lookup key).
func (u *Unlocked) Name() string { return u.info.Name }

// IsHWBacked reports whether the identity is hardware-key-protected
// (per its metadata flag). For the storage-agnostic HW refactor see PR 2.
func (u *Unlocked) IsHWBacked() bool { return u.info.HWKey }

// --- Verification (free function, no key needed) ---

// Verify checks an ML-DSA-65 (FIPS 204) signature against the given data using
// the signer's public key bytes. Free function because verification doesn't
// need an Unlocked handle.
func Verify(data, sig, signerPubKey []byte) (bool, error) {
	return crypto.Verify(data, sig, signerPubKey)
}

// --- Memory hygiene helpers ---

// wipeBytes overwrites a byte slice with zeros. Best-effort: the Go compiler
// could in principle elide the writes, but in practice this works for our
// purposes (memguard does the heavy lifting; this is for transient buffers
// just before they go out of scope).
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wipeString attempts to zero the backing array of a string. Strings in Go
// are immutable in the language, but the underlying bytes can be overwritten
// via unsafe — which we deliberately avoid here. Instead we just nil the
// caller's reference to encourage GC. The original string content may
// linger in memory until GC runs and the runtime decides to reuse the page.
//
// For sensitive strings (private key material), prefer working with []byte
// and using wipeBytes. wipeString is a best-effort hint, not a guarantee.
func wipeString(s *string) { *s = "" }
