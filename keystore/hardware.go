package keystore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/instacryptio/icfx/crypto"
)

// challengeFileSuffix is the suffix appended to an identity name to form the
// challenge filename. Each hardware-backed identity gets its own challenge
// file under the keystore directory: e.g. "alice.hwchallenge". The challenge
// is plaintext — security depends on the hardware key, not on hiding the
// challenge.
const challengeFileSuffix = ".hwchallenge"

// challengeLength is the size of the random challenge sent to the hardware
// device. Yubikey HMAC-SHA1 challenge-response accepts up to 64 bytes.
const challengeLength = 32

// HardwareKeyDecorator wraps any Keystore with a per-identity hardware-key
// encryption layer.
//
// On every key load/store, it derives a key-encryption-key from
//
//	HKDF-SHA256(passphrase, hwKey.Challenge(<name>.hwchallenge))
//
// encrypts/decrypts the bytes itself with age-scrypt + hex(KEK), and
// delegates the resulting ciphertext to the inner keystore. Because the
// decorator owns the encryption layer, the inner can be any Keystore
// implementation (file, OS keychain, future USB-stick backend) — it just
// stores the opaque ciphertext bytes.
//
// Each identity has its own challenge file, so different identities produce
// different KEKs even with the same physical device. The challenge file
// always lives on local disk regardless of the inner backend (it's not
// secret, and a single disk-file location keeps the implementation simple
// across all backends).
//
// Without the hardware device, the KEK cannot be computed and the inner
// ciphertext cannot be decrypted.
type HardwareKeyDecorator struct {
	inner        Keystore
	hwKey        crypto.HardwareKey
	challengeDir string
	passFn       PassphraseFunc

	mu         sync.Mutex
	challenges map[string][]byte // identity name → challenge bytes; loaded lazily
}

// NewHardwareKeyDecorator creates a decorator that protects the keys stored
// in the given inner keystore with the combination of the user's passphrase
// (from passFn) and a hardware key. Per-identity challenges live in
// <challengeDir>/<name>.hwchallenge.
//
// The inner keystore should be in plaintext mode (no passphrase encryption
// of its own) — the decorator provides the encryption layer. For file
// backing, use NewFileStoreWithDir(dir). For OS keychain, NewKeychainStore().
func NewHardwareKeyDecorator(inner Keystore, hwKey crypto.HardwareKey, challengeDir string, passFn PassphraseFunc) *HardwareKeyDecorator {
	return &HardwareKeyDecorator{
		inner:        inner,
		hwKey:        hwKey,
		challengeDir: challengeDir,
		passFn:       passFn,
		challenges:   make(map[string][]byte),
	}
}

// ChallengePath returns the absolute path of the challenge file for the given
// identity. Useful for migration tooling, tests, and diagnostic commands.
func (d *HardwareKeyDecorator) ChallengePath(name string) string {
	return filepath.Join(d.challengeDir, name+challengeFileSuffix)
}

// EnsureChallenge creates a fresh random challenge file for the given identity
// if one does not already exist. Returns the challenge bytes either way.
// Called by setup flows immediately after slot programming/probing succeeds,
// before the first encryption operation.
func (d *HardwareKeyDecorator) EnsureChallenge(name string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadOrCreateChallengeLocked(name)
}

// Challenge returns the persisted challenge bytes for the given identity,
// loading them from disk on first call. Implements
// keystore.HWChallengeProvider so identity.Unlock can attach the challenge
// to the Unlocked handle for export.
func (d *HardwareKeyDecorator) Challenge(name string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadOrCreateChallengeLocked(name)
}

// RemoveChallenge deletes the challenge file for the given identity (used
// when toggling hardware key support OFF for an identity). Idempotent: a
// missing file is not an error.
func (d *HardwareKeyDecorator) RemoveChallenge(name string) error {
	d.mu.Lock()
	delete(d.challenges, name)
	d.mu.Unlock()
	err := os.Remove(d.ChallengePath(name))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing challenge file: %w", err)
	}
	return nil
}

// WriteChallenge persists the given challenge bytes for the given identity,
// overwriting any existing challenge. Used by the import flow when restoring
// HW protection from a portable bundle: the bundle carries the challenge
// bytes that must match the source machine's so the same KEK is derived.
func (d *HardwareKeyDecorator) WriteChallenge(name string, challenge []byte) error {
	if len(challenge) < 16 {
		return fmt.Errorf("challenge too short (%d bytes)", len(challenge))
	}
	if err := os.MkdirAll(d.challengeDir, 0700); err != nil {
		return fmt.Errorf("creating challenge directory: %w", err)
	}
	if err := os.WriteFile(d.ChallengePath(name), challenge, 0600); err != nil {
		return fmt.Errorf("writing challenge file: %w", err)
	}
	d.mu.Lock()
	d.challenges[name] = challenge
	d.mu.Unlock()
	return nil
}

// loadOrCreateChallengeLocked loads the persisted challenge for the given
// identity or generates and persists a fresh one. Caller must hold d.mu.
func (d *HardwareKeyDecorator) loadOrCreateChallengeLocked(name string) ([]byte, error) {
	if c, ok := d.challenges[name]; ok {
		return c, nil
	}

	path := d.ChallengePath(name)
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) < 16 {
			return nil, fmt.Errorf("challenge file %s is too short (%d bytes)", path, len(data))
		}
		d.challenges[name] = data
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading challenge file: %w", err)
	}

	if err := os.MkdirAll(d.challengeDir, 0700); err != nil {
		return nil, fmt.Errorf("creating challenge directory: %w", err)
	}
	challenge := make([]byte, challengeLength)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}
	if err := os.WriteFile(path, challenge, 0600); err != nil {
		return nil, fmt.Errorf("writing challenge file: %w", err)
	}
	d.challenges[name] = challenge
	return challenge, nil
}

// derivePassphrase computes the age-scrypt passphrase used to encrypt this
// identity's stored bytes: hex(HKDF-SHA256(passphrase, hwResponse)).
//
// It returns the hex-encoded KEK as a FRESH, caller-owned []byte (never a Go
// string) so the derived per-identity secret can be wiped after use; every
// caller MUST crypto.Zero the result. The master passphrase, the hardware
// response, and the raw KEK are all wiped here, keeping their lifetimes as
// short as possible. The hex encoding (not the raw KEK) is preserved as the
// scrypt passphrase for on-disk compatibility with keystores written before
// this change.
func (d *HardwareKeyDecorator) derivePassphrase(name string) ([]byte, error) {
	if d.passFn == nil {
		return nil, fmt.Errorf("hardware decorator requires a passphrase function")
	}

	d.mu.Lock()
	challenge, err := d.loadOrCreateChallengeLocked(name)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}

	pass, err := d.passFn()
	if err != nil {
		return nil, fmt.Errorf("getting passphrase: %w", err)
	}
	defer crypto.Zero(pass)

	response, err := d.hwKey.Challenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("hardware challenge-response (%s): %w", d.hwKey.Type(), err)
	}
	defer crypto.Zero(response)

	kek, err := crypto.DeriveHardwareKEKBytes(pass, response)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(kek)

	// Hex-encode into a []byte (not hex.EncodeToString, which would create an
	// un-zeroable string); this hex passphrase is what the caller wipes.
	hexKEK := make([]byte, hex.EncodedLen(len(kek)))
	hex.Encode(hexKEK, kek)
	return hexKEK, nil
}

// StoreEncryptionIdentity encrypts the given age secret key string with the
// HW-augmented KEK and stores the ciphertext (base64-encoded so it survives
// any text-mode handling by the inner keystore) in the inner keystore.
func (d *HardwareKeyDecorator) StoreEncryptionIdentity(name string, identity string) error {
	pass, err := d.derivePassphrase(name)
	if err != nil {
		return err
	}
	defer crypto.Zero(pass)
	ciphertext, err := crypto.EncryptWithPassphraseBytes([]byte(identity), pass)
	if err != nil {
		return fmt.Errorf("encrypting encryption identity: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return d.inner.StoreEncryptionIdentity(name, encoded)
}

// LoadEncryptionIdentity reverses StoreEncryptionIdentity.
func (d *HardwareKeyDecorator) LoadEncryptionIdentity(name string) (string, error) {
	encoded, err := d.inner.LoadEncryptionIdentity(name)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding encryption identity ciphertext: %w", err)
	}
	pass, err := d.derivePassphrase(name)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(pass)
	plaintext, err := crypto.DecryptWithPassphraseBytes(ciphertext, pass)
	if err != nil {
		return "", fmt.Errorf("decrypting encryption identity (wrong passphrase or hardware key?): %w", err)
	}
	return string(plaintext), nil
}

// StoreSigningKey encrypts the given signing key bytes with the HW-augmented
// KEK and stores the ciphertext in the inner keystore.
func (d *HardwareKeyDecorator) StoreSigningKey(name string, key []byte) error {
	pass, err := d.derivePassphrase(name)
	if err != nil {
		return err
	}
	defer crypto.Zero(pass)
	ciphertext, err := crypto.EncryptWithPassphraseBytes(key, pass)
	if err != nil {
		return fmt.Errorf("encrypting signing key: %w", err)
	}
	return d.inner.StoreSigningKey(name, ciphertext)
}

// LoadSigningKey reverses StoreSigningKey.
func (d *HardwareKeyDecorator) LoadSigningKey(name string) ([]byte, error) {
	ciphertext, err := d.inner.LoadSigningKey(name)
	if err != nil {
		return nil, err
	}
	pass, err := d.derivePassphrase(name)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(pass)
	plaintext, err := crypto.DecryptWithPassphraseBytes(ciphertext, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypting signing key (wrong passphrase or hardware key?): %w", err)
	}
	return plaintext, nil
}

// HasKeys delegates to the inner keystore.
func (d *HardwareKeyDecorator) HasKeys(name string) bool {
	return d.inner.HasKeys(name)
}

// Clear removes the keys from the inner keystore and the challenge file.
func (d *HardwareKeyDecorator) Clear(name string) error {
	if err := d.inner.Clear(name); err != nil {
		return err
	}
	return d.RemoveChallenge(name)
}

// ListNames delegates to the inner keystore.
func (d *HardwareKeyDecorator) ListNames() ([]string, error) {
	return d.inner.ListNames()
}
