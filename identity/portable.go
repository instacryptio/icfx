package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/validate"
)

// portableBundle is the on-disk format produced by Unlocked.Export and
// consumed by Import. The whole struct gets marshaled to JSON and then
// encrypted with a passphrase via age scrypt — the JSON form never reaches
// disk in plaintext.
type portableBundle struct {
	EncryptionIdentity string   `json:"encryption_identity"` // age secret key string (AGE-SECRET-KEY-PQ-1...)
	SigningPrivateKey  string   `json:"signing_private_key"` // base64-encoded ML-DSA-65 private key
	Info               Identity `json:"info"`                // public metadata
	// HWKey is true iff the source identity was hardware-key-protected.
	// HWChallenge is the per-identity challenge bytes the hardware key
	// HMACs to derive the KEK. The challenge is not secret; security comes
	// from the device's HMAC secret, not from hiding the challenge.
	HWKey       bool   `json:"hw_key,omitempty"`
	HWChallenge []byte `json:"hw_challenge,omitempty"`
}

// HWRestoreFn is invoked by Import when a portable bundle carries hardware-
// key state (HWKey=true). The callback receives the bundle's challenge bytes
// and decides what to do:
//
//   - Return (nil, nil) to import as a plain (non-HW) identity. The keys are
//     stored in the original ks passed to Import; info.HWKey is set to false.
//   - Return (hwKS, nil) to preserve HW protection. The caller is responsible
//     for opening the device, persisting the challenge bytes (typically by
//     calling hwKS.WriteChallenge or by passing the bytes through the
//     decorator constructor), and returning a HardwareKeyDecorator wrapping
//     the configured plain backend. Import will use hwKS to store the keys
//     and set info.HWKey to true.
//   - Return (_, err) to fail the import.
//
// Pass nil for restoreHW to always import as plain (HW state is dropped).
type HWRestoreFn func(challenge []byte) (keystore.Keystore, error)

// Export encrypts the held private keys + public metadata into a portable
// bundle protected by the given passphrase. The plaintext key material is
// briefly opened from memguard, immediately serialized, encrypted with
// passphrase-derived scrypt, and the temporary buffers wiped — same
// pattern GPG uses for `--export-secret-keys`.
//
// The returned bytes are safe to write to disk or transmit; without the
// passphrase, the bundle is opaque ciphertext.
func (u *Unlocked) Export(exportPassphrase string) ([]byte, error) {
	return u.ExportBytes([]byte(exportPassphrase))
}

// ExportBytes is the wipeable-bytes core of Export: the passphrase stays a
// []byte (caller-owned, caller-wiped) all the way to the age boundary.
func (u *Unlocked) ExportBytes(exportPassphrase []byte) ([]byte, error) {
	if u.encKey == nil || u.sigKey == nil {
		return nil, ErrUnlockedClosed
	}
	if len(exportPassphrase) == 0 {
		return nil, fmt.Errorf("export passphrase cannot be empty")
	}

	encBuf, err := u.encKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening encryption identity enclave: %w", err)
	}
	defer encBuf.Destroy()

	sigBuf, err := u.sigKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening signing key enclave: %w", err)
	}
	defer sigBuf.Destroy()

	bundle := portableBundle{
		EncryptionIdentity: string(encBuf.Bytes()),
		SigningPrivateKey:  base64.StdEncoding.EncodeToString(sigBuf.Bytes()),
		Info:               u.info,
	}
	// Best-effort minimize the lifetime of the plaintext private-key strings
	// held in the bundle (Go strings can't be truly zeroed, but drop the
	// references as soon as the encrypted bytes are produced).
	defer wipeString(&bundle.EncryptionIdentity)
	defer wipeString(&bundle.SigningPrivateKey)
	if u.info.HWKey {
		if len(u.hwChallenge) == 0 {
			return nil, fmt.Errorf("identity is hardware-key-protected but no challenge attached; ensure the keystore implements keystore.HWChallengeProvider")
		}
		bundle.HWKey = true
		bundle.HWChallenge = u.hwChallenge
	}

	jsonData, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle: %w", err)
	}
	defer wipeBytes(jsonData)

	encrypted, err := crypto.EncryptWithPassphraseBytes(jsonData, exportPassphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypting bundle: %w", err)
	}
	return encrypted, nil
}

// Peek decrypts a portable bundle and returns just the public metadata
// (without persisting the keys to a keystore). Useful for callers that
// need to know the identity name or HW state before deciding how to
// configure the import — e.g. constructing the right HW-decorated
// keystore under the right challenge-file name.
//
// The plaintext key bytes are decrypted and immediately wiped; only the
// public Identity metadata is returned.
func Peek(bundle []byte, importPassphrase string) (Identity, bool, error) {
	return PeekBytes(bundle, []byte(importPassphrase))
}

// PeekBytes is the wipeable-bytes core of Peek.
func PeekBytes(bundle, importPassphrase []byte) (Identity, bool, error) {
	info, hwKey, _, err := PeekBytesFull(bundle, importPassphrase)
	return info, hwKey, err
}

// PeekBytesFull is PeekBytes plus the bundle's hardware-key challenge bytes
// (nil when the identity is not HW-protected). The challenge is not secret —
// security comes from the device's HMAC — so callers may surface it to drive
// the platform hardware-key ceremony (e.g. an NFC tap) during import.
func PeekBytesFull(bundle, importPassphrase []byte) (Identity, bool, []byte, error) {
	if len(importPassphrase) == 0 {
		return Identity{}, false, nil, fmt.Errorf("import passphrase cannot be empty")
	}
	plaintext, err := crypto.DecryptWithPassphraseBytes(bundle, importPassphrase)
	if err != nil {
		return Identity{}, false, nil, fmt.Errorf("decrypting bundle (wrong passphrase?): %w", err)
	}
	defer wipeBytes(plaintext)

	var pb portableBundle
	if err := json.Unmarshal(plaintext, &pb); err != nil {
		return Identity{}, false, nil, fmt.Errorf("parsing bundle: %w", err)
	}
	defer wipeString(&pb.EncryptionIdentity)
	defer wipeString(&pb.SigningPrivateKey)

	if pb.Info.Name == "" {
		return Identity{}, false, nil, fmt.Errorf("bundle is missing identity name")
	}
	// Copy the challenge out (non-secret) so it's decoupled from pb before the
	// deferred wipes run.
	var challenge []byte
	if len(pb.HWChallenge) > 0 {
		challenge = append([]byte(nil), pb.HWChallenge...)
	}
	return pb.Info, pb.HWKey, challenge, nil
}

// Import decrypts a bundle produced by Unlocked.Export and persists the
// keys into the given keystore under the bundle's identity name. The
// returned Identity is the metadata that was carried in the bundle —
// callers typically merge it into their identity store records.
//
// When the bundle carries HW state and restoreHW is non-nil, restoreHW is
// asked whether to preserve HW protection (see HWRestoreFn). If it returns
// a HW-decorated keystore, that keystore is used to store the keys (so
// they're encrypted with the HW-augmented KEK on this machine) and
// info.HWKey is set to true. Otherwise the keys are stored via the original
// ks and info.HWKey is set to false.
//
// Import is a free function (not a method on Unlocked) because the source
// of the bundle is bytes, not an unlocked handle.
func Import(bundle []byte, importPassphrase string, ks keystore.Keystore, restoreHW HWRestoreFn) (Identity, error) {
	return ImportBytes(bundle, []byte(importPassphrase), ks, restoreHW)
}

// ImportBytes is the wipeable-bytes core of Import.
func ImportBytes(bundle, importPassphrase []byte, ks keystore.Keystore, restoreHW HWRestoreFn) (Identity, error) {
	if len(importPassphrase) == 0 {
		return Identity{}, fmt.Errorf("import passphrase cannot be empty")
	}

	plaintext, err := crypto.DecryptWithPassphraseBytes(bundle, importPassphrase)
	if err != nil {
		return Identity{}, fmt.Errorf("decrypting bundle (wrong passphrase?): %w", err)
	}
	defer wipeBytes(plaintext)

	var pb portableBundle
	if err := json.Unmarshal(plaintext, &pb); err != nil {
		return Identity{}, fmt.Errorf("parsing bundle: %w", err)
	}
	defer wipeString(&pb.EncryptionIdentity)
	defer wipeString(&pb.SigningPrivateKey)

	// The name arrives from an untrusted bundle and is later used as a
	// filesystem path component (keystore + identity meta store). Validate it
	// at the library boundary so every consumer — not just profile.Import — is
	// protected against path traversal (e.g. a crafted "../../…" name).
	if err := validate.ValidateName(pb.Info.Name); err != nil {
		return Identity{}, fmt.Errorf("invalid identity name in bundle: %w", err)
	}

	sigKey, err := base64.StdEncoding.DecodeString(pb.SigningPrivateKey)
	if err != nil {
		return Identity{}, fmt.Errorf("decoding signing key: %w", err)
	}
	defer wipeBytes(sigKey)

	info := pb.Info
	targetKS := ks
	info.HWKey = false

	// Bind the advertised public fields to the actual imported PRIVATE keys.
	// The bundle's self-reported EncPubKey/SignPubKey/Fingerprint are not covered
	// by any signature, so trusting them lets a crafted bundle publish
	// attacker-chosen public keys / poison the index fingerprint (the value the
	// cloud anti-takeover gate reads) / encrypt meta to a key the identity can't
	// decrypt. Recompute from the private keys and reject any disagreement.
	encPub, signPubB64, _, fp, derr := crypto.DerivePublic(pb.EncryptionIdentity, sigKey)
	if derr != nil {
		return Identity{}, fmt.Errorf("deriving public keys from imported private keys: %w", derr)
	}
	if info.EncPubKey != "" && info.EncPubKey != encPub {
		return Identity{}, fmt.Errorf("bundle encryption public key does not match its private key")
	}
	if info.SignPubKey != "" && info.SignPubKey != signPubB64 {
		return Identity{}, fmt.Errorf("bundle signing public key does not match its private key")
	}
	if info.Fingerprint != "" && info.Fingerprint != fp {
		return Identity{}, fmt.Errorf("bundle fingerprint does not match its keys")
	}
	info.EncPubKey = encPub
	info.SignPubKey = signPubB64
	info.Fingerprint = fp

	// The alias is an unauthenticated label; normalize + validate it (drop on
	// failure) so a malicious bundle can't inject control/bidi/oversized text or
	// a non-conforming handle into the plaintext index.
	info.Alias = validate.NormalizeAlias(info.Alias)

	if pb.HWKey && restoreHW != nil {
		hwKS, err := restoreHW(pb.HWChallenge)
		if err != nil {
			return Identity{}, fmt.Errorf("hardware key restore: %w", err)
		}
		if hwKS != nil {
			targetKS = hwKS
			info.HWKey = true
		}
	}

	// Refuse to clobber an existing identity's keys. Silently overwriting them
	// on a name collision would enable key substitution/destruction (and on
	// darwin the delete-then-add can lose the original on a mid-op failure).
	// Return the ErrKeysExist sentinel so callers can distinguish a genuine
	// duplicate from an orphaned partial import (keys stored, never indexed)
	// and offer a reconcile path. Return the DERIVED-and-verified info (not the
	// bundle's self-report) so a reconcile persists key-bound public fields.
	if targetKS.HasKeys(info.Name) {
		return info, fmt.Errorf("identity %q: %w", info.Name, ErrKeysExist)
	}

	if err := targetKS.StoreEncryptionIdentity(info.Name, pb.EncryptionIdentity); err != nil {
		return Identity{}, fmt.Errorf("storing encryption identity: %w", err)
	}
	if err := targetKS.StoreSigningKey(info.Name, sigKey); err != nil {
		return Identity{}, fmt.Errorf("storing signing key: %w", err)
	}

	return info, nil
}
