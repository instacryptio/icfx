package bundle

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// Rotation/revocation authenticity.
//
// A rotation carries the NEW lock (self-signed by the new key) plus a
// continuity signature by the OLD key over the whole rotation — proving the
// holder of the previously-trusted key authorized the move. A revocation
// carries a signature by the key being revoked. Verify-before-apply checks
// these against the key already stored for the contact, so a stranger cannot
// silently substitute or revoke a contact's keys.

const (
	revokeCanonicalTag = "ICFX-REVOKE-V1"
	rotateCanonicalTag = "ICFX-ROTATE-V1"
)

// ErrBundleSigInvalid reports a missing or invalid authenticity signature.
var ErrBundleSigInvalid = errors.New("bundle signature is missing or invalid")

// ErrContinuityMismatch reports that a rotation/revocation does not correspond
// to the contact it targets (wrong revoked fingerprint or IC ID).
var ErrContinuityMismatch = errors.New("rotation/revocation does not match the target contact")

// Signer signs with an identity's signing key — an unlocked identity satisfies it.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

func writeField(buf *bytes.Buffer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}

func writeStr(buf *bytes.Buffer, s string) { writeField(buf, []byte(s)) }

// CanonicalRevocationBytes builds the deterministic bytes signed for a
// revocation. The Sig field is never covered.
func CanonicalRevocationBytes(rev RevocationBundle) []byte {
	var b bytes.Buffer
	writeStr(&b, revokeCanonicalTag)
	writeStr(&b, rev.ID)
	writeStr(&b, rev.RevokedFingerprint)
	writeStr(&b, rev.RevokedAt)
	return b.Bytes()
}

// CanonicalRotationBytes builds the deterministic bytes signed (by the OLD key)
// for a rotation. It binds the revocation triple and the entire new lock,
// including the new lock's own self-signature, so neither half can be swapped.
func CanonicalRotationBytes(rot RotationBundle) []byte {
	var b bytes.Buffer
	writeStr(&b, rotateCanonicalTag)
	writeStr(&b, rot.Revocation.ID)
	writeStr(&b, rot.Revocation.RevokedFingerprint)
	writeStr(&b, rot.Revocation.RevokedAt)
	writeField(&b, qr.CanonicalLockBytes(rot.NewLock))
	writeStr(&b, rot.NewLock.Sig)
	return b.Bytes()
}

// SealRevocation signs rev with the revoked key's signer and returns it with
// Sig set.
func SealRevocation(s Signer, rev RevocationBundle) (RevocationBundle, error) {
	sig, err := s.Sign(CanonicalRevocationBytes(rev))
	if err != nil {
		return RevocationBundle{}, fmt.Errorf("signing revocation: %w", err)
	}
	rev.Sig = base64.StdEncoding.EncodeToString(sig)
	return rev, nil
}

// SealRotation signs rot with the OLD key's signer (continuity) and returns it
// with the top-level Sig set. The caller must have already sealed rot.NewLock
// with the new key (qr.SealLock).
func SealRotation(s Signer, rot RotationBundle) (RotationBundle, error) {
	sig, err := s.Sign(CanonicalRotationBytes(rot))
	if err != nil {
		return RotationBundle{}, fmt.Errorf("signing rotation: %w", err)
	}
	rot.Sig = base64.StdEncoding.EncodeToString(sig)
	return rot, nil
}

// VerifyLockForAdd verifies a lock arriving on a first-contact (add) path.
// First contact is trust-on-first-use, anchored by the human comparing the
// fingerprint out-of-band: the fingerprint binding (Fingerprint == hash of the
// actual keys) is the real check and is REQUIRED. A self-signature adds no
// first-contact protection — a MITM simply signs their own substituted lock —
// so it is ADVISORY here: verified when present (catches tampering/corruption),
// never required. This is why unsigned locks shared out-of-band (a re-shared
// contact lock, an older identity's lock) import fine. The self-signature is
// enforced where it actually matters: continuity on rotations (VerifyRotation)
// and sealed relay channels (which call qr.VerifyLockSelfSig directly).
func VerifyLockForAdd(parsed *ParsedBundle) error {
	if parsed.Lock == nil {
		return fmt.Errorf("no lock to verify")
	}
	if err := qr.VerifyFingerprint(*parsed.Lock); err != nil {
		return err
	}
	if parsed.Lock.Sig != "" {
		return qr.VerifyLockSelfSig(*parsed.Lock) // present ⇒ must be valid
	}
	return nil
}

// VerifyRotation verifies a rotation against the key currently stored for the
// target contact: the new lock self-signs, the fingerprint binds, the old key
// signed the transition (continuity), and the revocation names this contact.
func VerifyRotation(parsed *ParsedBundle, existing *contacts.Contact) error {
	if parsed.Lock == nil || parsed.Revocation == nil {
		return fmt.Errorf("rotation missing lock or revocation")
	}
	if existing == nil {
		return fmt.Errorf("no existing contact to verify continuity against")
	}
	if err := qr.VerifyLockSelfSig(*parsed.Lock); err != nil {
		return err
	}
	if err := verifyContinuity(*parsed.Revocation, existing); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(parsed.Sig)
	if err != nil {
		return fmt.Errorf("decoding rotation signature: %w", err)
	}
	oldPub, err := base64.StdEncoding.DecodeString(existing.SignPubKey)
	if err != nil {
		return fmt.Errorf("decoding stored contact key: %w", err)
	}
	rot := RotationBundle{Revocation: *parsed.Revocation, NewLock: *parsed.Lock, Sig: parsed.Sig}
	ok, err := crypto.Verify(CanonicalRotationBytes(rot), sig, oldPub)
	if err != nil {
		return fmt.Errorf("verifying rotation signature: %w", err)
	}
	if !ok {
		return ErrBundleSigInvalid
	}
	return nil
}

// VerifyRevocation verifies a revocation against the target contact's stored
// key: the revoked key signed it and the revocation names this contact.
func VerifyRevocation(parsed *ParsedBundle, existing *contacts.Contact) error {
	if parsed.Revocation == nil {
		return fmt.Errorf("no revocation to verify")
	}
	if existing == nil {
		return fmt.Errorf("no existing contact to verify against")
	}
	if err := verifyContinuity(*parsed.Revocation, existing); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(parsed.Sig)
	if err != nil {
		return fmt.Errorf("decoding revocation signature: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(existing.SignPubKey)
	if err != nil {
		return fmt.Errorf("decoding stored contact key: %w", err)
	}
	ok, err := crypto.Verify(CanonicalRevocationBytes(*parsed.Revocation), sig, pub)
	if err != nil {
		return fmt.Errorf("verifying revocation signature: %w", err)
	}
	if !ok {
		return ErrBundleSigInvalid
	}
	return nil
}

// verifyContinuity confirms a revocation names the contact it targets: the
// revoked fingerprint must match the contact's current fingerprint and the IC
// ID must match. Constant-time compared.
func verifyContinuity(rev RevocationBundle, existing *contacts.Contact) error {
	if subtle.ConstantTimeCompare([]byte(rev.RevokedFingerprint), []byte(existing.Fingerprint)) != 1 {
		return ErrContinuityMismatch
	}
	if existing.ID != "" && rev.ID != existing.ID {
		return ErrContinuityMismatch
	}
	return nil
}
