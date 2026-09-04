package qr

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/instacryptio/icfx/crypto"
)

// Lock authentication: self-signed locks + fingerprint binding.
//
// A lock's Sig is an ML-DSA-65 signature by the identity's OWN signing key over
// a canonical, domain-tagged byte string of the key-binding fields. Combined
// with fingerprint binding (Fingerprint == hash of the actual keys), this makes
// the out-of-band fingerprint check meaningful and makes locks tamper-evident.
// It is NOT first-contact MITM protection — first contact stays trust-on-first-
// use, anchored by the human comparing the fingerprint.

// lockCanonicalTag domain-separates lock signatures from rotation/revocation
// signatures so one can never be replayed as another.
const lockCanonicalTag = "ICFX-LOCK-V1"

// ErrFingerprintMismatch reports that a lock's Fingerprint does not match a
// hash of its actual EncPubKey+SignPubKey — the binding is broken (or forged).
var ErrFingerprintMismatch = errors.New("fingerprint does not match the lock's keys")

// ErrLockSigInvalid reports that a lock's self-signature is missing or invalid.
var ErrLockSigInvalid = errors.New("lock self-signature is missing or invalid")

// LockSigner is anything that can sign with an identity's signing key — an
// unlocked identity satisfies it.
type LockSigner interface {
	Sign(data []byte) ([]byte, error)
}

// writeField appends an 8-byte big-endian length prefix then the raw bytes.
// Length-prefixing makes the concatenation unambiguous regardless of contents.
func writeField(buf *bytes.Buffer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}

func writeStr(buf *bytes.Buffer, s string) { writeField(buf, []byte(s)) }

// CanonicalLockBytes builds the exact deterministic bytes signed for a lock's
// self-signature. It covers only the key-binding fields (ID, EncPubKey,
// SignPubKey, Fingerprint); Name/Email/Alias are advisory labels and are
// deliberately excluded so editing them never requires re-sealing (and thus
// never needs the private key). The Sig field itself is never covered.
func CanonicalLockBytes(lb LockBundle) []byte {
	var b bytes.Buffer
	writeStr(&b, lockCanonicalTag)
	writeStr(&b, lb.ID)
	writeStr(&b, lb.EncPubKey)
	writeStr(&b, lb.SignPubKey)
	writeStr(&b, lb.Fingerprint)
	return b.Bytes()
}

// SealLock returns a copy of lb with Sig set to a self-signature over its
// canonical bytes, produced by signer (the identity that owns SignPubKey).
func SealLock(signer LockSigner, lb LockBundle) (LockBundle, error) {
	sig, err := signer.Sign(CanonicalLockBytes(lb))
	if err != nil {
		return LockBundle{}, fmt.Errorf("signing lock: %w", err)
	}
	lb.Sig = base64.StdEncoding.EncodeToString(sig)
	return lb, nil
}

// VerifyFingerprint enforces the binding that makes out-of-band verification
// real: the Fingerprint field must equal a hash of the ACTUAL keys, not a
// self-asserted string. Constant-time compared.
func VerifyFingerprint(lb LockBundle) error {
	signPub, err := base64.StdEncoding.DecodeString(lb.SignPubKey)
	if err != nil {
		return fmt.Errorf("decoding sign pub key: %w", err)
	}
	want := crypto.Fingerprint(lb.EncPubKey, signPub)
	if subtle.ConstantTimeCompare([]byte(want), []byte(lb.Fingerprint)) != 1 {
		return ErrFingerprintMismatch
	}
	return nil
}

// VerifyLockSelfSig verifies a lock's self-signature against its own SignPubKey
// AND enforces fingerprint binding. Use this on every peer/cloud channel where
// a lock arrives sealed (directory hits, friend requests/accepts, rotations).
// A lock with no Sig is rejected — callers that legitimately accept unsigned
// locks (manual entry) should call VerifyFingerprint directly instead.
func VerifyLockSelfSig(lb LockBundle) error {
	if lb.Sig == "" {
		return ErrLockSigInvalid
	}
	if err := VerifyFingerprint(lb); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(lb.Sig)
	if err != nil {
		return fmt.Errorf("decoding lock signature: %w", err)
	}
	signPub, err := base64.StdEncoding.DecodeString(lb.SignPubKey)
	if err != nil {
		return fmt.Errorf("decoding sign pub key: %w", err)
	}
	ok, err := crypto.Verify(CanonicalLockBytes(lb), sig, signPub)
	if err != nil {
		return fmt.Errorf("verifying lock signature: %w", err)
	}
	if !ok {
		return ErrLockSigInvalid
	}
	return nil
}
