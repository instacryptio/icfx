package bundle

import (
	"encoding/base64"
	"testing"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

type rawSigner struct{ key []byte }

func (r rawSigner) Sign(data []byte) ([]byte, error) { return crypto.Sign(data, r.key) }

// makeSealedLock returns a self-signed lock plus its keypair.
func makeSealedLock(t *testing.T, id, name string) (qr.LockBundle, *crypto.KeyPair) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	lb := qr.LockBundle{
		ID:          id,
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
	}
	sealed, err := qr.SealLock(rawSigner{kp.SigningPrivateKey}, lb)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed, kp
}

func contactFor(lb qr.LockBundle) *contacts.Contact {
	return &contacts.Contact{
		ID:          lb.ID,
		Alias:       lb.Name,
		EncPubKey:   lb.EncPubKey,
		SignPubKey:  lb.SignPubKey,
		Fingerprint: lb.Fingerprint,
	}
}

// TestVerifyLockForAdd covers the fingerprint-anchored first-contact add path:
// the fingerprint binding is required; the self-signature is advisory (verified
// when present, not required). This is what lets an out-of-band lock shared
// without a signature (a re-shared contact lock, an older identity's lock)
// import, while still rejecting a tampered fingerprint or a bad signature.
func TestVerifyLockForAdd(t *testing.T) {
	signed, _ := makeSealedLock(t, "ic-alice", "alice")

	t.Run("valid signed lock", func(t *testing.T) {
		if err := VerifyLockForAdd(&ParsedBundle{Lock: &signed}); err != nil {
			t.Fatalf("valid signed lock rejected: %v", err)
		}
	})

	t.Run("unsigned lock with correct fingerprint", func(t *testing.T) {
		unsigned := signed
		unsigned.Sig = "" // out-of-band lock with no self-signature
		if err := VerifyLockForAdd(&ParsedBundle{Lock: &unsigned}); err != nil {
			t.Fatalf("unsigned lock with a valid fingerprint must be accepted: %v", err)
		}
	})

	t.Run("present but invalid signature", func(t *testing.T) {
		other, _ := makeSealedLock(t, "ic-bob", "bob")
		bad := signed
		bad.Sig = other.Sig // valid base64, wrong signature for these keys
		if err := VerifyLockForAdd(&ParsedBundle{Lock: &bad}); err == nil {
			t.Fatal("a present-but-invalid signature must be rejected")
		}
	})

	t.Run("fingerprint mismatch", func(t *testing.T) {
		forged := signed
		forged.Sig = "" // even unsigned, a broken binding must be rejected
		forged.Fingerprint = "deadbeef" + forged.Fingerprint[8:]
		if err := VerifyLockForAdd(&ParsedBundle{Lock: &forged}); err == nil {
			t.Fatal("a fingerprint that does not bind the keys must be rejected")
		}
	})

	t.Run("nil lock", func(t *testing.T) {
		if err := VerifyLockForAdd(&ParsedBundle{}); err == nil {
			t.Fatal("nil lock must error")
		}
	})
}

// TestVerifyRotation_RoundTrip: Alice is a saved contact; she rotates. The new
// lock self-signs with the new key; the rotation is signed by the OLD key.
// Verification against Alice's stored (old) key succeeds.
func TestVerifyRotation_RoundTrip(t *testing.T) {
	oldLock, oldKP := makeSealedLock(t, "ic-alice", "alice")
	existing := contactFor(oldLock)

	newLock, _ := makeSealedLock(t, "ic-alice", "alice") // same IC-ID, new keys
	rot := RotationBundle{
		Revocation: NewRevocation(oldLock.ID, oldLock.Fingerprint),
		NewLock:    newLock,
	}
	rot, err := SealRotation(rawSigner{oldKP.SigningPrivateKey}, rot)
	if err != nil {
		t.Fatalf("seal rotation: %v", err)
	}

	parsed := &ParsedBundle{Type: BundleRotate, Lock: &rot.NewLock, Revocation: &rot.Revocation, Sig: rot.Sig}
	if err := VerifyRotation(parsed, existing); err != nil {
		t.Fatalf("valid rotation rejected: %v", err)
	}
}

func TestVerifyRotation_Tamper(t *testing.T) {
	oldLock, oldKP := makeSealedLock(t, "ic-alice", "alice")
	existing := contactFor(oldLock)
	newLock, _ := makeSealedLock(t, "ic-alice", "alice")
	seal := func(rot RotationBundle) *ParsedBundle {
		rot, err := SealRotation(rawSigner{oldKP.SigningPrivateKey}, rot)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return &ParsedBundle{Type: BundleRotate, Lock: &rot.NewLock, Revocation: &rot.Revocation, Sig: rot.Sig}
	}

	t.Run("wrong old key (attacker-signed)", func(t *testing.T) {
		_, attackerKP := makeSealedLock(t, "ic-x", "x")
		rot := RotationBundle{Revocation: NewRevocation(oldLock.ID, oldLock.Fingerprint), NewLock: newLock}
		rot, _ = SealRotation(rawSigner{attackerKP.SigningPrivateKey}, rot)
		parsed := &ParsedBundle{Type: BundleRotate, Lock: &rot.NewLock, Revocation: &rot.Revocation, Sig: rot.Sig}
		if err := VerifyRotation(parsed, existing); err == nil {
			t.Fatal("rotation signed by a non-stored key must be rejected")
		}
	})

	t.Run("revoked fingerprint mismatch", func(t *testing.T) {
		parsed := seal(RotationBundle{Revocation: NewRevocation(oldLock.ID, "ffffffffffffffffffffffffffffffff"), NewLock: newLock})
		if err := VerifyRotation(parsed, existing); err == nil {
			t.Fatal("wrong revoked fingerprint must be rejected")
		}
	})

	t.Run("swapped new lock", func(t *testing.T) {
		parsed := seal(RotationBundle{Revocation: NewRevocation(oldLock.ID, oldLock.Fingerprint), NewLock: newLock})
		attackerLock, _ := makeSealedLock(t, "ic-alice", "alice")
		parsed.Lock = &attackerLock // continuity sig no longer covers this lock
		if err := VerifyRotation(parsed, existing); err == nil {
			t.Fatal("swapped new lock must be rejected")
		}
	})

	t.Run("ID mismatch", func(t *testing.T) {
		parsed := seal(RotationBundle{Revocation: NewRevocation("ic-someone-else", oldLock.Fingerprint), NewLock: newLock})
		if err := VerifyRotation(parsed, existing); err == nil {
			t.Fatal("mismatched IC-ID must be rejected")
		}
	})
}

func TestVerifyRevocation_RoundTrip(t *testing.T) {
	lock, kp := makeSealedLock(t, "ic-alice", "alice")
	existing := contactFor(lock)
	rev := NewRevocation(lock.ID, lock.Fingerprint)
	rev, err := SealRevocation(rawSigner{kp.SigningPrivateKey}, rev)
	if err != nil {
		t.Fatalf("seal revocation: %v", err)
	}
	parsed := &ParsedBundle{Type: BundleRevoke, Revocation: &rev, Sig: rev.Sig}
	if err := VerifyRevocation(parsed, existing); err != nil {
		t.Fatalf("valid revocation rejected: %v", err)
	}

	// Attacker-signed revocation → rejected.
	_, attackerKP := makeSealedLock(t, "ic-x", "x")
	bad := NewRevocation(lock.ID, lock.Fingerprint)
	bad, _ = SealRevocation(rawSigner{attackerKP.SigningPrivateKey}, bad)
	parsedBad := &ParsedBundle{Type: BundleRevoke, Revocation: &bad, Sig: bad.Sig}
	if err := VerifyRevocation(parsedBad, existing); err == nil {
		t.Fatal("revocation signed by a non-stored key must be rejected")
	}
}

// TestCrossTypeReplay: a revocation signature must not verify as a rotation
// signature (distinct domain tags), and vice versa.
func TestCrossTypeReplay(t *testing.T) {
	lock, kp := makeSealedLock(t, "ic-alice", "alice")
	existing := contactFor(lock)

	rev := NewRevocation(lock.ID, lock.Fingerprint)
	rev, _ = SealRevocation(rawSigner{kp.SigningPrivateKey}, rev)

	// Try to pass the revocation's signature off as a rotation continuity sig.
	newLock, _ := makeSealedLock(t, "ic-alice", "alice")
	forged := &ParsedBundle{
		Type:       BundleRotate,
		Lock:       &newLock,
		Revocation: &rev,
		Sig:        rev.Sig, // revocation sig replayed as rotation sig
	}
	if err := VerifyRotation(forged, existing); err == nil {
		t.Fatal("revocation signature must not verify as a rotation signature")
	}
}

func TestParsedBundleCarriesSig(t *testing.T) {
	lock, kp := makeSealedLock(t, "ic-alice", "alice")
	rev := NewRevocation(lock.ID, lock.Fingerprint)
	rev, _ = SealRevocation(rawSigner{kp.SigningPrivateKey}, rev)
	raw, err := MarshalRevocation(rev)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Sig != rev.Sig {
		t.Fatalf("ParsedBundle.Sig not populated: got %q want %q", parsed.Sig, rev.Sig)
	}
}
