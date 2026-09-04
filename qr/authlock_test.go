package qr

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/instacryptio/icfx/crypto"
)

type rawSigner struct{ key []byte }

func (r rawSigner) Sign(data []byte) ([]byte, error) { return crypto.Sign(data, r.key) }

func sealedLock(t *testing.T) (LockBundle, *crypto.KeyPair) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	lb := LockBundle{
		ID:          "ic-alice",
		Name:        "alice",
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
		Email:       "alice@x.io",
		Alias:       "al",
	}
	sealed, err := SealLock(rawSigner{kp.SigningPrivateKey}, lb)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed, kp
}

func TestSealVerifyRoundTrip(t *testing.T) {
	lb, _ := sealedLock(t)
	if err := VerifyLockSelfSig(lb); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
	if err := VerifyFingerprint(lb); err != nil {
		t.Fatalf("fingerprint binding failed: %v", err)
	}
}

func TestVerifyLockSelfSig_TamperCoveredFields(t *testing.T) {
	base, _ := sealedLock(t)
	// Each covered field, when altered, must break the signature (or the
	// fingerprint binding, which is checked first — either is a rejection).
	cases := map[string]func(*LockBundle){
		"ID":          func(l *LockBundle) { l.ID = "ic-mallory" },
		"EncPubKey":   func(l *LockBundle) { l.EncPubKey = l.EncPubKey + "x" },
		"Fingerprint": func(l *LockBundle) { l.Fingerprint = base.Fingerprint[:30] + "ff" },
	}
	for name, mutate := range cases {
		lb := base
		mutate(&lb)
		if err := VerifyLockSelfSig(lb); err == nil {
			t.Errorf("%s tamper: verify unexpectedly passed", name)
		}
	}
}

func TestVerifyLockSelfSig_LabelEditStillValid(t *testing.T) {
	lb, _ := sealedLock(t)
	lb.Name = "renamed"
	lb.Email = "new@x.io"
	lb.Alias = "nn"
	if err := VerifyLockSelfSig(lb); err != nil {
		t.Fatalf("label edit must not break self-sig: %v", err)
	}
}

func TestVerifyLockSelfSig_MissingSig(t *testing.T) {
	lb, _ := sealedLock(t)
	lb.Sig = ""
	if err := VerifyLockSelfSig(lb); !errors.Is(err, ErrLockSigInvalid) {
		t.Fatalf("missing sig: got %v, want ErrLockSigInvalid", err)
	}
}

func TestVerifyFingerprint_Mismatch(t *testing.T) {
	lb, _ := sealedLock(t)
	lb.Fingerprint = "00000000000000000000000000000000"
	if err := VerifyFingerprint(lb); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("fingerprint mismatch: got %v, want ErrFingerprintMismatch", err)
	}
}

func TestVerifyLockSelfSig_WrongKey(t *testing.T) {
	lb, _ := sealedLock(t)
	// Swap in a different signing key (and its fingerprint would differ, so
	// the binding catches it first) — either way it must be rejected.
	other, _ := sealedLock(t)
	lb.SignPubKey = other.SignPubKey
	if err := VerifyLockSelfSig(lb); err == nil {
		t.Fatal("swapped signing key must be rejected")
	}
}

func TestCanonicalLockBytes_ExcludesSig(t *testing.T) {
	lb, _ := sealedLock(t)
	a := CanonicalLockBytes(lb)
	lb2 := lb
	lb2.Sig = "different"
	b := CanonicalLockBytes(lb2)
	if string(a) != string(b) {
		t.Fatal("canonical bytes must not depend on Sig")
	}
	// Label fields are excluded too.
	lb3 := lb
	lb3.Name = "zzz"
	lb3.Email = "zzz@x.io"
	if string(CanonicalLockBytes(lb3)) != string(a) {
		t.Fatal("canonical bytes must not depend on labels")
	}
}
