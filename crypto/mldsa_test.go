package crypto

import "testing"

// TestSigningIsMLDSA65 pins the signing algorithm to FIPS 204 ML-DSA-65 by its
// exact key/signature byte sizes, and exercises a full sign→verify round trip.
// It is a guard against an accidental algorithm change (e.g. reverting to the
// pre-standard Dilithium mode3, whose sizes are 4000/3293) going unnoticed —
// the failure mode that shipped a wrong "ML-DSA" claim for months.
func TestSigningIsMLDSA65(t *testing.T) {
	const (
		mldsa65PubKeySize  = 1952
		mldsa65PrivKeySize = 4032
		mldsa65SigSize     = 3309
	)

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if got := len(kp.SigningPublicKey); got != mldsa65PubKeySize {
		t.Errorf("sign pubkey = %d bytes, want %d (ML-DSA-65)", got, mldsa65PubKeySize)
	}
	if got := len(kp.SigningPrivateKey); got != mldsa65PrivKeySize {
		t.Errorf("sign privkey = %d bytes, want %d (ML-DSA-65)", got, mldsa65PrivKeySize)
	}

	msg := []byte("the quick brown fox")
	sig, err := Sign(msg, kp.SigningPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(sig); got != mldsa65SigSize {
		t.Errorf("signature = %d bytes, want %d (ML-DSA-65)", got, mldsa65SigSize)
	}

	ok, err := Verify(msg, sig, kp.SigningPublicKey)
	if err != nil || !ok {
		t.Fatalf("Verify(valid) = %v, %v; want true, nil", ok, err)
	}
	if tampered, _ := Verify([]byte("the quick brown FOX"), sig, kp.SigningPublicKey); tampered {
		t.Error("Verify accepted a tampered message")
	}

	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(other): %v", err)
	}
	if wrong, _ := Verify(msg, sig, other.SigningPublicKey); wrong {
		t.Error("Verify accepted a signature under the wrong key")
	}
}
