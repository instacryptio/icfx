package crypto

import (
	"encoding/base64"
	"testing"
)

// TestDerivePublic confirms the public fields recomputed from private keys match
// what GenerateKeyPair produced — the property ImportBytes relies on to reject a
// bundle whose self-reported public fields don't match its private keys.
func TestDerivePublic(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	encPub, signPubB64, signPub, fp, err := DerivePublic(kp.EncryptionIdentity, kp.SigningPrivateKey)
	if err != nil {
		t.Fatalf("DerivePublic: %v", err)
	}
	if encPub != kp.EncryptionRecipient {
		t.Errorf("encPub mismatch:\n got  %q\n want %q", encPub, kp.EncryptionRecipient)
	}
	if signPubB64 != base64.StdEncoding.EncodeToString(kp.SigningPublicKey) {
		t.Errorf("signPub base64 mismatch")
	}
	if string(signPub) != string(kp.SigningPublicKey) {
		t.Errorf("signPub bytes mismatch")
	}
	if fp != kp.Fingerprint {
		t.Errorf("fingerprint mismatch:\n got  %q\n want %q", fp, kp.Fingerprint)
	}

	// A mismatched signing key derives a different fingerprint — the tamper
	// ImportBytes rejects.
	kp2, _ := GenerateKeyPair()
	_, _, _, fp2, err := DerivePublic(kp.EncryptionIdentity, kp2.SigningPrivateKey)
	if err != nil {
		t.Fatalf("DerivePublic(mixed): %v", err)
	}
	if fp2 == kp.Fingerprint {
		t.Error("mixing a different signing key must change the fingerprint")
	}
}
