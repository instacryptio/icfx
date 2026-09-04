package validate

import (
	"encoding/base64"
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

func TestValidateLockBundle(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}
	fp := crypto.Fingerprint(kp.EncryptionRecipient, kp.SigningPublicKey)

	validBundle := qr.LockBundle{
		Name:        "test",
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: fp,
		Email:       "test@example.com",
	}

	tests := []struct {
		name    string
		bundle  qr.LockBundle
		wantErr bool
	}{
		{"valid complete", validBundle, false},
		{"valid minimal", qr.LockBundle{Name: "test", EncPubKey: kp.EncryptionRecipient}, false},
		{"missing name", qr.LockBundle{EncPubKey: kp.EncryptionRecipient}, true},
		{"missing enc key", qr.LockBundle{Name: "test"}, true},
		{"invalid enc key", qr.LockBundle{Name: "test", EncPubKey: "bad-key"}, true},
		{"invalid sign key", qr.LockBundle{Name: "test", EncPubKey: kp.EncryptionRecipient, SignPubKey: "not-base64!!!"}, true},
		{"invalid fingerprint", qr.LockBundle{Name: "test", EncPubKey: kp.EncryptionRecipient, Fingerprint: "tooshort"}, true},
		{"invalid email", qr.LockBundle{Name: "test", EncPubKey: kp.EncryptionRecipient, Email: "notanemail"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLockBundle(tt.bundle)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLockBundle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
