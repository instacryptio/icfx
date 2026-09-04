package validate

import (
	"strings"
	"testing"

	"github.com/instacryptio/icfx/crypto"
)

func TestValidateContactFields(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	tests := []struct {
		name        string
		alias       string
		encPubKey   string
		signPubKey  string
		fingerprint string
		email       string
		wantErr     bool
	}{
		{"valid minimal", "alice", kp.EncryptionRecipient, "", "", "", false},
		{"valid with email", "alice", kp.EncryptionRecipient, "", "", "alice@example.com", false},
		{"empty alias", "", kp.EncryptionRecipient, "", "", "", true},
		{"alias too long", strings.Repeat("a", 257), kp.EncryptionRecipient, "", "", "", true},
		{"empty enc key", "alice", "", "", "", "", true},
		{"invalid enc key", "alice", "not-a-key", "", "", "", true},
		{"invalid fingerprint", "alice", kp.EncryptionRecipient, "", "short", "", true},
		{"invalid email", "alice", kp.EncryptionRecipient, "", "", "bademail", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContactFields(tt.alias, tt.encPubKey, tt.signPubKey, tt.fingerprint, tt.email, "")
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContactFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
