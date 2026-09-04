package validate

import (
	"encoding/base64"
	"testing"

	"github.com/instacryptio/icfx/crypto"
)

func TestValidateEncPubKey(t *testing.T) {
	// Generate a real key pair for valid key tests
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid key", kp.EncryptionRecipient, false},
		{"empty", "", true},
		{"wrong prefix", "age1abc123", true},
		{"random string", "not-a-key-at-all", true},
		{"truncated", "age1pq1abc", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEncPubKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEncPubKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEncIdentity(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid identity", kp.EncryptionIdentity, false},
		{"empty", "", true},
		{"wrong prefix", "AGE-SECRET-KEY-1ABC", true},
		{"random string", "not-a-key", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEncIdentity(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEncIdentity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSignPubKey(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}
	validBase64 := base64.StdEncoding.EncodeToString(kp.SigningPublicKey)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid key", validBase64, false},
		{"empty", "", true},
		{"invalid base64", "not-valid-base64!!!", true},
		{"valid base64 wrong data", base64.StdEncoding.EncodeToString([]byte("short")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignPubKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSignPubKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSignPrivateKey(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{"valid key", kp.SigningPrivateKey, false},
		{"empty", nil, true},
		{"too short", []byte("short"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignPrivateKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSignPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
