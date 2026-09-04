package validate

import (
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
)

func TestValidateICFXFile(t *testing.T) {
	// Generate a real encrypted file for valid test
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}
	encrypted, err := crypto.Encrypt([]byte("test data"), []string{kp.EncryptionRecipient})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// Create an armored file
	armored := format.ArmorEncode([]byte("some payload"), format.ArmorLockLabel)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid age encrypted", encrypted, false},
		{"valid armored", armored, false},
		{"empty", nil, true},
		{"random bytes", []byte("this is not encrypted at all"), true},
		{"truncated ICFX magic", []byte("ICFX"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateICFXFile(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateICFXFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
