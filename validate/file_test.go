package validate

import (
	"encoding/binary"
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
)

// container hand-builds an unsigned ProfilePrivate container around an age
// payload (the encrypt package cannot be imported here without a cycle).
func container(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := append([]byte{}, format.MagicBytes...)
	buf = append(buf, byte(format.ProfilePrivate))
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(payload)))
	buf = append(buf, payload...)
	return binary.BigEndian.AppendUint16(buf, 0)
}

func TestValidateICFXFile(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}
	encrypted, err := crypto.Encrypt([]byte("test data"), []string{kp.EncryptionRecipient})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	armored := format.ArmorEncode([]byte("some payload"), format.ArmorLockLabel)
	whole := container(t, encrypted)
	truncated := whole[:len(whole)-3] // signature-length field cut off

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid container", whole, false},
		{"valid age encrypted", encrypted, false},
		{"valid armored", armored, false},
		{"empty", nil, true},
		{"random bytes", []byte("this is not encrypted at all"), true},
		{"truncated ICFX magic", []byte("ICFX"), true},
		{"unknown profile", []byte("ICFX\x09\x00\x00rest"), true},
		{"truncated container", truncated, true},
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
