package format

import (
	"errors"
	"testing"
	"time"
)

func TestSerializeDeserialize(t *testing.T) {
	original := &Container{
		Profile: ProfilePublicBuffered,
		Metadata: Metadata{
			SenderFingerprint: "a1b2c3d4e5f6abcd",
			Timestamp:         time.Now().Truncate(time.Second),
			OriginalFilename:  "test.txt",
			IsSigned:          true,
		},
		Payload:   []byte("encrypted-payload-data"),
		Signature: []byte("signature-bytes"),
	}

	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	parsed, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize() error: %v", err)
	}

	if parsed.Profile != original.Profile {
		t.Errorf("Profile = %#x, want %#x", byte(parsed.Profile), byte(original.Profile))
	}
	if parsed.Metadata.SenderFingerprint != original.Metadata.SenderFingerprint {
		t.Errorf("SenderFingerprint = %q, want %q", parsed.Metadata.SenderFingerprint, original.Metadata.SenderFingerprint)
	}
	if parsed.Metadata.OriginalFilename != original.Metadata.OriginalFilename {
		t.Errorf("OriginalFilename = %q, want %q", parsed.Metadata.OriginalFilename, original.Metadata.OriginalFilename)
	}
	if parsed.Metadata.IsSigned != original.Metadata.IsSigned {
		t.Errorf("IsSigned = %v, want %v", parsed.Metadata.IsSigned, original.Metadata.IsSigned)
	}
	if string(parsed.Payload) != string(original.Payload) {
		t.Errorf("Payload mismatch")
	}
	if string(parsed.Signature) != string(original.Signature) {
		t.Errorf("Signature mismatch")
	}
}

func TestSerializeDeserializeUnsigned(t *testing.T) {
	original := &Container{
		Profile: ProfilePublicBuffered,
		Metadata: Metadata{
			SenderFingerprint: "abcdef0123456789",
			Timestamp:         time.Now().Truncate(time.Second),
			OriginalFilename:  "unsigned.txt",
			IsSigned:          false,
		},
		Payload:   []byte("payload"),
		Signature: nil,
	}

	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	parsed, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize() error: %v", err)
	}

	if parsed.Metadata.IsSigned {
		t.Error("IsSigned should be false")
	}
	if len(parsed.Signature) != 0 {
		t.Error("Signature should be empty")
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Format
	}{
		{"ICFX", []byte("ICFX\x01rest-of-data"), FormatICFX},
		{"age", []byte("age-encryption.org/v1\n..."), FormatAge},
		{"unknown", []byte("random data"), FormatUnknown},
		{"empty", []byte{}, FormatUnknown},
		{"short", []byte("IC"), FormatUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.data)
			if got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	tests := []struct {
		f    Format
		want string
	}{
		{FormatICFX, "icfx"},
		{FormatAge, "age"},
		{FormatUnknown, "unknown"},
	}

	for _, tt := range tests {
		if got := tt.f.String(); got != tt.want {
			t.Errorf("Format(%d).String() = %q, want %q", tt.f, got, tt.want)
		}
	}
}

func TestDeserializeInvalidMagic(t *testing.T) {
	_, err := Deserialize([]byte("NOPE\x01\x00\x00"))
	if !errors.Is(err, ErrInvalidMagic) {
		t.Errorf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestDeserializeTooShort(t *testing.T) {
	_, err := Deserialize([]byte("ICFX"))
	if !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}
