package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveHardwareKEK_Deterministic(t *testing.T) {
	pass := "correct horse battery staple"
	resp := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14}

	k1, err := DeriveHardwareKEK(pass, resp)
	if err != nil {
		t.Fatalf("DeriveHardwareKEK: %v", err)
	}
	k2, err := DeriveHardwareKEK(pass, resp)
	if err != nil {
		t.Fatalf("DeriveHardwareKEK (second call): %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Errorf("derivation not deterministic:\nk1=%x\nk2=%x", k1, k2)
	}
	if len(k1) != hardwareKEKLength {
		t.Errorf("KEK length = %d, want %d", len(k1), hardwareKEKLength)
	}
}

func TestDeriveHardwareKEK_DifferentPassphrase(t *testing.T) {
	resp := []byte("hardware response bytes 12345")

	k1, _ := DeriveHardwareKEK("password1", resp)
	k2, _ := DeriveHardwareKEK("password2", resp)

	if bytes.Equal(k1, k2) {
		t.Errorf("different passphrases produced same KEK")
	}
}

func TestDeriveHardwareKEK_DifferentResponse(t *testing.T) {
	pass := "samepass"

	k1, _ := DeriveHardwareKEK(pass, []byte("response one"))
	k2, _ := DeriveHardwareKEK(pass, []byte("response two"))

	if bytes.Equal(k1, k2) {
		t.Errorf("different responses produced same KEK")
	}
}

func TestDeriveHardwareKEK_EmptyResponse(t *testing.T) {
	_, err := DeriveHardwareKEK("pass", []byte{})
	if err == nil {
		t.Errorf("expected error for empty hardware response")
	}
}

// An all-zero hardware response is degenerate (it would nullify the hardware
// factor) and must be rejected — a genuine HMAC-SHA1 is never all-zero; an
// all-zero salt signals a malfunctioning or non-genuine device.
func TestDeriveHardwareKEK_AllZeroResponseRejected(t *testing.T) {
	if _, err := DeriveHardwareKEK("pass", make([]byte, 20)); err == nil {
		t.Errorf("expected error for all-zero hardware response")
	}
	// A single non-zero byte makes it non-degenerate and derives normally.
	nonzero := make([]byte, 20)
	nonzero[19] = 0x01
	if _, err := DeriveHardwareKEK("pass", nonzero); err != nil {
		t.Errorf("non-degenerate response should derive: %v", err)
	}
}

// An EMPTY passphrase must be accepted: keychain-origin identities (HWKEKNone)
// derive the KEK from the hardware response alone, with the OS keychain as the
// second factor. Rejecting it here breaks HW-only keychain unlock (regression
// guard — see ic-app hwPassFnForKEK(HWKEKNone)).
func TestDeriveHardwareKEK_EmptyPassphraseAllowed(t *testing.T) {
	kek, err := DeriveHardwareKEKBytes([]byte{}, []byte("device-response"))
	if err != nil {
		t.Fatalf("empty passphrase must be allowed (HWKEKNone), got error: %v", err)
	}
	if len(kek) != hardwareKEKLength {
		t.Fatalf("KEK length = %d, want %d", len(kek), hardwareKEKLength)
	}
}
