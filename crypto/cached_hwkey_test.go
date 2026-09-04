package crypto

import (
	"bytes"
	"testing"
)

func TestCachedHWResponse_Basic(t *testing.T) {
	resp := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}

	c, err := NewCachedHWResponse(resp, "12345", "yubikey")
	if err != nil {
		t.Fatalf("NewCachedHWResponse: %v", err)
	}
	if got := c.Serial(); got != "12345" {
		t.Errorf("Serial: got %q, want %q", got, "12345")
	}
	if got := c.Type(); got != "yubikey" {
		t.Errorf("Type: got %q, want %q", got, "yubikey")
	}

	got, err := c.Challenge([]byte("ignored"))
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if !bytes.Equal(got, resp) {
		t.Errorf("Challenge returned %x, want %x", got, resp)
	}
}

func TestCachedHWResponse_DefensiveCopy(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5}
	c, err := NewCachedHWResponse(src, "", "")
	if err != nil {
		t.Fatalf("NewCachedHWResponse: %v", err)
	}
	// Mutate the source buffer after injection — should not affect
	// subsequent Challenge results.
	src[0] = 99

	got, _ := c.Challenge(nil)
	if got[0] != 1 {
		t.Errorf("CachedHWResponse aliased source buffer: got[0]=%d, want 1", got[0])
	}

	// Caller mutating the returned buffer should not affect future calls.
	got[0] = 88
	got2, _ := c.Challenge(nil)
	if got2[0] != 1 {
		t.Errorf("Challenge returned aliased internal buffer: got[0]=%d, want 1", got2[0])
	}
}

func TestCachedHWResponse_Empty(t *testing.T) {
	if _, err := NewCachedHWResponse(nil, "", ""); err == nil {
		t.Error("NewCachedHWResponse(nil) should error")
	}
	if _, err := NewCachedHWResponse([]byte{}, "", ""); err == nil {
		t.Error("NewCachedHWResponse([]) should error")
	}
}

func TestCachedHWResponse_SatisfiesInterface(t *testing.T) {
	c, _ := NewCachedHWResponse([]byte{1}, "", "")
	var _ HardwareKey = c
}
