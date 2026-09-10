//go:build hardware && !nohw && !android && !ios

// Hardware acceptance tests for the HID chalresp backend. These require a real
// device (YubiKey, or OnlyKey) with slot 2 programmed for HMAC-SHA1 and are
// excluded from normal builds. Run with:
//
//	go test -tags hardware ./hardware/chalresp/ -v
//
// The decisive real-world check is separate: unlock a pre-existing HW-protected
// identity with a build using this package (`icc id show <name>`) — that proves
// byte-compatibility with whatever sealed it.
package chalresp

import (
	"bytes"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

func hwKey(t *testing.T) *Key {
	t.Helper()
	devs, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(devs) == 0 {
		t.Skip("no compatible hardware key attached")
	}
	t.Logf("device: family=%s serial=%q", devs[0].Family, devs[0].Serial)
	prog, err := IsSlot2Programmed(devs[0])
	if err != nil {
		t.Fatalf("IsSlot2Programmed: %v", err)
	}
	if !prog {
		t.Skip("slot 2 is not programmed for HMAC-SHA1 challenge-response")
	}
	k, err := Open(devs[0])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return k
}

// TestHardwareChallengeSmoke exercises the protocol across challenge lengths,
// including a 32-byte challenge ending in 0x00 (the padding edge case). The
// responses are logged for debugging — these are throwaway TEST challenges, not
// a real identity's; never log a production identity's challenge or response.
func TestHardwareChallengeSmoke(t *testing.T) {
	k := hwKey(t)
	cases := []struct {
		name string
		ch   []byte
	}{
		{"len1", []byte{0x42}},
		{"len20", bytes.Repeat([]byte{0x11}, 20)},
		{"len32", bytes.Repeat([]byte{0x22}, 32)},
		{"len63", bytes.Repeat([]byte{0x33}, 63)},
		{"len64", bytes.Repeat([]byte{0x44}, 64)},
		{"len32-zero-ending", append(bytes.Repeat([]byte{0x55}, 31), 0x00)},
	}
	for _, c := range cases {
		resp, err := k.Challenge(c.ch)
		if err != nil {
			t.Fatalf("[%s] Challenge: %v", c.name, err)
		}
		if len(resp) != hmacLen {
			t.Fatalf("[%s] response length = %d, want %d", c.name, len(resp), hmacLen)
		}
		t.Logf("[%s] challenge=%x -> %x", c.name, c.ch, resp)
	}
}

// TestHardwareDeterministic confirms the same challenge yields the same response
// (each call needs a touch on touch-configured slots).
func TestHardwareDeterministic(t *testing.T) {
	k := hwKey(t)
	ch := bytes.Repeat([]byte{0xA5}, 32)
	r1, err := k.Challenge(ch)
	if err != nil {
		t.Fatalf("Challenge #1: %v", err)
	}
	r2, err := k.Challenge(ch)
	if err != nil {
		t.Fatalf("Challenge #2: %v", err)
	}
	if !bytes.Equal(r1, r2) {
		t.Fatalf("non-deterministic response: %x != %x", r1, r2)
	}
}

// TestHardwareVsYkman cross-checks against yubikit/ykman (the "standard" impl).
// Uses an ASCII challenge (no trailing 0x00) so `ykman otp calculate` hashes the
// same bytes regardless of hex/string interpretation. Skips if ykman is absent
// or its output can't be parsed — some ykman versions differ, so treat a skip as
// "verify the invocation", and only a genuine byte mismatch as an impl bug.
func TestHardwareVsYkman(t *testing.T) {
	if _, err := exec.LookPath("ykman"); err != nil {
		t.Skip("ykman not in PATH")
	}
	k := hwKey(t)
	challenge := []byte("instacrypt-chalresp-oracle")
	resp, err := k.Challenge(challenge)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	out, err := exec.Command("ykman", "otp", "calculate", "2", string(challenge)).Output()
	if err != nil {
		t.Skipf("ykman invocation failed (adjust for your version): %v", err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		t.Skipf("could not parse ykman output %q as hex: %v", strings.TrimSpace(string(out)), err)
	}
	if !bytes.Equal(resp, want) {
		t.Fatalf("mismatch vs ykman: got %x, ykman %x", resp, want)
	}
	t.Logf("matches ykman: %x", resp)
}
