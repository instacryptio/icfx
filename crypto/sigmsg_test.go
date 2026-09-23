package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func digestOf(b byte) []byte { return bytes.Repeat([]byte{b}, NewContainerDigest().Size()) }

// TestSignedMessageFraming pins the exact bytes a container signature covers:
// a length-framed tag first, then the profile, then the two digests.
func TestSignedMessageFraming(t *testing.T) {
	msg := SignedMessage(0x05, digestOf(0xAA), digestOf(0xBB))

	tagLen := binary.BigEndian.Uint64(msg[:8])
	if int(tagLen) != len(containerCanonicalTag) || string(msg[8:8+tagLen]) != containerCanonicalTag {
		t.Fatalf("message must begin with the length-framed tag, got %q", msg[:8+tagLen])
	}
	want := 8 + len(containerCanonicalTag) + 8 + 1 + 8 + 64 + 8 + 64
	if len(msg) != want {
		t.Fatalf("message length = %d, want %d", len(msg), want)
	}
	if !bytes.Equal(msg, SignedMessage(0x05, digestOf(0xAA), digestOf(0xBB))) {
		t.Fatal("SignedMessage must be deterministic")
	}
}

// TestSignedMessageBindsEveryField: changing the profile or either digest
// changes the message — none of them can be swapped without the signature
// noticing.
func TestSignedMessageBindsEveryField(t *testing.T) {
	base := SignedMessage(0x05, digestOf(0xAA), digestOf(0xBB))
	variants := map[string][]byte{
		"profile":    SignedMessage(0x06, digestOf(0xAA), digestOf(0xBB)),
		"plaintext":  SignedMessage(0x05, digestOf(0xAC), digestOf(0xBB)),
		"ciphertext": SignedMessage(0x05, digestOf(0xAA), digestOf(0xBD)),
	}
	for name, v := range variants {
		if bytes.Equal(base, v) {
			t.Fatalf("changing the %s must change the signed message", name)
		}
	}
}

// TestSignedMessageRoundTrip: a real ML-DSA-65 signature over the message
// verifies, and fails once any bound field changes.
func TestSignedMessageRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := SignedMessage(0x05, digestOf(0x01), digestOf(0x02))
	sig, err := Sign(msg, kp.SigningPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(msg, sig, kp.SigningPublicKey); err != nil || !ok {
		t.Fatalf("signature must verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify(SignedMessage(0x06, digestOf(0x01), digestOf(0x02)), sig, kp.SigningPublicKey); ok {
		t.Fatal("signature must not verify under another profile byte")
	}
}
