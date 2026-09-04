package crypto

import (
	"bytes"
	"testing"
	"time"

	"github.com/instacryptio/icfx/format"
)

// TestSignedPrivateContainerRoundTrip pins the full v2 signed chain the
// clients implement: encode inner metadata → encrypt → sign the payload →
// serialize private → (share-path strip is a no-op on private) →
// deserialize → decrypt → decode inner metadata → verify the signature
// with the fingerprint revealed by decryption.
func TestSignedPrivateContainerRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	filedata := []byte("signed and private file contents")
	meta := format.Metadata{
		SenderFingerprint: kp.Fingerprint,
		Timestamp:         time.Now().UTC(),
		OriginalFilename:  "quarterly.xlsx",
		IsSigned:          true,
	}
	inner, err := format.EncodePayload(meta, filedata)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	payload, err := Encrypt(inner, []string{kp.EncryptionRecipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	sig, err := Sign(payload, kp.SigningPrivateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	container := &format.Container{
		Profile:   format.ProfilePrivateBuffered,
		Payload:   payload,
		Signature: sig,
		Private:   true,
	}
	data, err := container.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if bytes.Contains(data, []byte("quarterly")) || bytes.Contains(data, []byte(kp.Fingerprint)) {
		t.Fatal("private container leaked metadata")
	}

	// Recipient path: parse, decrypt, peel inner metadata, verify.
	parsed, err := format.Deserialize(data)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !parsed.Private {
		t.Fatal("expected private container")
	}
	plain, err := Decrypt(parsed.Payload, kp.EncryptionIdentity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	gotMeta, gotFile, err := format.DecodePayload(plain)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if gotMeta.SenderFingerprint != kp.Fingerprint || !gotMeta.IsSigned || gotMeta.OriginalFilename != "quarterly.xlsx" {
		t.Fatalf("inner metadata: %+v", gotMeta)
	}
	if !bytes.Equal(gotFile, filedata) {
		t.Fatal("file bytes mismatch")
	}
	ok, err := Verify(parsed.Payload, parsed.Signature, kp.SigningPublicKey)
	if err != nil || !ok {
		t.Fatalf("signature must verify after decrypt: ok=%v err=%v", ok, err)
	}

	// Tampered payload fails verification.
	bad := append([]byte{}, parsed.Payload...)
	bad[len(bad)/2] ^= 0xFF
	if ok, _ := Verify(bad, parsed.Signature, kp.SigningPublicKey); ok {
		t.Fatal("tampered payload must not verify")
	}
}
