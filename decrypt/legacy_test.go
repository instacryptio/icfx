package decrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
)

// Legacy containers still decrypt so existing files stay readable, but their
// signatures — which bound only the ciphertext — are no longer honoured. These
// tests build each legacy layout by hand with a signature that WAS valid under
// its retired scheme, and check that the plaintext comes back while the
// verdict is VerifyFailed.

// retiredStreamingTag is the domain prefix the retired streaming layouts
// signed under. It exists here only to prove such signatures are ignored.
const retiredStreamingTag = "ICFXv3\x00"

type legacyOpts struct {
	profile  format.Profile
	headered bool // write the plaintext header (public layouts only)
	signed   bool
}

// legacyContainer builds a legacy container exactly as the retired writers
// did: sealed inner framing for the private layouts, bare file bytes for the
// public ones, a raw-ciphertext signature for buffered layouts and a tagged
// ciphertext-digest signature for streaming ones.
func legacyContainer(t *testing.T, sender, recipient *party, file []byte, o legacyOpts) []byte {
	t.Helper()
	meta := testMeta(sender, o.signed)
	payloadPlain := file
	if o.profile.SealsMetadata() {
		var err error
		if payloadPlain, err = format.EncodePayload(meta, file); err != nil {
			t.Fatal(err)
		}
	}
	ciphertext, err := crypto.Encrypt(payloadPlain, []string{recipient.kp.EncryptionRecipient})
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	if o.signed {
		msg := ciphertext
		if o.profile.Streaming() {
			msg = append([]byte(retiredStreamingTag), digest(ciphertext)...)
		}
		if sig, err = crypto.Sign(msg, sender.kp.SigningPrivateKey); err != nil {
			t.Fatal(err)
		}
	}
	var headerMeta []byte
	if o.headered {
		if headerMeta, err = json.Marshal(meta); err != nil {
			t.Fatal(err)
		}
	}
	buf := append([]byte{}, format.MagicBytes...)
	buf = append(buf, byte(o.profile))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(headerMeta)))
	buf = append(buf, headerMeta...)
	switch {
	case o.profile.Streaming():
		buf = binary.BigEndian.AppendUint64(buf, uint64(len(ciphertext)))
	default:
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(ciphertext)))
	}
	buf = append(buf, ciphertext...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sig)))
	return append(buf, sig...)
}

func TestLegacyDecryptsButNeverVerifies(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("written by an older build")
	cl := []contacts.Contact{contactFor("alice", sender)} // a key that WOULD have verified

	cases := []struct {
		name string
		o    legacyOpts
	}{
		{"public-buffered", legacyOpts{profile: format.LegacyProfilePublicBuffered, headered: true, signed: true}},
		{"private-buffered", legacyOpts{profile: format.LegacyProfilePrivateBuffered, signed: true}},
		{"private-streaming", legacyOpts{profile: format.LegacyProfilePrivateStreaming, signed: true}},
		{"public-streaming", legacyOpts{profile: format.LegacyProfilePublicStreaming, headered: true, signed: true}},
		{"public-streaming-stripped", legacyOpts{profile: format.LegacyProfilePublicStreaming, signed: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plain, res := decryptContainerBytes(t, legacyContainer(t, sender, recipient, file, c.o), recipient.u, cl)
			if !bytes.Equal(plain, file) {
				t.Fatalf("plaintext mismatch: %q", plain)
			}
			if res.Status != VerifyFailed {
				t.Fatalf("legacy signature must not be honoured, got %+v", res)
			}
			if c.o.headered || c.o.profile.SealsMetadata() {
				if res.SignerFP != sender.kp.Fingerprint {
					t.Fatalf("claimed signer must be reported: %+v", res)
				}
			}
		})
	}
}

func TestLegacyUnsignedStaysUnsigned(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("never signed")
	for _, p := range []format.Profile{format.LegacyProfilePublicBuffered, format.LegacyProfilePrivateBuffered, format.LegacyProfilePrivateStreaming, format.LegacyProfilePublicStreaming} {
		plain, res := decryptContainerBytes(t, legacyContainer(t, sender, recipient, file, legacyOpts{profile: p, headered: p.Public()}), recipient.u, nil)
		if !bytes.Equal(plain, file) {
			t.Fatalf("profile %#x: plaintext mismatch", byte(p))
		}
		if res.Status != VerifyUnsigned {
			t.Fatalf("profile %#x: want VerifyUnsigned, got %+v", byte(p), res)
		}
	}
}

func TestLegacyWrongRecipientCannotDecrypt(t *testing.T) {
	sender, recipient, stranger := newParty(t, "sender"), newParty(t, "recipient"), newParty(t, "stranger")
	data := legacyContainer(t, sender, recipient, []byte("secret"), legacyOpts{profile: format.LegacyProfilePrivateStreaming, signed: true})
	if _, err := DecryptAndVerifyStream(bytes.NewReader(data), &bytes.Buffer{}, stranger.u, nil); err == nil {
		t.Fatal("want decrypt error for wrong recipient")
	}
}
