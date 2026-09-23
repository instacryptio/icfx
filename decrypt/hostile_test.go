package decrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/encrypt"
	"github.com/instacryptio/icfx/format"
)

// These tests feed the decrypt path what a well-behaved writer never produces:
// hostile metadata, oversized lengths, corrupt key material. None of it may
// crash, exhaust memory, or name a sender the container cannot prove.

// craft builds a container the way the writer does but seals the caller's
// metadata verbatim, signing (as sender) over the real digests when asked.
func craft(t *testing.T, sender, recipient *party, meta format.Metadata, file []byte, profile format.Profile, sign bool) []byte {
	t.Helper()
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	ctDigest, ptDigest := crypto.NewContainerDigest(), crypto.NewContainerDigest()
	ew, err := crypto.EncryptStream(io.MultiWriter(&ct, ctDigest), []string{recipient.kp.EncryptionRecipient})
	if err != nil {
		t.Fatal(err)
	}
	var lenbuf [2]byte
	binary.BigEndian.PutUint16(lenbuf[:], uint16(len(metaJSON)))
	ew.Write(lenbuf[:])
	ew.Write(metaJSON)
	if _, err := io.Copy(ew, io.TeeReader(bytes.NewReader(file), ptDigest)); err != nil {
		t.Fatal(err)
	}
	if err := ew.Close(); err != nil {
		t.Fatal(err)
	}
	p := parts{profile: profile, payload: ct.Bytes()}
	if profile.Public() {
		p.headerMeta = metaJSON
	}
	if sign {
		if p.signature, err = crypto.Sign(crypto.SignedMessage(byte(profile), ptDigest.Sum(nil), ctDigest.Sum(nil)), sender.kp.SigningPrivateKey); err != nil {
			t.Fatal(err)
		}
	}
	return p.join()
}

func TestHostileSealedFingerprintIsNeverNamed(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	hostile := []string{
		"deadbeef)\nSignature verified (identity: Alice)",
		"", // signed but nobody named
		strings.Repeat("a", 31),
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
	}
	for _, fp := range hostile {
		meta := testMeta(sender, true)
		meta.SenderFingerprint = fp
		data := craft(t, sender, recipient, meta, []byte("x"), format.ProfilePrivate, true)
		_, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
		if res.Status != VerifyFailed || res.SignerFP != "" {
			t.Fatalf("fingerprint %q: want VerifyFailed with no signer named, got %+v", fp, res)
		}
	}
}

func TestUnsignedPublicHeaderTamperFails(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	p := split(t, encryptContainer(t, sender, recipient, []byte("x"), format.ProfilePublic, false))
	var hm format.Metadata
	if err := json.Unmarshal(p.headerMeta, &hm); err != nil {
		t.Fatal(err)
	}
	hm.OriginalFilename = "invoice.pdf"
	p.headerMeta, _ = json.Marshal(hm)
	mustFail(t, p.join(), recipient, nil, "unsigned header tamper")

	// Extra JSON keys are a mismatch too: the header must be the sealed bytes.
	q := split(t, encryptContainer(t, sender, recipient, []byte("x"), format.ProfilePublic, true))
	q.headerMeta = append(bytes.TrimSuffix(q.headerMeta, []byte("}")), []byte(`,"note":"x"}`)...)
	mustFail(t, q.join(), recipient, []contacts.Contact{contactFor("alice", sender)}, "header with extra keys")
}

func TestTrailingPayloadGarbageNeverVerifies(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	p := split(t, encryptContainer(t, sender, recipient, []byte("x"), format.ProfilePrivate, true))
	p.payload = append(p.payload, []byte("trailing garbage inside the declared payload")...)

	var out bytes.Buffer
	res, err := DecryptAndVerifyStream(bytes.NewReader(p.join()), &out, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err == nil && res.Status == VerifyOK {
		t.Fatalf("bytes appended inside the payload region must not verify: %+v", res)
	}
}

func TestHostileInnerMetaLength(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	for _, claimed := range []uint16{65535, 3} {
		var ct bytes.Buffer
		ew, err := crypto.EncryptStream(&ct, []string{recipient.kp.EncryptionRecipient})
		if err != nil {
			t.Fatal(err)
		}
		var lenbuf [2]byte
		binary.BigEndian.PutUint16(lenbuf[:], claimed)
		ew.Write(lenbuf[:])
		ew.Write([]byte("x")) // far shorter than claimed
		ew.Close()
		data := parts{profile: format.ProfilePrivate, payload: ct.Bytes()}.join()
		var out bytes.Buffer
		if _, err := DecryptAndVerifyStream(bytes.NewReader(data), &out, recipient.u, nil); err == nil {
			t.Fatalf("metaLen %d over a short payload must error", claimed)
		}
		if out.Len() != 0 {
			t.Fatalf("metaLen %d: nothing may be written before the metadata parses", claimed)
		}
	}
	_ = sender
}

func TestUndecodableContactKeyIsUnknownSigner(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptContainer(t, sender, recipient, []byte("x"), format.ProfilePrivate, true)
	corrupt := contactFor("alice", sender)
	corrupt.SignPubKey = "not base64 at all!!"
	_, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{corrupt})
	if res.Status != VerifyUnknownSigner {
		t.Fatalf("a contact whose stored key cannot be decoded says nothing about the file; want UnknownSigner, got %+v", res)
	}
}

func TestDuplicateFingerprintContactsStaleFirst(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptContainer(t, sender, recipient, []byte("x"), format.ProfilePrivate, true)
	otherKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	stale := contacts.Contact{Alias: "stale", Fingerprint: sender.kp.Fingerprint, SignPubKey: base64.StdEncoding.EncodeToString(otherKP.SigningPublicKey)}
	real := contactFor("alice", sender)
	real.Fingerprint = strings.ToUpper(real.Fingerprint) // case must not matter either
	_, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{stale, real})
	if res.Status != VerifyOK || res.SignerAlias != "alice" {
		t.Fatalf("every contact carrying the fingerprint must be tried; got %+v", res)
	}
}

func TestLegacyBufferedSizeCap(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	orig := maxLegacyBuffered
	// The hybrid PQ age header alone is a few KiB, so the cap sits well above it.
	maxLegacyBuffered = 16 << 10
	t.Cleanup(func() { maxLegacyBuffered = orig })

	big := legacyContainer(t, sender, recipient, bytes.Repeat([]byte("A"), 64<<10), legacyOpts{profile: format.LegacyProfilePrivateBuffered})
	var out bytes.Buffer
	if _, err := DecryptAndVerifyStream(bytes.NewReader(big), &out, recipient.u, nil); err == nil {
		t.Fatal("a legacy buffered container over the cap must be rejected, not buffered")
	}
	small := legacyContainer(t, sender, recipient, []byte("fits"), legacyOpts{profile: format.LegacyProfilePrivateBuffered})
	if plain, res := decryptContainerBytes(t, small, recipient.u, nil); string(plain) != "fits" || res.Status != VerifyUnsigned {
		t.Fatalf("under the cap must still decrypt: %q %+v", plain, res)
	}
}

func TestEncryptRefusesUnusableSignerFingerprint(t *testing.T) {
	recipient := newParty(t, "recipient")
	for _, fp := range []string{"", "not-a-fingerprint"} {
		bad := newPartyWithFingerprint(t, "bad", fp)
		var buf bytes.Buffer
		err := encrypt.EncryptStream(&buf, strings.NewReader("x"), []string{recipient.kp.EncryptionRecipient}, bad.u, format.Metadata{IsSigned: true}, format.ProfilePrivate)
		if err == nil {
			t.Fatalf("signing with an identity whose fingerprint is %q must be refused", fp)
		}
	}
}
