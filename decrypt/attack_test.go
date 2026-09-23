package decrypt

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
)

// These tests are the threat model of the container signature: every way an
// attacker might re-attribute, strip, forge or re-label a container must end
// in VerifyFailed — never in VerifyOK naming anyone but the real signer.

// mustFail decrypts as the recipient with the given contacts and asserts the
// verdict is VerifyFailed (plaintext may or may not be intact — the point is
// the attribution).
func mustFail(t *testing.T, data []byte, recipient *party, cl []contacts.Contact, what string) VerifyResult {
	t.Helper()
	var out bytes.Buffer
	res, err := DecryptAndVerifyStream(bytes.NewReader(data), &out, recipient.u, cl)
	if err != nil {
		t.Fatalf("%s: decrypt must still succeed, got %v", what, err)
	}
	if res.Status != VerifyFailed {
		t.Fatalf("%s: want VerifyFailed, got %+v", what, res)
	}
	return res
}

// TestFingerprintSwapFails is the reported attack: an attacker takes someone
// else's public container, rewrites the advisory header to name themselves and
// re-signs under their own key. Verification must key off the sealed
// metadata and fail — never report the attacker as the author.
func TestFingerprintSwapFails(t *testing.T) {
	author, recipient, attacker := newParty(t, "author"), newParty(t, "recipient"), newParty(t, "attacker")
	file := []byte("the author wrote this")
	p := split(t, encryptContainer(t, author, recipient, file, format.ProfilePublic, true))

	// Header now claims the attacker; the attacker signs the best message they
	// can build (they cannot decrypt, so the plaintext digest is a guess).
	var hm format.Metadata
	if err := json.Unmarshal(p.headerMeta, &hm); err != nil {
		t.Fatal(err)
	}
	hm.SenderFingerprint = attacker.kp.Fingerprint
	p.headerMeta, _ = json.Marshal(hm)
	sig, err := attacker.u.Sign(crypto.SignedMessage(byte(p.profile), digest(nil), digest(p.payload)))
	if err != nil {
		t.Fatal(err)
	}
	p.signature = sig

	cl := []contacts.Contact{contactFor("author", author), contactFor("attacker", attacker)}
	res := mustFail(t, p.join(), recipient, cl, "fingerprint swap")
	if res.SignerAlias == "attacker" || res.SignerFP == attacker.kp.Fingerprint {
		t.Fatalf("attacker must never be named as signer: %+v", res)
	}
}

// TestRecipientCannotReattribute: a legitimate recipient knows the plaintext,
// so they can build the exact signed message — but the sealed metadata still
// names the author, so their signature resolves against the author's key and
// fails. Claiming authorship requires re-encrypting, i.e. a new container of
// their own.
func TestRecipientCannotReattribute(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	file := []byte("shared secret")
	p := split(t, encryptContainer(t, author, recipient, file, format.ProfilePrivate, true))

	sig, err := recipient.u.Sign(crypto.SignedMessage(byte(p.profile), digest(file), digest(p.payload)))
	if err != nil {
		t.Fatal(err)
	}
	p.signature = sig

	res := mustFail(t, p.join(), recipient, []contacts.Contact{contactFor("author", author)}, "recipient re-sign")
	if res.SignerFP != author.kp.Fingerprint {
		t.Fatalf("the sealed author must still be the named signer: %+v", res)
	}
}

// TestSignatureStripFails: removing the signature from a file whose sealed
// metadata says it is signed is tampering, not an unsigned file.
func TestSignatureStripFails(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	p := split(t, encryptContainer(t, author, recipient, []byte("signed"), format.ProfilePrivate, true))
	p.signature = nil

	res := mustFail(t, p.join(), recipient, []contacts.Contact{contactFor("author", author)}, "signature strip")
	if res.SignerFP != author.kp.Fingerprint {
		t.Fatalf("stripped container must still name its signer: %+v", res)
	}
}

// TestBoltOnSignatureFails: nobody may add a signature to a file its author
// left unsigned.
func TestBoltOnSignatureFails(t *testing.T) {
	author, recipient, attacker := newParty(t, "author"), newParty(t, "recipient"), newParty(t, "attacker")
	file := []byte("unsigned by design")
	p := split(t, encryptContainer(t, author, recipient, file, format.ProfilePrivate, false))

	sig, err := attacker.u.Sign(crypto.SignedMessage(byte(p.profile), digest(file), digest(p.payload)))
	if err != nil {
		t.Fatal(err)
	}
	p.signature = sig

	mustFail(t, p.join(), recipient, []contacts.Contact{contactFor("attacker", attacker)}, "bolt-on signature")
}

// TestHeaderMismatchFails: an advisory header that disagrees with the sealed
// metadata in any field is a failure, even with the signature intact.
func TestHeaderMismatchFails(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	p := split(t, encryptContainer(t, author, recipient, []byte("x"), format.ProfilePublic, true))

	var hm format.Metadata
	if err := json.Unmarshal(p.headerMeta, &hm); err != nil {
		t.Fatal(err)
	}
	hm.OriginalFilename = "invoice.pdf"
	p.headerMeta, _ = json.Marshal(hm)

	mustFail(t, p.join(), recipient, []contacts.Contact{contactFor("author", author)}, "header mismatch")
}

// TestStrippedHeaderStillVerifies is the sharing path: the upload strips the
// advisory header (format.ZeroMetaLen) and the container must still verify
// with full authorship from the sealed copy.
func TestStrippedHeaderStillVerifies(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	file := []byte("shared through the cloud")
	p := split(t, encryptContainer(t, author, recipient, file, format.ProfilePublic, true))
	p.headerMeta = nil

	plain, res := decryptContainerBytes(t, p.join(), recipient.u, []contacts.Contact{contactFor("author", author)})
	if !bytes.Equal(plain, file) || res.Status != VerifyOK || res.SignerAlias != "author" {
		t.Fatalf("stripped public container must verify from sealed metadata: %+v", res)
	}
}

// TestProfileFlipFails: the profile byte is inside the signed message, so
// re-labelling a container as another layout fails verification.
func TestProfileFlipFails(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	cl := []contacts.Contact{contactFor("author", author)}

	// 0x05 → 0x06 (a header-less public container is a valid layout).
	p := split(t, encryptContainer(t, author, recipient, []byte("x"), format.ProfilePrivate, true))
	p.profile = format.ProfilePublic
	mustFail(t, p.join(), recipient, cl, "private→public flip")

	// 0x05 → legacy 0x03: decrypts through the legacy path, never verifies.
	p.profile = format.LegacyProfilePrivateStreaming
	mustFail(t, p.join(), recipient, cl, "downgrade to legacy")

	// 0x06 → 0x05 while keeping the header is not a valid layout at all.
	q := split(t, encryptContainer(t, author, recipient, []byte("x"), format.ProfilePublic, true))
	q.profile = format.ProfilePrivate
	if _, err := DecryptAndVerifyStream(bytes.NewReader(q.join()), &bytes.Buffer{}, recipient.u, cl); err == nil {
		t.Fatal("a private profile with a header must be rejected")
	}
}

// TestSpliceSignatureFails: a valid signature from one container cannot be
// moved onto another with different content.
func TestSpliceSignatureFails(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	a := split(t, encryptContainer(t, author, recipient, []byte("first"), format.ProfilePrivate, true))
	b := split(t, encryptContainer(t, author, recipient, []byte("second"), format.ProfilePrivate, true))
	b.signature = a.signature

	mustFail(t, b.join(), recipient, []contacts.Contact{contactFor("author", author)}, "spliced signature")
}

func TestTamperedSignatureFails(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	data := encryptContainer(t, author, recipient, []byte("payload"), format.ProfilePrivate, true)
	tampered := append([]byte{}, data...)
	tampered[len(tampered)-1] ^= 0xFF // last byte is inside the signature

	mustFail(t, tampered, recipient, []contacts.Contact{contactFor("author", author)}, "tampered signature")
}

func TestTamperedCiphertextNeverVerifies(t *testing.T) {
	author, recipient := newParty(t, "author"), newParty(t, "recipient")
	data := encryptContainer(t, author, recipient, []byte("tamper me"), format.ProfilePrivate, true)
	tampered := append([]byte{}, data...)
	tampered[len(tampered)/2] ^= 0xFF // somewhere in the payload

	var out bytes.Buffer
	res, err := DecryptAndVerifyStream(bytes.NewReader(tampered), &out, recipient.u, []contacts.Contact{contactFor("author", author)})
	// age rejects the tampered ciphertext (decrypt error) OR the signature
	// fails — either way it must NOT report VerifyOK.
	if err == nil && res.Status == VerifyOK {
		t.Fatalf("tampered ciphertext must not verify OK, got %+v", res)
	}
}
