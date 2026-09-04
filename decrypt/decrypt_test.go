package decrypt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
)

// --- fixtures ---------------------------------------------------------------

var errMemKSNotFound = errors.New("mem keystore: not found")

type memKeystore struct {
	enc map[string]string
	sig map[string][]byte
}

func newMemKeystore() *memKeystore {
	return &memKeystore{enc: map[string]string{}, sig: map[string][]byte{}}
}

func (m *memKeystore) StoreEncryptionIdentity(name, id string) error { m.enc[name] = id; return nil }
func (m *memKeystore) LoadEncryptionIdentity(name string) (string, error) {
	v, ok := m.enc[name]
	if !ok {
		return "", errMemKSNotFound
	}
	return v, nil
}
func (m *memKeystore) StoreSigningKey(name string, key []byte) error {
	cp := make([]byte, len(key))
	copy(cp, key)
	m.sig[name] = cp
	return nil
}
func (m *memKeystore) LoadSigningKey(name string) ([]byte, error) {
	v, ok := m.sig[name]
	if !ok {
		return nil, errMemKSNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}
func (m *memKeystore) HasKeys(name string) bool {
	_, a := m.enc[name]
	_, b := m.sig[name]
	return a && b
}
func (m *memKeystore) Clear(name string) error { delete(m.enc, name); delete(m.sig, name); return nil }
func (m *memKeystore) ListNames() ([]string, error) {
	out := make([]string, 0, len(m.enc))
	for k := range m.enc {
		out = append(out, k)
	}
	return out, nil
}

// party is a generated identity + an unlocked handle for it.
type party struct {
	kp *crypto.KeyPair
	u  *identity.Unlocked
}

func newParty(t *testing.T, name string) *party {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	ks := newMemKeystore()
	if err := ks.StoreEncryptionIdentity(name, kp.EncryptionIdentity); err != nil {
		t.Fatal(err)
	}
	if err := ks.StoreSigningKey(name, kp.SigningPrivateKey); err != nil {
		t.Fatal(err)
	}
	info := identity.Identity{
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
		Status:      "active",
	}
	u, err := identity.Unlock(ks, info)
	if err != nil {
		t.Fatalf("unlocking identity: %v", err)
	}
	t.Cleanup(u.Close)
	return &party{kp: kp, u: u}
}

// contactFor builds a contact record naming sender's current signing key.
func contactFor(alias string, sender *party) contacts.Contact {
	return contacts.Contact{
		Alias:       alias,
		Fingerprint: sender.kp.Fingerprint,
		SignPubKey:  base64.StdEncoding.EncodeToString(sender.kp.SigningPublicKey),
	}
}

type buildOpts struct {
	profile          format.Profile
	private          bool
	signed           bool
	sender           *party
	recipient        *party
	headerFPOverride string // set a header SenderFingerprint that differs from the inner one
	innerFPOverride  string // set the inner/authoritative SenderFingerprint
}

// buildContainer produces a serialized .icfx container exactly as the buffered
// encrypt flow does: a private profile seals inner metadata into the payload; a
// public profile leaves the payload bare. Then age-encrypt to the recipient,
// sign the ciphertext, and serialize.
func buildContainer(t *testing.T, filedata []byte, o buildOpts) []byte {
	t.Helper()
	if o.profile == 0 {
		o.profile = format.ProfilePrivateBuffered
	}
	innerFP := o.sender.kp.Fingerprint
	if o.innerFPOverride != "" {
		innerFP = o.innerFPOverride
	}
	meta := format.Metadata{SenderFingerprint: innerFP, OriginalFilename: "test.txt", IsSigned: o.signed}

	payloadPlain := filedata
	if !o.profile.Public() {
		enc, err := format.EncodePayload(meta, filedata)
		if err != nil {
			t.Fatalf("encode payload: %v", err)
		}
		payloadPlain = enc
	}
	ciphertext, err := crypto.Encrypt(payloadPlain, []string{o.recipient.kp.EncryptionRecipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var sig []byte
	if o.signed {
		sig, err = crypto.Sign(ciphertext, o.sender.kp.SigningPrivateKey)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
	}
	c := &format.Container{Profile: o.profile, Payload: ciphertext, Signature: sig, Private: o.private}
	if !o.private {
		hdr := meta
		if o.headerFPOverride != "" {
			hdr.SenderFingerprint = o.headerFPOverride
		}
		c.Metadata = hdr
	}
	data, err := c.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return data
}

// --- tests ------------------------------------------------------------------

func TestUnsignedContainer(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("hello world")
	data := buildContainer(t, file, buildOpts{signed: false, sender: sender, recipient: recipient})

	res, err := DecryptAndVerify(data, recipient.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, file) {
		t.Fatalf("plaintext mismatch: %q", res.Plaintext)
	}
	if res.Verify.Status != VerifyUnsigned {
		t.Fatalf("want VerifyUnsigned, got %v", res.Verify.Status)
	}
}

func TestPrivateV2SignedContactMatch(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("private v2 payload")
	data := buildContainer(t, file, buildOpts{private: true, signed: true, sender: sender, recipient: recipient})

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, file) {
		t.Fatalf("plaintext mismatch")
	}
	if res.Verify.Status != VerifyOK || res.Verify.SignerAlias != "alice" || res.Verify.UsedRevokedKey {
		t.Fatalf("want OK via contact alice, got %+v", res.Verify)
	}
}

func TestPublicV2SignedContactMatch(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("public-meta v2")
	data := buildContainer(t, file, buildOpts{private: false, signed: true, sender: sender, recipient: recipient})

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("bob", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyOK || res.Verify.SignerAlias != "bob" {
		t.Fatalf("want OK via contact bob, got %+v", res.Verify)
	}
}

func TestSelfSigned(t *testing.T) {
	// Sender is also the recipient (encrypt-to-self); no contacts.
	self := newParty(t, "me")
	file := []byte("dear diary")
	data := buildContainer(t, file, buildOpts{private: true, signed: true, sender: self, recipient: self})

	res, err := DecryptAndVerify(data, self.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyOK || res.Verify.SignerIdentity != "me" {
		t.Fatalf("want OK via self identity, got %+v", res.Verify)
	}
}

func TestUnverifiableUnknownSender(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := buildContainer(t, []byte("x"), buildOpts{private: true, signed: true, sender: sender, recipient: recipient})

	// No contacts, recipient != sender → cannot resolve a signer key.
	res, err := DecryptAndVerify(data, recipient.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyUnverifiable || res.Verify.SignerFP != sender.kp.Fingerprint {
		t.Fatalf("want Unverifiable with signer fp, got %+v", res.Verify)
	}
}

func TestRevokedPreviousKey(t *testing.T) {
	oldSender, recipient := newParty(t, "old-sender"), newParty(t, "recipient")
	newKP, err := crypto.GenerateKeyPair() // the contact's CURRENT (rotated) key
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	// File was signed with the OLD key; the contact has since rotated.
	data := buildContainer(t, []byte("signed before rotation"), buildOpts{private: true, signed: true, sender: oldSender, recipient: recipient})
	contact := contacts.Contact{
		Alias:       "carol",
		Fingerprint: newKP.Fingerprint, // current key
		SignPubKey:  base64.StdEncoding.EncodeToString(newKP.SigningPublicKey),
		PreviousKeys: []contacts.PreviousKey{{
			Fingerprint: oldSender.kp.Fingerprint,
			SignPubKey:  base64.StdEncoding.EncodeToString(oldSender.kp.SigningPublicKey),
			RevokedAt:   revokedAt,
		}},
	}

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contact})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyOK || !res.Verify.UsedRevokedKey || res.Verify.SignerAlias != "carol" {
		t.Fatalf("want OK via revoked key, got %+v", res.Verify)
	}
	if !res.Verify.RevokedAt.Equal(revokedAt) {
		t.Fatalf("want RevokedAt %v, got %v", revokedAt, res.Verify.RevokedAt)
	}
}

func TestTamperedSignature(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := buildContainer(t, []byte("payload"), buildOpts{private: true, signed: true, sender: sender, recipient: recipient})

	// Flip a byte inside the trailing signature block.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)-1] ^= 0xFF

	res, err := DecryptAndVerify(tampered, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyUnverifiable {
		t.Fatalf("want Unverifiable for tampered sig, got %+v", res.Verify)
	}
}

func TestInnerMetaIsAuthoritative(t *testing.T) {
	// A v2 public-meta container whose plaintext HEADER names a bogus signer,
	// while the authenticated INNER metadata names the true sender. Verification
	// must key off the inner metadata and succeed.
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := buildContainer(t, []byte("trust the inside"), buildOpts{
		private: false, signed: true, sender: sender, recipient: recipient,
		headerFPOverride: "00000000000000000000000000000000",
	})

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyOK || res.Verify.SignerAlias != "alice" {
		t.Fatalf("inner meta must win: got %+v", res.Verify)
	}
}

func TestForgedInnerMetaFailsVerify(t *testing.T) {
	// Inner metadata claims a DIFFERENT sender than the one who actually signed;
	// the signature over the payload won't verify against that claimed key.
	realSigner, recipient := newParty(t, "real"), newParty(t, "recipient")
	impostor := newParty(t, "impostor")
	data := buildContainer(t, []byte("who signed this?"), buildOpts{
		private: true, signed: true, sender: realSigner, recipient: recipient,
		innerFPOverride: impostor.kp.Fingerprint,
	})

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("impostor", impostor)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.Status != VerifyUnverifiable {
		t.Fatalf("forged inner-meta signer must not verify, got %+v", res.Verify)
	}
}

func TestHeaderedV1Signed(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("legacy v1")
	data := buildContainer(t, file, buildOpts{profile: format.ProfilePublicBuffered, private: false, signed: true, sender: sender, recipient: recipient})

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, file) {
		t.Fatalf("v1 plaintext mismatch")
	}
	if res.Verify.Status != VerifyOK || res.Verify.SignerAlias != "alice" {
		t.Fatalf("want OK via header FP, got %+v", res.Verify)
	}
}

func TestStrippedV1Private(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("stripped legacy")
	data := buildContainer(t, file, buildOpts{profile: format.ProfilePublicBuffered, private: true, signed: true, sender: sender, recipient: recipient})

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, file) {
		t.Fatalf("stripped-v1 plaintext mismatch")
	}
	if res.Verify.Status != VerifyNoMetadata {
		t.Fatalf("want NoMetadata for stripped v1, got %+v", res.Verify)
	}
}

func TestBadContainerErrors(t *testing.T) {
	recipient := newParty(t, "recipient")
	if _, err := DecryptAndVerify([]byte("not an icfx container"), recipient.u, nil); err == nil {
		t.Fatal("want error for garbage input")
	}
}

func TestWrongRecipientCannotDecrypt(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	stranger := newParty(t, "stranger")
	data := buildContainer(t, []byte("secret"), buildOpts{private: true, signed: true, sender: sender, recipient: recipient})

	if _, err := DecryptAndVerify(data, stranger.u, nil); err == nil {
		t.Fatal("want decrypt error for wrong recipient")
	}
}
