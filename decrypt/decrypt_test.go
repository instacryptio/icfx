package decrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/encrypt"
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

func testMeta(sender *party, signed bool) format.Metadata {
	return format.Metadata{
		SenderFingerprint: sender.kp.Fingerprint,
		Timestamp:         time.Now().UTC().Truncate(time.Second),
		OriginalFilename:  "test.bin",
		IsSigned:          signed,
	}
}

// encryptContainer produces a container through the real writer.
func encryptContainer(t *testing.T, sender, recipient *party, filedata []byte, profile format.Profile, signed bool) []byte {
	t.Helper()
	var signer *identity.Unlocked
	if signed {
		signer = sender.u
	}
	var buf bytes.Buffer
	if err := encrypt.EncryptStream(&buf, bytes.NewReader(filedata), []string{recipient.kp.EncryptionRecipient}, signer, testMeta(sender, signed), profile); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	out := buf.Bytes()
	if out[4] != byte(profile) {
		t.Fatalf("expected profile byte %#x, got %#x", byte(profile), out[4])
	}
	return out
}

func decryptContainerBytes(t *testing.T, container []byte, u *identity.Unlocked, cl []contacts.Contact) ([]byte, VerifyResult) {
	t.Helper()
	var out bytes.Buffer
	res, err := DecryptAndVerifyStream(bytes.NewReader(container), &out, u, cl)
	if err != nil {
		t.Fatalf("DecryptAndVerifyStream: %v", err)
	}
	return out.Bytes(), res
}

// parts is a streaming container taken apart so tests can tamper with one
// field and put it back together.
type parts struct {
	profile    format.Profile
	headerMeta []byte
	payload    []byte
	signature  []byte
}

func split(t *testing.T, data []byte) parts {
	t.Helper()
	profile, metaLen, err := format.ParseHeaderPrefix(data[:format.HeaderPrefixLen])
	if err != nil {
		t.Fatal(err)
	}
	off := format.HeaderPrefixLen
	p := parts{profile: profile, headerMeta: append([]byte{}, data[off:off+metaLen]...)}
	off += metaLen
	plen := int(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8
	p.payload = append([]byte{}, data[off:off+plen]...)
	off += plen
	slen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	p.signature = append([]byte{}, data[off:off+slen]...)
	return p
}

func (p parts) join() []byte {
	buf := append([]byte{}, format.MagicBytes...)
	buf = append(buf, byte(p.profile))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.headerMeta)))
	buf = append(buf, p.headerMeta...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(p.payload)))
	buf = append(buf, p.payload...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.signature)))
	return append(buf, p.signature...)
}

func digest(b []byte) []byte {
	h := crypto.NewContainerDigest()
	h.Write(b)
	return h.Sum(nil)
}

// --- round trips --------------------------------------------------------------

func TestPrivateSignedContactMatch(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("private payload")
	data := encryptContainer(t, sender, recipient, file, format.ProfilePrivate, true)
	if bytes.Contains(data, []byte("test.bin")) || bytes.Contains(data, []byte(sender.kp.Fingerprint)) {
		t.Fatal("private container leaked metadata")
	}

	plain, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatalf("plaintext mismatch: %q", plain)
	}
	if res.Status != VerifyOK || res.SignerAlias != "alice" || res.UsedRevokedKey || res.SignerFP != sender.kp.Fingerprint {
		t.Fatalf("want OK via contact alice, got %+v", res)
	}
}

func TestPublicSignedContactMatch(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("public-header payload")
	data := encryptContainer(t, sender, recipient, file, format.ProfilePublic, true)
	if !bytes.Contains(data, []byte("test.bin")) {
		t.Fatal("public container should carry the advisory header")
	}

	plain, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{contactFor("bob", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatal("plaintext mismatch")
	}
	if res.Status != VerifyOK || res.SignerAlias != "bob" {
		t.Fatalf("want OK via contact bob, got %+v", res)
	}
}

func TestSelfSigned(t *testing.T) {
	self := newParty(t, "me")
	file := []byte("dear diary")
	data := encryptContainer(t, self, self, file, format.ProfilePrivate, true)

	plain, res := decryptContainerBytes(t, data, self.u, nil)
	if !bytes.Equal(plain, file) {
		t.Fatal("plaintext mismatch")
	}
	if res.Status != VerifyOK || res.SignerIdentity != "me" {
		t.Fatalf("want OK via self, got %+v", res)
	}
}

func TestUnsigned(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("no signature here")
	for _, p := range []format.Profile{format.ProfilePrivate, format.ProfilePublic} {
		data := encryptContainer(t, sender, recipient, file, p, false)
		plain, res := decryptContainerBytes(t, data, recipient.u, nil)
		if !bytes.Equal(plain, file) {
			t.Fatal("plaintext mismatch")
		}
		if res.Status != VerifyUnsigned {
			t.Fatalf("profile %#x: want VerifyUnsigned, got %+v", byte(p), res)
		}
	}
}

func TestUnknownSigner(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptContainer(t, sender, recipient, []byte("x"), format.ProfilePrivate, true)

	_, res := decryptContainerBytes(t, data, recipient.u, nil) // no contacts, recipient != sender
	if res.Status != VerifyUnknownSigner || res.SignerFP != sender.kp.Fingerprint {
		t.Fatalf("want UnknownSigner with signer fp, got %+v", res)
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
	data := encryptContainer(t, oldSender, recipient, []byte("signed before rotation"), format.ProfilePrivate, true)
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

	_, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{contact})
	if res.Status != VerifyOK || !res.UsedRevokedKey || res.SignerAlias != "carol" {
		t.Fatalf("want OK via revoked key, got %+v", res)
	}
	if !res.RevokedAt.Equal(revokedAt) {
		t.Fatalf("want RevokedAt %v, got %v", revokedAt, res.RevokedAt)
	}
}

func TestInMemoryFormMatchesStream(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("same answer either way")
	data := encryptContainer(t, sender, recipient, file, format.ProfilePrivate, true)

	res, err := DecryptAndVerify(data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, file) || res.Verify.Status != VerifyOK || res.Verify.SignerAlias != "alice" {
		t.Fatalf("in-memory form: %+v", res.Verify)
	}
}

func TestPublicHeaderReadableWithoutDecrypt(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptContainer(t, sender, recipient, []byte("scriptable"), format.ProfilePublic, true)

	sh, err := format.ParseStreamHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseStreamHeader: %v", err)
	}
	if sh.Profile != format.ProfilePublic || sh.Private {
		t.Fatalf("want public profile with header, got %#x private=%v", byte(sh.Profile), sh.Private)
	}
	if sh.HeaderMeta.OriginalFilename != "test.bin" || sh.HeaderMeta.SenderFingerprint != sender.kp.Fingerprint {
		t.Fatalf("header metadata not readable without decrypting: %+v", sh.HeaderMeta)
	}
}

// --- writer contract ---------------------------------------------------------

func TestEncryptRejectsLegacyProfiles(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	for _, p := range []format.Profile{format.LegacyProfilePublicBuffered, format.LegacyProfilePrivateBuffered, format.LegacyProfilePrivateStreaming, format.LegacyProfilePublicStreaming, format.Profile(0x07)} {
		var buf bytes.Buffer
		err := encrypt.EncryptStream(&buf, strings.NewReader("x"), []string{recipient.kp.EncryptionRecipient}, sender.u, testMeta(sender, true), p)
		if err == nil {
			t.Fatalf("profile %#x must not be writable", byte(p))
		}
	}
}

func TestSenderFingerprintFollowsSigner(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	impostor := newParty(t, "impostor")

	// An empty fingerprint is filled from the signer.
	meta := testMeta(sender, true)
	meta.SenderFingerprint = ""
	var buf bytes.Buffer
	if err := encrypt.EncryptStream(&buf, strings.NewReader("x"), []string{recipient.kp.EncryptionRecipient}, sender.u, meta, format.ProfilePrivate); err != nil {
		t.Fatal(err)
	}
	if _, res := decryptContainerBytes(t, buf.Bytes(), recipient.u, []contacts.Contact{contactFor("alice", sender)}); res.Status != VerifyOK || res.SignerFP != sender.kp.Fingerprint {
		t.Fatalf("want OK with the signer's fingerprint sealed, got %+v", res)
	}

	// A fingerprint naming anyone but the signer is refused outright.
	meta.SenderFingerprint = impostor.kp.Fingerprint
	if err := encrypt.EncryptStream(&bytes.Buffer{}, strings.NewReader("x"), []string{recipient.kp.EncryptionRecipient}, sender.u, meta, format.ProfilePrivate); err == nil {
		t.Fatal("a sealed fingerprint that is not the signer's must be refused")
	}
}

func TestWrongRecipientCannotDecrypt(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	stranger := newParty(t, "stranger")
	data := encryptContainer(t, sender, recipient, []byte("secret"), format.ProfilePrivate, true)

	var out bytes.Buffer
	if _, err := DecryptAndVerifyStream(bytes.NewReader(data), &out, stranger.u, nil); err == nil {
		t.Fatal("want decrypt error for wrong recipient")
	}
}

func TestBadContainerErrors(t *testing.T) {
	recipient := newParty(t, "recipient")
	if _, err := DecryptAndVerify([]byte("not an icfx container"), recipient.u, nil); err == nil {
		t.Fatal("want error for garbage input")
	}
	if _, err := DecryptAndVerify([]byte("ICFX\x09\x00\x00rest"), recipient.u, nil); !errors.Is(err, format.ErrUnsupportedProfile) {
		t.Fatalf("unknown profile: want ErrUnsupportedProfile, got %v", err)
	}
}
