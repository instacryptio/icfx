package identity_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
)

// makeTestUnlocked generates a fresh keypair, stores it in an in-memory
// keystore, and returns the resulting Unlocked + the public key bytes for
// signature verification.
func makeTestUnlocked(t *testing.T, name string) (*identity.Unlocked, []byte, []byte) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ks := newMemKeystore()
	if err := ks.StoreEncryptionIdentity(name, kp.EncryptionIdentity); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}
	if err := ks.StoreSigningKey(name, kp.SigningPrivateKey); err != nil {
		t.Fatalf("StoreSigningKey: %v", err)
	}

	info := identity.Identity{
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
		Status:      identity.StatusActive,
	}

	u, err := identity.Unlock(ks, info)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return u, kp.SigningPublicKey, []byte(kp.EncryptionRecipient)
}

func TestUnlocked_SignVerifyRoundTrip(t *testing.T) {
	u, signPub, _ := makeTestUnlocked(t, "alice")
	defer u.Close()

	data := []byte("the quick brown fox")
	sig, err := u.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := identity.Verify(data, sig, signPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("Verify returned false on a valid signature")
	}

	// Tamper with the data — verification must fail.
	ok, _ = identity.Verify([]byte("not the original"), sig, signPub)
	if ok {
		t.Errorf("Verify returned true on tampered data")
	}
}

func TestUnlocked_EncryptDecryptRoundTrip(t *testing.T) {
	alice, _, _ := makeTestUnlocked(t, "alice")
	defer alice.Close()
	bob, _, _ := makeTestUnlocked(t, "bob")
	defer bob.Close()

	plaintext := []byte("for bob's eyes only")

	ciphertext, err := alice.Encrypt(plaintext, []string{bob.Info().EncPubKey})
	if err != nil {
		t.Fatalf("alice.Encrypt: %v", err)
	}

	got, err := bob.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("bob.Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}

	// Alice can't decrypt — wrong identity
	if _, err := alice.Decrypt(ciphertext); err == nil {
		t.Errorf("alice.Decrypt of bob's ciphertext should fail")
	}
}

func TestUnlocked_EncryptToSelfRoundTrip(t *testing.T) {
	u, _, _ := makeTestUnlocked(t, "alice")
	defer u.Close()

	plaintext := []byte("note to self")
	ciphertext, err := u.EncryptToSelf(plaintext)
	if err != nil {
		t.Fatalf("EncryptToSelf: %v", err)
	}

	got, err := u.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestUnlocked_GitSignRoundTrip(t *testing.T) {
	u, signPub, _ := makeTestUnlocked(t, "alice")
	defer u.Close()

	commitContent := []byte("tree abc\nauthor x <x@x.io> 0 +0000\n\nsubject\n")

	var sigBuf bytes.Buffer
	if err := u.GitSign(bytes.NewReader(commitContent), &sigBuf); err != nil {
		t.Fatalf("GitSign: %v", err)
	}

	ok, err := crypto.GitVerify(bytes.NewReader(commitContent), sigBuf.Bytes(), signPub)
	if err != nil {
		t.Fatalf("GitVerify: %v", err)
	}
	if !ok {
		t.Errorf("GitVerify returned false on a valid git signature")
	}

	// Confirm the fingerprint header is present
	_, fpr, err := crypto.ParseGitSignature(sigBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseGitSignature: %v", err)
	}
	if fpr != u.Fingerprint() {
		t.Errorf("signature fingerprint = %q, want %q", fpr, u.Fingerprint())
	}
}

func TestUnlocked_CloseWipesAndOpsErrorAfterClose(t *testing.T) {
	u, _, _ := makeTestUnlocked(t, "alice")
	u.Close()

	// Close is idempotent.
	u.Close()

	if _, err := u.Sign([]byte("x")); !errors.Is(err, identity.ErrUnlockedClosed) {
		t.Errorf("Sign after Close returned %v, want ErrUnlockedClosed", err)
	}
	if _, err := u.Decrypt([]byte("x")); !errors.Is(err, identity.ErrUnlockedClosed) {
		t.Errorf("Decrypt after Close returned %v, want ErrUnlockedClosed", err)
	}
	if _, err := u.Encrypt([]byte("x"), []string{"age1pq1foo"}); !errors.Is(err, identity.ErrUnlockedClosed) {
		t.Errorf("Encrypt after Close returned %v, want ErrUnlockedClosed", err)
	}
	if _, err := u.EncryptToSelf([]byte("x")); !errors.Is(err, identity.ErrUnlockedClosed) {
		t.Errorf("EncryptToSelf after Close returned %v, want ErrUnlockedClosed", err)
	}
	if err := u.GitSign(bytes.NewReader([]byte("x")), &bytes.Buffer{}); !errors.Is(err, identity.ErrUnlockedClosed) {
		t.Errorf("GitSign after Close returned %v, want ErrUnlockedClosed", err)
	}
	if _, err := u.Export("pp"); !errors.Is(err, identity.ErrUnlockedClosed) {
		t.Errorf("Export after Close returned %v, want ErrUnlockedClosed", err)
	}
}

func TestExportImport_RoundTrip(t *testing.T) {
	src, _, _ := makeTestUnlocked(t, "alice")
	defer src.Close()

	bundle, err := src.Export("export-pass")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	dstKS := newMemKeystore()
	imported, err := identity.Import(bundle, "export-pass", dstKS, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if imported.Name != src.Name() {
		t.Errorf("imported name = %q, want %q", imported.Name, src.Name())
	}
	if imported.Fingerprint != src.Fingerprint() {
		t.Errorf("imported fingerprint = %q, want %q", imported.Fingerprint, src.Fingerprint())
	}

	// Re-Unlock from the destination keystore — should produce a working
	// handle that can decrypt what alice's original handle encrypted.
	dst, err := identity.Unlock(dstKS, imported)
	if err != nil {
		t.Fatalf("re-Unlock from destination keystore: %v", err)
	}
	defer dst.Close()

	plaintext := []byte("survives the round trip")
	ciphertext, err := src.EncryptToSelf(plaintext)
	if err != nil {
		t.Fatalf("EncryptToSelf: %v", err)
	}
	got, err := dst.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("dst.Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("post-import decrypt = %q, want %q", got, plaintext)
	}
}

func TestImport_WrongPassphraseFails(t *testing.T) {
	src, _, _ := makeTestUnlocked(t, "alice")
	defer src.Close()

	bundle, err := src.Export("right-pass")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if _, err := identity.Import(bundle, "wrong-pass", newMemKeystore(), nil); err == nil {
		t.Errorf("Import with wrong passphrase should fail")
	}
}

func TestExport_EmptyPassphraseRejected(t *testing.T) {
	u, _, _ := makeTestUnlocked(t, "alice")
	defer u.Close()
	if _, err := u.Export(""); err == nil {
		t.Errorf("Export with empty passphrase should fail")
	}
}

// --- HW Export/Import round-trip ---

// stubHardwareKey simulates a hardware key by HMAC-SHA1 of a stored secret
// over the challenge bytes. Two stubs with the same secret produce the same
// response — so a HW-protected identity exported with stub-A and imported
// with stub-A round-trips identically to a real device-with-the-same-secret.
type stubHardwareKey struct{ secret []byte }

func (s *stubHardwareKey) Challenge(c []byte) ([]byte, error) {
	mac := hmac.New(sha1.New, s.secret)
	mac.Write(c)
	return mac.Sum(nil), nil
}
func (s *stubHardwareKey) Serial() string { return "STUB-001" }
func (s *stubHardwareKey) Type() string   { return "stub" }

// makeHWUnlocked builds an HW-protected identity end-to-end so the rest of
// the round-trip tests have a known starting state.
func makeHWUnlocked(t *testing.T, name, passphrase string, hwSecret []byte) (*identity.Unlocked, *keystore.HardwareKeyDecorator, []byte) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	hw := &stubHardwareKey{secret: hwSecret}
	passFn := func() ([]byte, error) { return []byte(passphrase), nil }
	dec := keystore.NewHardwareKeyDecorator(newMemKeystore(), hw, dir, passFn)

	if err := dec.StoreEncryptionIdentity(name, kp.EncryptionIdentity); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}
	if err := dec.StoreSigningKey(name, kp.SigningPrivateKey); err != nil {
		t.Fatalf("StoreSigningKey: %v", err)
	}
	info := identity.Identity{
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
		Status:      identity.StatusActive,
		HWKey:       true,
	}
	u, err := identity.Unlock(dec, info)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return u, dec, kp.SigningPublicKey
}

func TestExportImport_PreservesHW(t *testing.T) {
	hwSecret := []byte("device-secret-AAA")
	src, _, _ := makeHWUnlocked(t, "alice", "user-pass", hwSecret)
	defer src.Close()

	bundle, err := src.Export("export-pass")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Import on a fresh keystore. The restoreHW callback wires in a
	// fresh decorator over the new memKeystore, persisting the bundle's
	// challenge bytes so the same KEK is derived for future unlocks.
	dstKS := newMemKeystore()
	dstDir := t.TempDir()
	dstHW := &stubHardwareKey{secret: hwSecret} // same secret = same device class
	dstPass := func() ([]byte, error) { return []byte("user-pass"), nil }

	var dstDec *keystore.HardwareKeyDecorator
	imported, err := identity.Import(bundle, "export-pass", dstKS, func(challenge []byte) (keystore.Keystore, error) {
		dstDec = keystore.NewHardwareKeyDecorator(dstKS, dstHW, dstDir, dstPass)
		if err := dstDec.WriteChallenge("alice", challenge); err != nil {
			return nil, err
		}
		return dstDec, nil
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !imported.HWKey {
		t.Errorf("imported.HWKey = false, want true (restoreHW returned a HW keystore)")
	}

	// Re-Unlock from the destination decorator and decrypt something
	// originally encrypted by the source identity.
	dst, err := identity.Unlock(dstDec, imported)
	if err != nil {
		t.Fatalf("re-Unlock: %v", err)
	}
	defer dst.Close()
	plaintext := []byte("hw-protected payload")
	ct, err := src.EncryptToSelf(plaintext)
	if err != nil {
		t.Fatalf("EncryptToSelf: %v", err)
	}
	got, err := dst.Decrypt(ct)
	if err != nil {
		t.Fatalf("dst.Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("post-import decrypt = %q, want %q", got, plaintext)
	}
}

func TestExportImport_StripHW(t *testing.T) {
	src, _, _ := makeHWUnlocked(t, "alice", "user-pass", []byte("device-secret"))
	defer src.Close()

	bundle, err := src.Export("export-pass")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	dstKS := newMemKeystore()
	imported, err := identity.Import(bundle, "export-pass", dstKS, func(challenge []byte) (keystore.Keystore, error) {
		return nil, nil // decline HW restore
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imported.HWKey {
		t.Errorf("imported.HWKey = true, want false (caller declined HW restore)")
	}

	// Re-Unlock from the plain keystore — should work without any device.
	dst, err := identity.Unlock(dstKS, imported)
	if err != nil {
		t.Fatalf("re-Unlock from plain keystore: %v", err)
	}
	defer dst.Close()
	plaintext := []byte("now non-hw")
	ct, err := src.EncryptToSelf(plaintext)
	if err != nil {
		t.Fatalf("EncryptToSelf: %v", err)
	}
	got, err := dst.Decrypt(ct)
	if err != nil {
		t.Fatalf("dst.Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypt mismatch: got %q, want %q", got, plaintext)
	}
}

// --- in-memory keystore for tests ---

// hwErrKeystore is a memKeystore that also satisfies HWChallengeProvider but
// always fails Challenge — used to exercise Unlock's HW-challenge error path,
// which must destroy the already-sealed key enclaves before returning.
type hwErrKeystore struct {
	*memKeystore
}

func (hwErrKeystore) Challenge(string) ([]byte, error) {
	return nil, errors.New("hardware device error")
}

// TestUnlockHWChallengeErrorReturnsAndWipes: when the HW challenge fails after
// the key enclaves are sealed, Unlock returns the error (and, per the fix,
// destroys the enclaves — verified indirectly by -race/no-panic).
func TestUnlockHWChallengeErrorReturnsAndWipes(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	mem := newMemKeystore()
	if err := mem.StoreEncryptionIdentity("hw", kp.EncryptionIdentity); err != nil {
		t.Fatal(err)
	}
	if err := mem.StoreSigningKey("hw", kp.SigningPrivateKey); err != nil {
		t.Fatal(err)
	}
	u, err := identity.Unlock(hwErrKeystore{mem}, identity.Identity{Name: "hw", HWKey: true})
	if err == nil {
		u.Close()
		t.Fatal("expected an error when the HW challenge fails")
	}
	if u != nil {
		t.Fatal("expected nil Unlocked on error")
	}
}

type memKeystore struct {
	enc map[string]string
	sig map[string][]byte
}

func newMemKeystore() *memKeystore {
	return &memKeystore{enc: map[string]string{}, sig: map[string][]byte{}}
}

func (m *memKeystore) StoreEncryptionIdentity(name, identity string) error {
	m.enc[name] = identity
	return nil
}
func (m *memKeystore) LoadEncryptionIdentity(name string) (string, error) {
	v, ok := m.enc[name]
	if !ok {
		return "", errMemKeystoreNotFound
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
		return nil, errMemKeystoreNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}
func (m *memKeystore) HasKeys(name string) bool {
	_, ok1 := m.enc[name]
	_, ok2 := m.sig[name]
	return ok1 && ok2
}
func (m *memKeystore) Clear(name string) error {
	delete(m.enc, name)
	delete(m.sig, name)
	return nil
}
func (m *memKeystore) ListNames() ([]string, error) {
	seen := map[string]bool{}
	for k := range m.enc {
		seen[k] = true
	}
	for k := range m.sig {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

var errMemKeystoreNotFound = errors.New("memKeystore: not found")

// Compile-time interface check.
var _ keystore.Keystore = (*memKeystore)(nil)
