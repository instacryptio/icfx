package keystore

import (
	"crypto/hmac"
	"crypto/sha1"
	"os"
	"path/filepath"
	"testing"

	"github.com/instacryptio/icfx/crypto"
)

// mockHardwareKey simulates a hardware key in memory by computing
// HMAC-SHA1(secret, challenge) directly. This matches what real hardware
// would do for the same secret + challenge.
type mockHardwareKey struct {
	secret []byte
	serial string
	typ    string
	calls  int
}

func newMockHardwareKey(secret []byte) *mockHardwareKey {
	return &mockHardwareKey{secret: secret, serial: "MOCK-001", typ: "mock"}
}

func (m *mockHardwareKey) Challenge(challenge []byte) ([]byte, error) {
	m.calls++
	mac := hmac.New(sha1.New, m.secret)
	mac.Write(challenge)
	return mac.Sum(nil), nil
}

func (m *mockHardwareKey) Serial() string { return m.serial }
func (m *mockHardwareKey) Type() string   { return m.typ }

// Verify mock satisfies the interface.
var _ crypto.HardwareKey = (*mockHardwareKey)(nil)

func TestHardwareKeyDecorator_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	hwSecret := []byte("device-secret-12345678901")
	hw := newMockHardwareKey(hwSecret)

	passFn := func() ([]byte, error) { return []byte("user-passphrase"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	identity := "AGE-SECRET-KEY-PQ-1FAKEFAKEFAKE"
	if err := dec.StoreEncryptionIdentity("alice", identity); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}

	if _, err := os.Stat(dec.ChallengePath("alice")); err != nil {
		t.Errorf("expected alice.hwchallenge to exist after first store")
	}

	got, err := dec.LoadEncryptionIdentity("alice")
	if err != nil {
		t.Fatalf("LoadEncryptionIdentity: %v", err)
	}
	if got != identity {
		t.Errorf("identity round-trip mismatch:\nstored=%q\nloaded=%q", identity, got)
	}
}

func TestHardwareKeyDecorator_SigningKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("hw-secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	signKey := []byte{0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78}
	if err := dec.StoreSigningKey("alice", signKey); err != nil {
		t.Fatalf("StoreSigningKey: %v", err)
	}
	got, err := dec.LoadSigningKey("alice")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if string(got) != string(signKey) {
		t.Errorf("signing key round-trip mismatch:\nstored=%x\nloaded=%x", signKey, got)
	}
}

func TestHardwareKeyDecorator_DifferentDeviceFails(t *testing.T) {
	dir := t.TempDir()
	hw1 := newMockHardwareKey([]byte("device-A-secret"))
	passFn := func() ([]byte, error) { return []byte("samepass"), nil }

	dec1 := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw1, dir, passFn)
	if err := dec1.StoreEncryptionIdentity("alice", "AGE-SECRET-KEY-PQ-1XYZ"); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}

	hw2 := newMockHardwareKey([]byte("device-B-secret"))
	dec2 := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw2, dir, passFn)
	_, err := dec2.LoadEncryptionIdentity("alice")
	if err == nil {
		t.Errorf("expected decryption to fail with different hardware secret")
	}
}

func TestHardwareKeyDecorator_WrongPassphraseFails(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("hw-secret"))

	passOK := func() ([]byte, error) { return []byte("right-pass"), nil }
	dec1 := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passOK)
	if err := dec1.StoreEncryptionIdentity("alice", "AGE-SECRET-KEY-PQ-1XYZ"); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}

	passWrong := func() ([]byte, error) { return []byte("wrong-pass"), nil }
	dec2 := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passWrong)
	_, err := dec2.LoadEncryptionIdentity("alice")
	if err == nil {
		t.Errorf("expected decryption to fail with wrong passphrase")
	}
}

func TestHardwareKeyDecorator_ChallengePersistsAcrossOps(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }

	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)
	if err := dec.StoreEncryptionIdentity("alice", "id-1"); err != nil {
		t.Fatalf("first store: %v", err)
	}

	challenge1, err := os.ReadFile(filepath.Join(dir, "alice.hwchallenge"))
	if err != nil {
		t.Fatalf("reading challenge file: %v", err)
	}

	// Subsequent operation on the same identity should reuse the persisted challenge.
	if err := dec.StoreSigningKey("alice", []byte{1, 2, 3}); err != nil {
		t.Fatalf("second store: %v", err)
	}

	challenge2, err := os.ReadFile(filepath.Join(dir, "alice.hwchallenge"))
	if err != nil {
		t.Fatalf("re-reading challenge file: %v", err)
	}

	if string(challenge1) != string(challenge2) {
		t.Errorf("alice's challenge changed between operations:\nfirst=%x\nsecond=%x", challenge1, challenge2)
	}
}

// TestHardwareKeyDecorator_DistinctChallengesPerIdentity verifies the central
// invariant of the per-identity model: two identities sharing the same
// physical hardware key get distinct challenges (and therefore distinct KEKs).
func TestHardwareKeyDecorator_DistinctChallengesPerIdentity(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	if err := dec.StoreEncryptionIdentity("alice", "id-alice"); err != nil {
		t.Fatalf("store alice: %v", err)
	}
	if err := dec.StoreEncryptionIdentity("bob", "id-bob"); err != nil {
		t.Fatalf("store bob: %v", err)
	}

	aliceChallenge, err := os.ReadFile(filepath.Join(dir, "alice.hwchallenge"))
	if err != nil {
		t.Fatalf("reading alice's challenge: %v", err)
	}
	bobChallenge, err := os.ReadFile(filepath.Join(dir, "bob.hwchallenge"))
	if err != nil {
		t.Fatalf("reading bob's challenge: %v", err)
	}

	if string(aliceChallenge) == string(bobChallenge) {
		t.Errorf("expected distinct challenges per identity; both got %x", aliceChallenge)
	}

	// Round-trip both — must independently decrypt.
	gotAlice, err := dec.LoadEncryptionIdentity("alice")
	if err != nil {
		t.Fatalf("load alice: %v", err)
	}
	if gotAlice != "id-alice" {
		t.Errorf("alice: got %q, want %q", gotAlice, "id-alice")
	}
	gotBob, err := dec.LoadEncryptionIdentity("bob")
	if err != nil {
		t.Fatalf("load bob: %v", err)
	}
	if gotBob != "id-bob" {
		t.Errorf("bob: got %q, want %q", gotBob, "id-bob")
	}
}

func TestHardwareKeyDecorator_RemoveChallenge(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	if err := dec.StoreEncryptionIdentity("alice", "id-1"); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := os.Stat(dec.ChallengePath("alice")); err != nil {
		t.Fatalf("expected challenge to exist after store")
	}

	if err := dec.RemoveChallenge("alice"); err != nil {
		t.Fatalf("RemoveChallenge: %v", err)
	}
	if _, err := os.Stat(dec.ChallengePath("alice")); err == nil {
		t.Errorf("expected challenge to be gone after RemoveChallenge")
	}

	// Idempotent: removing a non-existent challenge should not error.
	if err := dec.RemoveChallenge("alice"); err != nil {
		t.Errorf("RemoveChallenge on missing file should not error, got: %v", err)
	}
}

func TestHardwareKeyDecorator_ListNamesFiltersChallengeFiles(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	if err := dec.StoreEncryptionIdentity("alice", "id-1"); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}
	if err := dec.StoreSigningKey("alice", []byte{1, 2, 3}); err != nil {
		t.Fatalf("StoreSigningKey: %v", err)
	}

	names, err := dec.ListNames()
	if err != nil {
		t.Fatalf("ListNames: %v", err)
	}
	for _, n := range names {
		if n == "alice.hwchallenge" || n == ".hwchallenge" {
			t.Errorf("challenge file leaked into ListNames output: %q", n)
		}
	}
	found := false
	for _, n := range names {
		if n == "alice" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'alice' in ListNames output, got %v", names)
	}
}

// memKeystore is a keychain-shaped Keystore implementation backed by a Go
// map. It deliberately doesn't write any files, so it proves the decorator's
// crypto layer doesn't depend on file-backed inner storage.
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
		return "", os.ErrNotExist
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
		return nil, os.ErrNotExist
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

var _ Keystore = (*memKeystore)(nil)

// TestHardwareKeyDecorator_KeychainShapedInner exercises the storage-agnostic
// path: an inner keystore that only stores opaque bytes (no files, no
// passphrase callbacks of its own). Round-trip must succeed identically to
// the file-backed case. This is the PR 2 headline scenario — HW + keychain.
func TestHardwareKeyDecorator_KeychainShapedInner(t *testing.T) {
	challengeDir := t.TempDir() // challenge file always lives on disk
	hw := newMockHardwareKey([]byte("hw-secret"))
	passFn := func() ([]byte, error) { return []byte("user-pass"), nil }
	inner := newMemKeystore()
	dec := NewHardwareKeyDecorator(inner, hw, challengeDir, passFn)

	identity := "AGE-SECRET-KEY-PQ-1FAKE"
	if err := dec.StoreEncryptionIdentity("alice", identity); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}

	// The inner stores ciphertext, not plaintext — verify that.
	stored, err := inner.LoadEncryptionIdentity("alice")
	if err != nil {
		t.Fatalf("inner.LoadEncryptionIdentity: %v", err)
	}
	if stored == identity {
		t.Errorf("inner stored plaintext identity; expected ciphertext")
	}

	got, err := dec.LoadEncryptionIdentity("alice")
	if err != nil {
		t.Fatalf("dec.LoadEncryptionIdentity: %v", err)
	}
	if got != identity {
		t.Errorf("identity round-trip mismatch:\nstored=%q\nloaded=%q", identity, got)
	}

	signKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := dec.StoreSigningKey("alice", signKey); err != nil {
		t.Fatalf("StoreSigningKey: %v", err)
	}
	gotSig, err := dec.LoadSigningKey("alice")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if string(gotSig) != string(signKey) {
		t.Errorf("signing key round-trip mismatch:\nstored=%x\nloaded=%x", signKey, gotSig)
	}
}

// TestHardwareKeyDecorator_ChallengeProviderInterface verifies the decorator
// satisfies keystore.HWChallengeProvider — the interface identity.Unlock uses
// to auto-attach the challenge to an Unlocked handle.
func TestHardwareKeyDecorator_ChallengeProviderInterface(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	var p HWChallengeProvider = dec // compile-time interface check
	c, err := p.Challenge("alice")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(c) < 16 {
		t.Errorf("expected challenge >= 16 bytes, got %d", len(c))
	}
}

func TestHardwareKeyDecorator_EnsureChallenge(t *testing.T) {
	dir := t.TempDir()
	hw := newMockHardwareKey([]byte("secret"))
	passFn := func() ([]byte, error) { return []byte("pass"), nil }
	dec := NewHardwareKeyDecorator(NewFileStoreWithDir(dir), hw, dir, passFn)

	c1, err := dec.EnsureChallenge("alice")
	if err != nil {
		t.Fatalf("EnsureChallenge first call: %v", err)
	}
	if len(c1) < 16 {
		t.Errorf("expected challenge of at least 16 bytes, got %d", len(c1))
	}

	c2, err := dec.EnsureChallenge("alice")
	if err != nil {
		t.Fatalf("EnsureChallenge second call: %v", err)
	}
	if string(c1) != string(c2) {
		t.Errorf("EnsureChallenge should return the same value on repeat calls")
	}
}
