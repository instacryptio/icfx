package cloud

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/qr"
)

type rawSigner struct{ key []byte }

func (r rawSigner) Sign(data []byte) ([]byte, error) { return crypto.Sign(data, r.key) }

func realLockBundle(t *testing.T, name string) qr.LockBundle {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	lb := qr.LockBundle{
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
	}
	sealed, err := qr.SealLock(rawSigner{kp.SigningPrivateKey}, lb)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

func directoryEntryFor(t *testing.T, lb qr.LockBundle) DirectoryEntry {
	t.Helper()
	raw, err := qr.MarshalLockBundle(lb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return DirectoryEntry{
		DisplayName: lb.Name,
		Fingerprint: lb.Fingerprint,
		LockArmored: string(format.ArmorEncode(raw, format.ArmorLockLabel)),
	}
}

// TestParseDirectoryLock: round trip succeeds; a listing whose fingerprint
// does not match the embedded lock is rejected — the check that stops a
// tampered or inconsistent directory row from planting a different key.
func TestParseDirectoryLock(t *testing.T) {
	lb := realLockBundle(t, "alice")
	entry := directoryEntryFor(t, lb)

	got, err := ParseDirectoryLock(entry)
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if got.Fingerprint != lb.Fingerprint || got.EncPubKey != lb.EncPubKey {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Fingerprint mismatch between listing and embedded lock → rejected.
	tampered := entry
	tampered.Fingerprint = realLockBundle(t, "mallory").Fingerprint
	if _, err := ParseDirectoryLock(tampered); err == nil {
		t.Fatal("fingerprint mismatch must be rejected")
	}
	if _, err := ParseDirectoryLock(tampered); err != nil && !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("want inconsistency error, got: %v", err)
	}

	// Garbage lock data → rejected.
	garbage := entry
	garbage.LockArmored = "not a lock"
	if _, err := ParseDirectoryLock(garbage); err == nil {
		t.Fatal("garbage lock must be rejected")
	}
}
