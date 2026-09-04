package profile_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/profile"
)

const (
	testKSPass     = "keystore-at-rest-pass"
	testExportPass = "cloud-enc-key-passphrase"
)

// useEnv points the global icfx dirs at an isolated temp tree (a "device") and
// returns an encrypted file keystore rooted there.
func useEnv(t *testing.T, dir string) *keystore.FileStore {
	t.Helper()
	config.SetConfigDir(filepath.Join(dir, "config"))
	config.SetDataPath(filepath.Join(dir, "data"))
	config.SetKeyPath(filepath.Join(dir, "keys"))
	if err := config.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories: %v", err)
	}
	keysDir, err := config.KeysDir()
	if err != nil {
		t.Fatalf("KeysDir: %v", err)
	}
	return keystore.NewEncryptedFileStoreWithDir(keysDir, func() (string, error) { return testKSPass, nil })
}

// createLocalIdentity mirrors `icc identity create`: generate a keypair, store
// its keys, save encrypted meta, and append the index entry.
func createLocalIdentity(t *testing.T, ks keystore.Keystore, name string) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
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
		Backend:     identity.BackendFile,
	}
	store, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.SaveMeta(info); err != nil {
		t.Fatalf("SaveMeta: %v", err)
	}
	entries, err := store.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	entries = append(entries, identity.IdentityIndex{Name: name, Backend: identity.BackendFile})
	if err := store.SaveIndex(entries); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return kp
}

// openFnFor mirrors ic-cli's openIdentity against the given keystore.
func openFnFor(ks keystore.Keystore) profile.OpenIdentityFn {
	return func(name string) (*identity.Unlocked, error) {
		store, err := identity.NewStore()
		if err != nil {
			return nil, err
		}
		entries, err := store.LoadIndex()
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Name != name {
				continue
			}
			u, err := identity.Unlock(ks, identity.Identity{Name: e.Name, Backend: e.Backend, HWKey: e.HWKey})
			if err != nil {
				return nil, err
			}
			if err := u.LoadMeta(store, e); err != nil {
				u.Close()
				return nil, err
			}
			return u, nil
		}
		return nil, identity.ErrNotFound
	}
}

// fileExportFn ships each identity's passphrase-encrypted at-rest ciphertext
// verbatim (the GPG-style transport) — it does NOT decrypt.
func fileExportFn(t *testing.T) profile.IdentityExportFn {
	t.Helper()
	return func(idx identity.IdentityIndex) (profile.RoamingEntry, error) {
		keysDir, err := config.KeysDir()
		if err != nil {
			return profile.RoamingEntry{}, err
		}
		enc, err := os.ReadFile(filepath.Join(keysDir, idx.Name+".enc"))
		if err != nil {
			return profile.RoamingEntry{}, err
		}
		sign, err := os.ReadFile(filepath.Join(keysDir, idx.Name+".sign"))
		if err != nil {
			return profile.RoamingEntry{}, err
		}
		return profile.RoamingEntry{Protection: profile.ProtectionPassphrase, Enc: enc, Sign: sign}, nil
	}
}

// fileImportFn writes the ciphertext to disk verbatim (no re-encryption, no prompt).
func fileImportFn(t *testing.T) profile.IdentityImportFn {
	t.Helper()
	return func(name string, entry profile.RoamingEntry) (string, error) {
		keysDir, err := config.KeysDir()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(keysDir, 0700); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(keysDir, name+".enc"), entry.Enc, 0600); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(keysDir, name+".sign"), entry.Sign, 0600); err != nil {
			return "", err
		}
		return identity.BackendFile, nil
	}
}

// TestExportImportIdentitiesRoaming is the roaming core: each identity's
// encrypted-at-rest form roams to a clean device via merge-import —
// non-destructively (existing identities survive) and idempotently by name.
func TestExportImportIdentitiesRoaming(t *testing.T) {
	// Device A: two identities, exported as their at-rest ciphertext.
	ksA := useEnv(t, t.TempDir())
	kpAlice := createLocalIdentity(t, ksA, "alice")
	kpBob := createLocalIdentity(t, ksA, "bob")

	blob, err := profile.ExportIdentitiesToBytes(testExportPass, fileExportFn(t))
	if err != nil {
		t.Fatalf("ExportIdentitiesToBytes: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("export produced empty blob")
	}
	// Zero-knowledge: the blob must be opaque — no plaintext names or keys.
	if bytes.Contains(blob, []byte("alice")) || bytes.Contains(blob, []byte(kpAlice.EncryptionRecipient)) {
		t.Fatal("export blob is not opaque — contains plaintext identity data")
	}

	// Device B: clean device that already holds its own "carol" plus a
	// same-named "bob" with DIFFERENT keys (to prove upsert + non-destructive).
	ksB := useEnv(t, t.TempDir())
	createLocalIdentity(t, ksB, "carol")
	createLocalIdentity(t, ksB, "bob") // will be upserted to device A's bob

	if err := profile.ImportIdentitiesFromBytes(blob, testExportPass, fileImportFn(t)); err != nil {
		t.Fatalf("ImportIdentitiesFromBytes: %v", err)
	}

	// Index on B: carol (untouched) + bob (upserted, not duplicated) + alice (added).
	storeB, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore(B): %v", err)
	}
	entries, err := storeB.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex(B): %v", err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	for _, want := range []string{"alice", "bob", "carol"} {
		if !names[want] {
			t.Errorf("identity %q missing from device B after merge", want)
		}
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 identities on B (bob not duplicated), got %d: %v", len(entries), names)
	}

	// alice's private key roamed and is usable on B.
	open := openFnFor(ksB)
	alice, err := open("alice")
	if err != nil {
		t.Fatalf("open alice on B: %v", err)
	}
	defer alice.Close()
	if alice.Info().EncPubKey != kpAlice.EncryptionRecipient {
		t.Errorf("alice pubkey mismatch after roaming")
	}
	msg := []byte("roamed secret")
	ct, err := alice.EncryptToSelf(msg)
	if err != nil {
		t.Fatalf("EncryptToSelf: %v", err)
	}
	pt, err := alice.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("roamed key round-trip mismatch")
	}

	// bob was upserted to device A's key (B's original bob key replaced).
	bob, err := open("bob")
	if err != nil {
		t.Fatalf("open bob on B: %v", err)
	}
	defer bob.Close()
	if bob.Info().EncPubKey != kpBob.EncryptionRecipient {
		t.Errorf("bob was not upserted to device A's key")
	}
}
