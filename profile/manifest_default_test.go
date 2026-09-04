package profile_test

// Verifies the successor-propagation channel: the identities roaming manifest
// carries this device's DefaultIdentity and each identity's public Fingerprint,
// so another device can adopt the hand-off/rotation successor (behind the
// ConfirmDefaultChange gate) and detect a default key-swap without unlocking.
// Reuses useEnv/createLocalIdentity/fileExportFn/fileImportFn/testExportPass
// from identities_roundtrip_test.go (same package).

import (
	"testing"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/profile"
)

func TestManifestRoundTripsDefaultAndFingerprint(t *testing.T) {
	// Device A: two identities.
	ksA := useEnv(t, t.TempDir())
	kpAlice := createLocalIdentity(t, ksA, "alice")
	kpBob := createLocalIdentity(t, ksA, "bob")

	// createLocalIdentity omits Fingerprint on the index entry; the real
	// create/rotate/import paths populate it (slice 5). Backfill so the test
	// asserts the per-identity fingerprint rides the manifest.
	setIndexFingerprints(t, map[string]string{"alice": kpAlice.Fingerprint, "bob": kpBob.Fingerprint})

	// ExportIdentitiesToBytes reads the account default via config.Load()
	// internally — persist a config with one set.
	cfg := config.DefaultConfig()
	cfg.DefaultIdentity = "alice"
	if err := cfg.Save(); err != nil {
		t.Fatalf("cfg.Save: %v", err)
	}

	blob, err := profile.ExportIdentitiesToBytes(testExportPass, fileExportFn(t))
	if err != nil {
		t.Fatalf("ExportIdentitiesToBytes: %v", err)
	}

	// PeekRoamingManifest reads the pointer + fingerprints with NO key import.
	m, err := profile.PeekRoamingManifest(blob, testExportPass)
	if err != nil {
		t.Fatalf("PeekRoamingManifest: %v", err)
	}
	if m.DefaultIdentity != "alice" {
		t.Errorf("manifest DefaultIdentity = %q, want alice", m.DefaultIdentity)
	}
	fps := map[string]string{}
	for _, mi := range m.Identities {
		fps[mi.Name] = mi.Fingerprint
	}
	if fps["alice"] == "" || fps["alice"] != kpAlice.Fingerprint {
		t.Errorf("manifest alice fingerprint = %q, want %q", fps["alice"], kpAlice.Fingerprint)
	}
	if fps["bob"] == "" || fps["bob"] != kpBob.Fingerprint {
		t.Errorf("manifest bob fingerprint = %q, want %q", fps["bob"], kpBob.Fingerprint)
	}

	// Device B (clean): import populates the local index Fingerprint from the
	// manifest (identities.go), so B's key-swap gate has a value to compare.
	useEnv(t, t.TempDir())
	if err := profile.ImportIdentitiesFromBytes(blob, testExportPass, fileImportFn(t)); err != nil {
		t.Fatalf("ImportIdentitiesFromBytes: %v", err)
	}
	store, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore(B): %v", err)
	}
	entries, err := store.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex(B): %v", err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Fingerprint
	}
	if got["alice"] != kpAlice.Fingerprint {
		t.Errorf("imported alice index fingerprint = %q, want %q", got["alice"], kpAlice.Fingerprint)
	}
	if got["bob"] != kpBob.Fingerprint {
		t.Errorf("imported bob index fingerprint = %q, want %q", got["bob"], kpBob.Fingerprint)
	}
}

// setIndexFingerprints backfills Fingerprint on the named index entries.
func setIndexFingerprints(t *testing.T, fps map[string]string) {
	t.Helper()
	store, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	entries, err := store.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	for i := range entries {
		if fp, ok := fps[entries[i].Name]; ok {
			entries[i].Fingerprint = fp
		}
	}
	if err := store.SaveIndex(entries); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
}
