package profile_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/profile"
)

// TestImportFromBytesRollsBackOnFailure pins the S0b safety property: when
// ImportFromBytes fails AFTER its point-of-no-return (wipeLocalState runs, then
// destKsFn is invoked), the snapshot/restore must put the user's original
// install back — no wiped keys, no half-install. Before the fix this test would
// fail: alice's keys would be gone.
func TestImportFromBytesRollsBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	ks := useEnv(t, dir)
	createLocalIdentity(t, ks, "alice")

	// A valid bundle to import (any valid bundle gets past manifest validation
	// and into the destructive phase).
	bundle, err := profile.ExportToBytesWithPass([]byte("bundle-pass"), openFnFor(ks))
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Capture the original on-disk install.
	keysDir, err := config.KeysDir()
	if err != nil {
		t.Fatalf("KeysDir: %v", err)
	}
	idxPath, err := config.IdentitiesFilePath()
	if err != nil {
		t.Fatalf("IdentitiesFilePath: %v", err)
	}
	origEnc := mustRead(t, filepath.Join(keysDir, "alice.enc"))
	origSign := mustRead(t, filepath.Join(keysDir, "alice.sign"))
	origIdx := mustRead(t, idxPath)

	// destKsFn is called AFTER wipeLocalState, so failing here means the wipe
	// already ran — the classic data-loss window this fix closes.
	failing := func() (keystore.Keystore, string, error) {
		return nil, "", fmt.Errorf("simulated destination-keystore failure")
	}
	err = profile.ImportFromBytes(bundle, profile.ImportOptions{PassphraseBytes: []byte("bundle-pass")}, failing)
	if err == nil {
		t.Fatal("expected import to fail, got nil")
	}

	// The original install must be intact, byte-for-byte.
	if got := mustRead(t, filepath.Join(keysDir, "alice.enc")); !bytes.Equal(got, origEnc) {
		t.Error("alice.enc not restored to its original contents after failed import")
	}
	if got := mustRead(t, filepath.Join(keysDir, "alice.sign")); !bytes.Equal(got, origSign) {
		t.Error("alice.sign not restored to its original contents after failed import")
	}
	if got := mustRead(t, idxPath); !bytes.Equal(got, origIdx) {
		t.Error("identities.json not restored to its original contents after failed import")
	}

	// The rollback archive must be cleaned up (no icfx-import-rollback-* left).
	leftovers, _ := filepath.Glob(filepath.Join(config.TempDir(), "icfx-import-rollback-*"))
	if len(leftovers) != 0 {
		t.Errorf("rollback archive not discarded after successful restore: %v", leftovers)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (rollback likely failed): %v", path, err)
	}
	return data
}
