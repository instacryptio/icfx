package identity_test

import (
	"testing"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
)

// tempProfile points config at a throwaway home so the on-disk index + meta
// land in a temp dir, then returns a fresh Store.
func tempProfile(t *testing.T) *identity.Store {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_DATA_HOME", home+"/.local/share")
	if err := config.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories: %v", err)
	}
	store, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// infoFor builds an importable Identity with a real EncPubKey (SaveMeta encrypts
// the meta to it).
func infoFor(t *testing.T, name, alias string) identity.Identity {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return identity.Identity{
		Name:        name,
		Alias:       alias,
		EncPubKey:   kp.EncryptionRecipient,
		Fingerprint: kp.Fingerprint,
		Status:      identity.StatusActive,
	}
}

func TestPersistImported(t *testing.T) {
	store := tempProfile(t)

	// First import → isFirst, writes index entry incl. Alias.
	imp := infoFor(t, "imp", "impalias")
	isFirst, dropped, err := identity.PersistImported(store, imp, identity.BackendFile)
	if err != nil || !isFirst || dropped {
		t.Fatalf("first import: isFirst=%v dropped=%v err=%v", isFirst, dropped, err)
	}
	entries, err := store.LoadIndex()
	if err != nil || len(entries) != 1 {
		t.Fatalf("index after first import: %+v err=%v", entries, err)
	}
	if entries[0].Name != "imp" || entries[0].Alias != "impalias" || entries[0].Backend != identity.BackendFile {
		t.Fatalf("index entry wrong: %+v", entries[0])
	}

	// Re-persisting the SAME identity (same keys/fingerprint) is idempotent —
	// this is the orphaned-import reconcile case; still one entry.
	isFirst, _, err = identity.PersistImported(store, imp, identity.BackendFile)
	if err != nil || isFirst {
		t.Fatalf("reconcile: isFirst=%v err=%v", isFirst, err)
	}
	if entries, _ = store.LoadIndex(); len(entries) != 1 {
		t.Fatalf("reconcile must not duplicate, got %d", len(entries))
	}

	// A DIFFERENT identity (different fingerprint) with the SAME name must be
	// REFUSED — this would hijack the existing entry (F3).
	if _, _, herr := identity.PersistImported(store, infoFor(t, "imp", "impalias"), identity.BackendFile); herr == nil {
		t.Fatal("must refuse to overwrite a same-name identity with different keys")
	}

	// A DIFFERENT identity importing the SAME alias → alias dropped to "".
	_, dropped, err = identity.PersistImported(store, infoFor(t, "other", "impalias"), identity.BackendFile)
	if err != nil || !dropped {
		t.Fatalf("collision: dropped=%v err=%v", dropped, err)
	}
	entries, _ = store.LoadIndex()
	other, err := identity.FindIndexByNameOrAlias(entries, "other")
	if err != nil {
		t.Fatalf("other not indexed: %v", err)
	}
	if other.Alias != "" {
		t.Fatalf("colliding alias must be dropped, got %q", other.Alias)
	}
}
