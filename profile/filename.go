package profile

import (
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity"
)

// defaultProfileFilename is the fallback when no default identity can be
// resolved (no config default and an empty index).
const defaultProfileFilename = "profile.tar.icfx"

// DefaultBackupFilename returns the default filename for a whole-profile backup:
// "<alias-or-name>-profile.tar.icfx", where the label comes from the default
// identity's plaintext index entry (NO unlock required — alias and name are
// both non-secret). Falls back to "profile.tar.icfx" when there is no default
// identity. This is the single source of truth for the profile backup name; an
// explicit user-chosen path still wins in the clients.
func DefaultBackupFilename() string {
	store, err := identity.NewStore()
	if err != nil {
		return defaultProfileFilename
	}
	entries, err := store.LoadIndex()
	if err != nil || len(entries) == 0 {
		return defaultProfileFilename
	}

	defaultName := ""
	if cfg, err := config.Load(); err == nil {
		defaultName = cfg.DefaultIdentity
	}
	idx := identity.ResolveDefaultIndex(entries, defaultName)
	if idx == nil {
		return defaultProfileFilename
	}
	return identity.BackupLabel(*idx) + "-profile.tar.icfx"
}
