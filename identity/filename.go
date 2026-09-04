package identity

import (
	"path/filepath"
	"strings"
)

// backupLabel returns the preferred human label for a backup filename: the
// alias when set, otherwise the display name. Both are sanitized for use as a
// path component.
func backupLabel(alias, name string) string {
	label := alias
	if label == "" {
		label = name
	}
	return sanitizeFilenameLabel(label)
}

// sanitizeFilenameLabel strips path separators and whitespace from a label so
// it is safe as a single filename component. An alias has none of these by
// validation; a display Name might (spaces, slashes), so this is the defensive
// fallback path.
func sanitizeFilenameLabel(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "_")
	// Collapse any path separators the OS would interpret.
	s = strings.ReplaceAll(s, string(filepath.Separator), "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, `\`, "_")
	return s
}

// BackupLabel returns the sanitized filename stem (alias-or-name, no extension)
// for an index entry — the shared piece other backup filenames build on
// (e.g. the profile package appends its own "-profile.tar.icfx" suffix). Works
// without unlocking (alias + name are both plaintext).
func BackupLabel(idx IdentityIndex) string {
	return backupLabel(idx.Alias, idx.Name)
}

// BackupFilename is the single source of truth for an identity backup's default
// filename: "<alias-or-name>.icid". Clients use it for the default save path
// (an explicit user-chosen path still wins).
func BackupFilename(id Identity) string {
	return backupLabel(id.Alias, id.Name) + ".icid"
}

// IndexBackupFilename is the index-entry counterpart of BackupFilename, usable
// without unlocking the identity (alias + name are both plaintext).
func IndexBackupFilename(idx IdentityIndex) string {
	return BackupLabel(idx) + ".icid"
}
