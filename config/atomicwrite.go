package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path durably: it writes to a temp file in the
// same directory, fsync-closes it with 0600 perms, then renames it over the
// target. A crash or full disk mid-write leaves the previous file intact rather
// than a truncated one, and readers never observe a partially-written file.
// The parent directory is created 0700 if missing.
//
// Shared by the plaintext-metadata stores (contacts, groups, identity meta,
// config) so the atomic-write logic lives in one place.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting temp file perms: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming temp file into place: %w", err)
	}
	return nil
}
