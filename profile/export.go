package profile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
)

// Export creates a passphrase-protected backup of the user's complete icfx
// state (config + identities + per-identity meta + contacts + per-identity
// encrypted key bundles) and writes it to outputPath.
//
// All identities are included regardless of backend (file or keychain) —
// each identity is exported via Unlocked.Export inside the tarball, so the
// keys travel as encrypted bundles rather than raw on-disk files. This is
// what makes keychain-backed identities recoverable on a different device.
//
// openFn opens the named identity into an *Unlocked handle; callers provide
// it because the right keystore construction is caller-specific (passphrase
// prompts, session passphrase, HW key handling). ic-cli's openIdentity and
// ic-app's openIdentity both fit this signature directly.
func Export(outputPath string, exportPassphrase string, openFn OpenIdentityFn) error {
	data, err := ExportToBytes(exportPassphrase, openFn)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0600)
}

// ExportToBytes is Export but returns the encrypted bytes directly. Used
// by ic-app where the Dart side handles the file-save dialog.
func ExportToBytes(exportPassphrase string, openFn OpenIdentityFn) ([]byte, error) {
	return ExportToBytesWithPass([]byte(exportPassphrase), openFn)
}

// ExportToBytesWithPass is the wipeable-bytes core of ExportToBytes: the
// passphrase stays a caller-owned (and caller-wiped) []byte down to the age
// boundary.
func ExportToBytesWithPass(exportPassphrase []byte, openFn OpenIdentityFn) ([]byte, error) {
	if len(exportPassphrase) == 0 {
		return nil, fmt.Errorf("export passphrase cannot be empty")
	}
	if openFn == nil {
		return nil, fmt.Errorf("openFn callback is required")
	}

	idStore, err := identity.NewStore()
	if err != nil {
		return nil, fmt.Errorf("creating identity store: %w", err)
	}
	entries, err := idStore.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("loading identity index: %w", err)
	}

	metaDir, err := config.IdentityMetaDir()
	if err != nil {
		return nil, fmt.Errorf("resolving identity meta dir: %w", err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	manifest := Manifest{
		Version:    bundleVersion,
		ExportedAt: time.Now().UTC(),
	}

	// Per-identity bundles + meta files.
	for _, e := range entries {
		unlocked, err := openFn(e.Name)
		if err != nil {
			return nil, fmt.Errorf("opening identity %q: %w", e.Name, err)
		}
		bundle, err := unlocked.ExportBytes(exportPassphrase)
		info := unlocked.Info()
		unlocked.Close()
		if err != nil {
			return nil, fmt.Errorf("exporting identity %q: %w", e.Name, err)
		}

		if err := tarWriteBytes(tw, filepath.Join("identities-bundles", e.Name+".icid"), bundle); err != nil {
			return nil, fmt.Errorf("writing bundle for %q: %w", e.Name, err)
		}

		metaPath := filepath.Join(metaDir, e.Name+".meta")
		if err := tarWriteFile(tw, metaPath, filepath.Join("identities", e.Name+".meta")); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("writing meta for %q: %w", e.Name, err)
		}

		manifest.Identities = append(manifest.Identities, ManifestIdentity{
			Name:  e.Name,
			HWKey: info.HWKey,
		})
	}

	// Singletons.
	configPath, _ := config.ConfigFilePath()
	if err := tarWriteFile(tw, configPath, "config.toml"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("writing config.toml: %w", err)
	}

	contactsPath, _ := config.ContactsFilePath()
	contactCount := countContactsAtPath(contactsPath)
	manifest.ContactCount = contactCount
	if err := tarWriteFile(tw, contactsPath, "contacts.json"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("writing contacts.json: %w", err)
	}

	// Manifest goes in LAST so it can include accurate counts. Position in
	// the tarball doesn't matter for our Import flow (which reads the whole
	// tar into memory before deciding what to do), but the convention is to
	// put metadata first; we put it last here purely as an implementation
	// shortcut. If Import ever wants to short-circuit on manifest, we can
	// switch to a two-pass write.
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}
	if err := tarWriteBytes(tw, "manifest.json", manifestJSON); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip: %w", err)
	}

	encrypted, err := crypto.EncryptWithPassphraseBytes(buf.Bytes(), exportPassphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypting profile: %w", err)
	}
	return encrypted, nil
}

// tarWriteBytes writes a single byte payload as a tar entry under name.
func tarWriteBytes(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name: name,
		Size: int64(len(data)),
		Mode: 0600,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// tarWriteFile reads diskPath and writes it as a tar entry under archiveName.
// Returns os.IsNotExist errors verbatim so callers can decide whether the
// file's absence is fatal.
func tarWriteFile(tw *tar.Writer, diskPath, archiveName string) error {
	data, err := os.ReadFile(diskPath)
	if err != nil {
		return err
	}
	return tarWriteBytes(tw, archiveName, data)
}

// countContactsAtPath returns the count of contacts in the local store, used
// only to populate the manifest's contact_count field for preview purposes.
// Best-effort: returns 0 on any error (missing file, parse failure, etc.).
func countContactsAtPath(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	// Reuse contacts package's wire format minimally — just count entries in
	// the JSON array under "contacts". Don't import contacts package to avoid
	// circular deps in case profile is ever pulled in there.
	type wireWrapper struct {
		Contacts []json.RawMessage `json:"contacts"`
	}
	var w wireWrapper
	if err := json.Unmarshal(raw, &w); err != nil {
		return 0
	}
	return len(w.Contacts)
}
