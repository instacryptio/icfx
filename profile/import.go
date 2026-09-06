package profile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/validate"
)

// PeekManifest decrypts only the manifest entry of a profile bundle and
// returns it without touching local state. Used by callers (typically the
// ic-app UI) to pre-flight what the bundle contains before showing the
// import-confirmation dialog. Same passphrase as Import.
//
// Wrong-passphrase errors propagate verbatim ("decrypting profile bundle
// (wrong passphrase?)" via crypto.DecryptWithPassphrase) so the caller
// can re-prompt.
func PeekManifest(inputPath string, importPassphrase string) (*Manifest, error) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("reading profile bundle: %w", err)
	}
	return PeekManifestFromBytes(raw, importPassphrase)
}

// PeekManifestFromBytes is PeekManifest but takes the encrypted bytes
// directly.
func PeekManifestFromBytes(data []byte, importPassphrase string) (*Manifest, error) {
	return PeekManifestFromBytesWithPass(data, []byte(importPassphrase))
}

// PeekManifestFromBytesWithPass is the wipeable-bytes core of
// PeekManifestFromBytes.
func PeekManifestFromBytesWithPass(data, importPassphrase []byte) (*Manifest, error) {
	plain, err := crypto.DecryptWithPassphraseBytes(data, importPassphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypting profile bundle (wrong passphrase?): %w", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, fmt.Errorf("decompressing bundle: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading bundle entry: %w", err)
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading manifest: %w", err)
		}
		var m Manifest
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("parsing manifest: %w", err)
		}
		if m.Version != bundleVersion {
			return nil, fmt.Errorf("unsupported bundle version %d (this build supports %d)", m.Version, bundleVersion)
		}
		return &m, nil
	}
	return nil, fmt.Errorf("manifest entry missing from bundle")
}

// PeekHWChallengesFromBytes returns, for each hardware-key-protected identity in
// a profile bundle, its HW challenge bytes keyed by identity name. The mobile
// client needs these to run the per-identity hardware-key ceremony (an NFC tap
// against the identity's own challenge) before importing the profile. The
// challenge is not secret; non-HW identities are omitted.
func PeekHWChallengesFromBytes(data, importPassphrase []byte) (map[string][]byte, error) {
	plain, err := crypto.DecryptWithPassphraseBytes(data, importPassphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypting profile bundle (wrong passphrase?): %w", err)
	}
	entries, err := readTarEntries(plain)
	if err != nil {
		return nil, err
	}
	manifestBytes, ok := entries["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("manifest entry missing from bundle")
	}
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	if m.Version != bundleVersion {
		return nil, fmt.Errorf("unsupported bundle version %d (this build supports %d)", m.Version, bundleVersion)
	}

	out := make(map[string][]byte)
	for _, mi := range m.Identities {
		if !mi.HWKey {
			continue
		}
		if err := validate.ValidateName(mi.Name); err != nil {
			return nil, fmt.Errorf("invalid identity name in bundle: %w", err)
		}
		bundleBytes, ok := entries["identities-bundles/"+mi.Name+".icid"]
		if !ok {
			return nil, fmt.Errorf("bundle for hardware-key identity %q missing from profile", mi.Name)
		}
		_, _, challenge, perr := identity.PeekBytesFull(bundleBytes, importPassphrase)
		if perr != nil {
			return nil, fmt.Errorf("peeking hardware-key identity %q: %w", mi.Name, perr)
		}
		if len(challenge) > 0 {
			out[mi.Name] = challenge
		}
	}
	return out, nil
}

// Import decrypts a profile backup and REPLACES the local installation.
// See ImportOptions for what gets brought across vs left alone.
//
// destKsFn is called after any config changes have been applied (so it
// observes the imported Keystore preference if IncludeSettings is true)
// to construct the destination keystore for the imported identities.
//
// DESTRUCTIVE. Callers are expected to confirm with the user before
// invoking. On failure mid-flight, the local state from before the call
// may be partially destroyed — the user should re-import or restart from
// a clean slate. The function tries to avoid half-installed identities
// but doesn't guarantee transactional rollback.
func Import(inputPath string, opts ImportOptions, destKsFn DestinationKeystoreFn) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading profile bundle: %w", err)
	}
	return ImportFromBytes(raw, opts, destKsFn)
}

// ImportFromBytes is Import but takes the encrypted bytes directly.
func ImportFromBytes(data []byte, opts ImportOptions, destKsFn DestinationKeystoreFn) (err error) {
	pass := opts.PassphraseBytes
	if len(pass) == 0 {
		pass = []byte(opts.Passphrase)
	}
	if len(pass) == 0 {
		return fmt.Errorf("import passphrase cannot be empty")
	}
	if destKsFn == nil {
		return fmt.Errorf("destKsFn callback is required")
	}

	plain, err := crypto.DecryptWithPassphraseBytes(data, pass)
	if err != nil {
		return fmt.Errorf("decrypting profile bundle (wrong passphrase?): %w", err)
	}

	// Slurp the whole tar into memory so we can pre-validate the manifest
	// before any destructive write. Tarballs are tiny relative to typical
	// process memory; this trades a few MB for safety.
	entries, err := readTarEntries(plain)
	if err != nil {
		return err
	}

	manifestBytes, ok := entries["manifest.json"]
	if !ok {
		return fmt.Errorf("manifest entry missing from bundle")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("parsing manifest: %w", err)
	}
	if manifest.Version != bundleVersion {
		return fmt.Errorf("unsupported bundle version %d (this build supports %d)", manifest.Version, bundleVersion)
	}

	// Everything above is non-destructive (pre-validation). Before the first
	// destructive write, snapshot the existing install so ANY failure in the
	// steps below rolls back to the user's previous profile. Without this, a
	// mid-import error (bad destKsFn, a HW ceremony that fails, a disk error on
	// identity N of M) leaves the keys already wiped and the profile
	// half-installed, with NO recovery — permanent key loss.
	backup, berr := snapshotInstall()
	if berr != nil {
		return fmt.Errorf("backing up the existing profile before import: %w", berr)
	}
	defer func() {
		if err != nil {
			if rerr := backup.restore(); rerr != nil {
				err = fmt.Errorf("%w; the previous profile could NOT be fully restored (%v) — your original data is preserved at %s", err, rerr, backup.root)
				return
			}
		}
		backup.discard()
	}()

	// Step 1: apply config first so destKsFn / KeysDir / etc. observe the
	// imported preferences during the rest of the import.
	if opts.IncludeSettings || opts.IncludePaths {
		if err := applyImportedConfig(entries["config.toml"], opts); err != nil {
			return err
		}
	}

	// Step 2: wipe local state. Best-effort — failures don't abort because
	// we're about to overwrite everything anyway, and a partial wipe is
	// recoverable by re-importing.
	wipeLocalState()

	// Step 3: install identities + meta from bundle.
	ks, backend, err := destKsFn()
	if err != nil {
		return fmt.Errorf("constructing destination keystore: %w", err)
	}

	idStore, err := identity.NewStore()
	if err != nil {
		return fmt.Errorf("creating identity store: %w", err)
	}

	var newIndex []identity.IdentityIndex
	for _, mi := range manifest.Identities {
		// The manifest name is attacker-controlled and becomes a filesystem
		// path component below (and via the keystore/meta stores) — validate
		// it before any Join so a hostile name can't escape the data dir.
		if err := validate.ValidateName(mi.Name); err != nil {
			return fmt.Errorf("invalid identity name in bundle: %w", err)
		}
		bundleBytes, ok := entries["identities-bundles/"+mi.Name+".icid"]
		if !ok {
			return fmt.Errorf("bundle for identity %q missing from archive", mi.Name)
		}

		var hwRestore identity.HWRestoreFn
		if opts.HWRestore != nil && mi.HWKey {
			hwRestore = opts.HWRestore(mi.Name)
		}

		info, err := identity.ImportBytes(bundleBytes, pass, ks, hwRestore)
		if err != nil {
			return fmt.Errorf("importing identity %q: %w", mi.Name, err)
		}

		// Per-identity meta file (verbatim copy).
		if metaBytes, ok := entries["identities/"+mi.Name+".meta"]; ok {
			metaDir, derr := config.IdentityMetaDir()
			if derr != nil {
				return fmt.Errorf("resolving identity meta dir: %w", derr)
			}
			if err := os.MkdirAll(metaDir, 0700); err != nil {
				return fmt.Errorf("creating identity meta dir: %w", err)
			}
			metaPath := filepath.Join(metaDir, mi.Name+".meta")
			if err := os.WriteFile(metaPath, metaBytes, 0600); err != nil {
				return fmt.Errorf("writing meta for %q: %w", mi.Name, err)
			}
		}

		info.Backend = backend
		// info.HWKey is already set correctly by identity.Import based on
		// whether hwRestore returned a HW-decorated keystore.
		newIndex = append(newIndex, identity.IdentityIndex{
			Name:        info.Name,
			Backend:     backend,
			HWKey:       info.HWKey,
			Fingerprint: info.Fingerprint,
		})
	}

	if err := idStore.SaveIndex(newIndex); err != nil {
		return fmt.Errorf("saving identity index: %w", err)
	}

	// Step 4: contacts (verbatim file overwrite).
	if contactsBytes, ok := entries["contacts.json"]; ok {
		contactsPath, cerr := config.ContactsFilePath()
		if cerr != nil {
			return fmt.Errorf("resolving contacts path: %w", cerr)
		}
		if err := os.MkdirAll(filepath.Dir(contactsPath), 0700); err != nil {
			return fmt.Errorf("creating data dir: %w", err)
		}
		if err := os.WriteFile(contactsPath, contactsBytes, 0600); err != nil {
			return fmt.Errorf("writing contacts.json: %w", err)
		}
	}

	// Step 5: if !IncludeSettings and local cfg.DefaultIdentity is empty,
	// seed it from the first imported identity.
	if !opts.IncludeSettings && len(newIndex) > 0 {
		cfg, lerr := config.Load()
		if lerr == nil && cfg.DefaultIdentity == "" {
			cfg.DefaultIdentity = newIndex[0].Name
			_ = cfg.Save()
		}
	}

	return nil
}

// installBackup is a rollback snapshot of the on-disk identity install, taken
// before ImportFromBytes's destructive phase so a failed import can restore the
// user's previous profile instead of leaving wiped keys and a half-install.
// It captures exactly what the import overwrites: the keys dir, the per-identity
// meta dir, identities.json, contacts.json, and config.toml.
type installBackup struct {
	root  string        // temp dir holding the archived copies
	items []backupEntry // one per install path, in restore order
}

// backupEntry records one live path and its archived copy. existed=false means
// the live path was absent at snapshot time, so restore removes it (undoing any
// file the partial import created).
type backupEntry struct {
	live    string // absolute live path, resolved BEFORE any config/path mutation
	stored  string // archived copy under root (unset when existed=false)
	isDir   bool
	existed bool
}

// snapshotInstall archives the current install into a fresh temp dir. Paths are
// resolved up front (before applyImportedConfig can change KeysDir/DataDir) so
// restore always targets the original locations.
func snapshotInstall() (*installBackup, error) {
	keysDir, err := config.KeysDir()
	if err != nil {
		return nil, fmt.Errorf("resolving keys dir: %w", err)
	}
	metaDir, err := config.IdentityMetaDir()
	if err != nil {
		return nil, fmt.Errorf("resolving identity meta dir: %w", err)
	}
	idxPath, err := config.IdentitiesFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving identities path: %w", err)
	}
	contactsPath, err := config.ContactsFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving contacts path: %w", err)
	}
	cfgPath, err := config.ConfigFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving config path: %w", err)
	}

	if err := os.MkdirAll(config.TempDir(), 0o700); err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	root, err := os.MkdirTemp(config.TempDir(), "icfx-import-rollback-")
	if err != nil {
		return nil, fmt.Errorf("creating rollback dir: %w", err)
	}

	b := &installBackup{root: root}
	specs := []struct {
		live  string
		isDir bool
		name  string
	}{
		{keysDir, true, "keys"},
		{metaDir, true, "meta"},
		{idxPath, false, "identities.json"},
		{contactsPath, false, "contacts.json"},
		{cfgPath, false, "config.toml"},
	}
	for _, s := range specs {
		entry := backupEntry{live: s.live, isDir: s.isDir}
		info, statErr := os.Stat(s.live)
		switch {
		case statErr == nil:
			entry.existed = true
			entry.stored = filepath.Join(root, s.name)
			if cErr := copyPath(s.live, entry.stored, s.isDir, info.Mode()); cErr != nil {
				b.discard()
				return nil, fmt.Errorf("archiving %s: %w", s.live, cErr)
			}
		case !os.IsNotExist(statErr):
			b.discard()
			return nil, fmt.Errorf("inspecting %s: %w", s.live, statErr)
		}
		b.items = append(b.items, entry)
	}
	return b, nil
}

// restore reverts the install to the snapshot: directories are cleared and
// repopulated, files are rewritten or (if absent at snapshot time) removed, so
// any partial state the failed import wrote is undone. Best-effort across all
// items; the collected errors are returned together so the caller can tell the
// user the archive was kept.
func (b *installBackup) restore() error {
	var errs []string
	for _, e := range b.items {
		if err := e.restore(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// restore reverts a single install path to its snapshot state.
func (e backupEntry) restore() error {
	if e.isDir {
		if err := os.RemoveAll(e.live); err != nil {
			return fmt.Errorf("clearing %s: %w", e.live, err)
		}
		if !e.existed {
			return nil
		}
		if err := copyTree(e.stored, e.live); err != nil {
			return fmt.Errorf("restoring %s: %w", e.live, err)
		}
		return nil
	}
	if e.existed {
		if err := copyFile(e.stored, e.live, 0o600); err != nil {
			return fmt.Errorf("restoring %s: %w", e.live, err)
		}
		return nil
	}
	if err := os.Remove(e.live); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", e.live, err)
	}
	return nil
}

// discard deletes the archive. Called on success, or after a successful restore.
func (b *installBackup) discard() {
	if b == nil || b.root == "" {
		return
	}
	_ = os.RemoveAll(b.root)
}

// copyPath copies a file or directory tree from src to dst.
func copyPath(src, dst string, isDir bool, mode os.FileMode) error {
	if isDir {
		return copyTree(src, dst)
	}
	return copyFile(src, dst, mode)
}

// copyFile copies src to dst (creating dst's parent), preserving the given mode.
func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o600
	}
	return os.WriteFile(dst, data, mode)
}

// copyTree recursively copies the directory src to dst.
func copyTree(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyTree(s, d); err != nil {
				return err
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if err := copyFile(s, d, info.Mode()); err != nil {
			return err
		}
	}
	return nil
}

// applyImportedConfig overlays the user-selected fields from the bundled
// config.toml onto the local config and saves it. Called before the wipe
// + install so subsequent steps observe the imported Keystore preference
// / paths.
func applyImportedConfig(configBytes []byte, opts ImportOptions) error {
	if len(configBytes) == 0 {
		return nil
	}

	// Write the imported config to a tmp file so we can use the existing
	// config.Load-style decoder via the file path that's already part of
	// the icfx config API.
	tmp, err := os.CreateTemp(config.TempDir(), "icfx-import-config-*.toml")
	if err != nil {
		return fmt.Errorf("creating temp config file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(configBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp config file: %w", err)
	}
	tmp.Close()

	imported, err := config.LoadFrom(tmpPath)
	if err != nil {
		return fmt.Errorf("parsing imported config: %w", err)
	}

	local, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading local config: %w", err)
	}

	if opts.IncludeSettings {
		local.DefaultIdentity = imported.DefaultIdentity
		local.DefaultFormat = imported.DefaultFormat
		local.Keystore = imported.Keystore
		local.Verbose = imported.Verbose
		local.Banner = imported.Banner
		local.AutoLockMinutes = imported.AutoLockMinutes
	}
	if opts.IncludePaths {
		local.ConfPath = imported.ConfPath
		local.DataPath = imported.DataPath
		local.KeyPath = imported.KeyPath
		// Re-apply the path overrides so the rest of this Import operation
		// uses the new paths.
		if local.DataPath != "" {
			config.SetDataPath(config.ExpandPath(local.DataPath))
		}
		if local.KeyPath != "" {
			config.SetKeyPath(config.ExpandPath(local.KeyPath))
		}
	}

	if err := local.Save(); err != nil {
		return fmt.Errorf("saving updated config: %w", err)
	}
	return nil
}

// wipeLocalState removes every identity keystore entry, meta file,
// hwchallenge file, identities.json, and contacts.json. Best-effort —
// errors are ignored because the caller is about to replace everything,
// and a partial wipe is fully recoverable by re-importing.
func wipeLocalState() {
	keysDir, _ := config.KeysDir()

	// Clear keystore entries for each known identity.
	if idStore, err := identity.NewStore(); err == nil {
		if entries, err := idStore.LoadIndex(); err == nil {
			for _, e := range entries {
				ks := wipeKeystoreFor(e.Backend, keysDir)
				if ks != nil {
					_ = ks.Clear(e.Name)
				}
			}
		}
	}

	// Delete leftover *.hwchallenge files in keysDir (would otherwise
	// confuse a subsequent re-import).
	if keysDir != "" {
		if entries, err := os.ReadDir(keysDir); err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".hwchallenge") {
					continue
				}
				_ = os.Remove(filepath.Join(keysDir, e.Name()))
			}
		}
	}

	// Delete *.meta files.
	if metaDir, err := config.IdentityMetaDir(); err == nil {
		if entries, err := os.ReadDir(metaDir); err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".meta") {
					continue
				}
				_ = os.Remove(filepath.Join(metaDir, e.Name()))
			}
		}
	}

	// Identities index + contacts.
	if p, err := config.IdentitiesFilePath(); err == nil {
		_ = os.Remove(p)
	}
	if p, err := config.ContactsFilePath(); err == nil {
		_ = os.Remove(p)
	}
}

// wipeKeystoreFor returns a non-decorated keystore suitable for calling
// Clear() against. Doesn't need encryption / passphrase — Clear is a
// deletion primitive.
//
// Returns nil if no usable keystore exists for the backend (e.g. backend
// says keychain but no keychain is available on this platform — the
// keychain entries either don't exist or can't be reached, so there's
// nothing to clear). Android keyring isn't handled here; mobile profile
// import is out of MVP scope.
func wipeKeystoreFor(backend, keysDir string) keystore.Keystore {
	if backend == identity.BackendKeychain && keystore.KeychainAvailable() {
		return keystore.NewKeychainStore()
	}
	if keysDir == "" {
		return nil
	}
	return keystore.NewFileStoreWithDir(keysDir)
}

// readTarEntries reads a full gzipped tar into a name→bytes map. Used by
// Import so we can validate the manifest before any destructive write.
func readTarEntries(gzipped []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return nil, fmt.Errorf("decompressing bundle: %w", err)
	}
	defer gr.Close()

	out := make(map[string][]byte)
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading bundle entry: %w", err)
		}
		// Path-traversal guard. The export side only writes flat / one-deep
		// names, so anything with ".." or absolute paths is malicious.
		clean := filepath.Clean(hdr.Name)
		if strings.Contains(clean, "..") || filepath.IsAbs(clean) {
			return nil, fmt.Errorf("invalid bundle entry path: %s", hdr.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading bundle entry %s: %w", hdr.Name, err)
		}
		out[hdr.Name] = body
	}
	return out, nil
}
