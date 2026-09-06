package profile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
)

// ErrUnsupportedRoamingVersion is returned by ImportIdentitiesFromBytes when the
// bundle's format version isn't recognized (e.g. an old v1 blob after upgrading
// to the at-rest transport). Callers can treat it like "nothing to pull" and let
// the next push replace the stale blob.
var ErrUnsupportedRoamingVersion = errors.New("unsupported identities bundle version")

// roamingBundleVersion is the identity-roaming bundle format. v2 ships each
// identity's *encrypted-at-rest* form (ciphertext for file/HW, raw for plain
// keychain) tagged by protection, instead of v1's decrypt-then-re-encrypt. The
// tarball is still wrapped under the outer cloud key (server opacity + the only
// protection for `cloud`-tagged entries); file/HW entries stay independently
// protected inside, so the cloud password never yields a usable file/HW key.
const roamingBundleVersion = 2

// RoamingDigest returns a deterministic fingerprint of the local identity set
// as it would roam: every identity's at-rest transport form plus its meta
// file, hashed in name order. It reads files only — no KDF, no prompts — so
// sync engines can call it every pass to detect "did anything change locally"
// without the cost of building (or uploading) a bundle. Two devices with the
// same identities produce the same digest.
func RoamingDigest(exportFn IdentityExportFn) (string, error) {
	if exportFn == nil {
		return "", fmt.Errorf("exportFn callback is required")
	}
	idStore, err := identity.NewStore()
	if err != nil {
		return "", fmt.Errorf("creating identity store: %w", err)
	}
	entries, err := idStore.LoadIndex()
	if err != nil {
		return "", fmt.Errorf("loading identity index: %w", err)
	}
	metaDir, err := config.IdentityMetaDir()
	if err != nil {
		return "", fmt.Errorf("resolving identity meta dir: %w", err)
	}

	sorted := make([]identity.IdentityIndex, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	h := sha256.New()
	writeField := func(field []byte) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(field)))
		h.Write(lenBuf[:])
		h.Write(field)
	}
	for _, e := range sorted {
		re, err := exportFn(e)
		if err != nil {
			return "", fmt.Errorf("exporting identity %q: %w", e.Name, err)
		}
		writeField([]byte(e.Name))
		writeField([]byte(re.Protection))
		writeField(re.Enc)
		writeField(re.Sign)
		writeField(re.Challenge)
		meta, err := os.ReadFile(filepath.Join(metaDir, e.Name+".meta"))
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("reading meta for %q: %w", e.Name, err)
		}
		writeField(meta)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ExportIdentitiesToBytes packs every local identity's at-rest transport form
// (via exportFn) into a bundle wrapped under outerKey. It does NOT decrypt
// file/HW keys — export is prompt-free; the secret is needed only to *use* a key.
func ExportIdentitiesToBytes(outerKey []byte, exportFn IdentityExportFn) ([]byte, error) {
	if len(outerKey) == 0 {
		return nil, fmt.Errorf("outer key cannot be empty")
	}
	defer crypto.Zero(outerKey)
	if exportFn == nil {
		return nil, fmt.Errorf("exportFn callback is required")
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

	manifest := Manifest{Version: roamingBundleVersion, ExportedAt: time.Now().UTC()}
	// Carry this device's account default so other devices can converge on a
	// hand-off/rotation successor (adopted behind the ConfirmDefaultChange gate).
	if cfg, cerr := config.Load(); cerr == nil {
		manifest.DefaultIdentity = cfg.DefaultIdentity
	}

	for _, e := range entries {
		re, err := exportFn(e)
		if err != nil {
			return nil, fmt.Errorf("exporting identity %q: %w", e.Name, err)
		}
		base := "identities/" + e.Name + "/"
		if err := tarWriteBytes(tw, base+"enc", re.Enc); err != nil {
			return nil, fmt.Errorf("writing enc for %q: %w", e.Name, err)
		}
		if err := tarWriteBytes(tw, base+"sign", re.Sign); err != nil {
			return nil, fmt.Errorf("writing sign for %q: %w", e.Name, err)
		}
		if len(re.Challenge) > 0 {
			if err := tarWriteBytes(tw, base+"challenge", re.Challenge); err != nil {
				return nil, fmt.Errorf("writing challenge for %q: %w", e.Name, err)
			}
		}
		// Meta is a plain on-disk file, encrypted to the identity's own key —
		// portable and backend-agnostic, so the profile package moves it directly.
		metaPath := filepath.Join(metaDir, e.Name+".meta")
		if err := tarWriteFile(tw, metaPath, base+"meta"); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("writing meta for %q: %w", e.Name, err)
		}
		manifest.Identities = append(manifest.Identities, ManifestIdentity{
			Name:        e.Name,
			HWKey:       re.Protection == ProtectionHW,
			Protection:  re.Protection,
			HWKEK:       re.HWKEK,
			Fingerprint: e.Fingerprint,
		})
	}

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
	return crypto.EncryptWithPassphraseBytes(buf.Bytes(), outerKey)
}

// ImportIdentitiesFromBytes unwraps the bundle with outerKey and MERGES each
// identity into the local keystore + index (upsert by name) via importFn, which
// stores the key material per the destination backend and reports where it
// landed. Non-destructive: does not wipe local state or touch contacts/settings.
// PeekRoamingManifest decrypts an identities roaming blob and returns its
// manifest (the default pointer + per-identity fingerprints) with NO key import,
// so the sync layer can detect a default-identity pointer change OR key-swap
// before the roam applies it. A wrong-default device can still read this (the
// blob is encKey-wrapped, not self-locked), which is what makes cross-device
// convergence work.
func PeekRoamingManifest(data []byte, outerKey []byte) (Manifest, error) {
	if len(outerKey) == 0 {
		return Manifest{}, fmt.Errorf("outer key cannot be empty")
	}
	defer crypto.Zero(outerKey)
	plain, err := crypto.DecryptWithPassphraseBytes(data, outerKey)
	if err != nil {
		return Manifest{}, fmt.Errorf("decrypting identities bundle (wrong cloud password?): %w", err)
	}
	entries, err := readTarEntries(plain)
	if err != nil {
		return Manifest{}, err
	}
	manifestBytes, ok := entries["manifest.json"]
	if !ok {
		return Manifest{}, fmt.Errorf("manifest entry missing from bundle")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parsing manifest: %w", err)
	}
	return manifest, nil
}

func ImportIdentitiesFromBytes(data []byte, outerKey []byte, importFn IdentityImportFn) error {
	if len(outerKey) == 0 {
		return fmt.Errorf("outer key cannot be empty")
	}
	if importFn == nil {
		return fmt.Errorf("importFn callback is required")
	}
	defer crypto.Zero(outerKey)

	plain, err := crypto.DecryptWithPassphraseBytes(data, outerKey)
	if err != nil {
		return fmt.Errorf("decrypting identities bundle (wrong cloud password?): %w", err)
	}
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
	if manifest.Version != roamingBundleVersion {
		return fmt.Errorf("%w %d (this build supports %d)", ErrUnsupportedRoamingVersion, manifest.Version, roamingBundleVersion)
	}

	idStore, err := identity.NewStore()
	if err != nil {
		return fmt.Errorf("creating identity store: %w", err)
	}
	index, err := idStore.LoadIndex()
	if err != nil {
		return fmt.Errorf("loading identity index: %w", err)
	}
	byName := make(map[string]int, len(index))
	for i, e := range index {
		byName[e.Name] = i
	}
	metaDir, err := config.IdentityMetaDir()
	if err != nil {
		return fmt.Errorf("resolving identity meta dir: %w", err)
	}

	for _, mi := range manifest.Identities {
		base := "identities/" + mi.Name + "/"
		enc, ok := entries[base+"enc"]
		if !ok {
			return fmt.Errorf("enc key for identity %q missing from archive", mi.Name)
		}
		sign, ok := entries[base+"sign"]
		if !ok {
			return fmt.Errorf("sign key for identity %q missing from archive", mi.Name)
		}
		re := RoamingEntry{
			Protection: mi.Protection,
			Enc:        enc,
			Sign:       sign,
			Challenge:  entries[base+"challenge"], // present only for hw
			HWKEK:      mi.HWKEK,
		}
		backend, err := importFn(mi.Name, re)
		if err != nil {
			return fmt.Errorf("importing identity %q: %w", mi.Name, err)
		}
		if metaBytes, ok := entries[base+"meta"]; ok {
			if err := os.MkdirAll(metaDir, 0700); err != nil {
				return fmt.Errorf("creating identity meta dir: %w", err)
			}
			if err := os.WriteFile(filepath.Join(metaDir, mi.Name+".meta"), metaBytes, 0600); err != nil {
				return fmt.Errorf("writing meta for %q: %w", mi.Name, err)
			}
		}
		// The KEK convention travels verbatim: backend is where THIS device
		// stores the bytes; HWKEK is how the origin encrypted them. Empty on
		// pre-HWKEK bundles — HWKEKConvention() then infers from Backend
		// (today's behavior).
		idx := identity.IdentityIndex{Name: mi.Name, Backend: backend, HWKey: mi.HWKey, HWKEK: mi.HWKEK, Fingerprint: mi.Fingerprint}
		if i, ok := byName[mi.Name]; ok {
			index[i] = idx
			continue
		}
		index = append(index, idx)
		byName[mi.Name] = len(index) - 1
	}

	if err := idStore.SaveIndex(index); err != nil {
		return fmt.Errorf("saving identity index: %w", err)
	}
	return nil
}
