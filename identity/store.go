package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
)

// Store manages identity persistence as two layers:
//
//  1. Plaintext index file at <dataDir>/identities.json — one entry per
//     identity, holding only what's structurally needed to enumerate
//     identities and locate their private keys (Name, Backend, HWKey).
//     This file is the only metadata that's readable without unlocking
//     any identity, and it intentionally contains no PII.
//
//  2. Per-identity encrypted meta files at <dataDir>/identities/<name>.meta —
//     one file per identity, age-encrypted to that identity's own EncPubKey.
//     Holds the rich metadata (ID, email, nicknames, names, public keys,
//     primary flag, status, timestamps). Decryption requires unlocking
//     the identity (see LoadMeta).
//
// This split eliminates the older design's fragility (whole-file encryption
// keyed to one identity's pubkey, which broke whenever identities were
// added/removed across keystore backends) AND keeps PII off-disk-in-cleartext.
type Store struct {
	path    string // identities.json
	metaDir string // identities/
}

// IdentityIndex is one entry in the plaintext identities.json index. Holds
// only the fields needed to (a) enumerate identities and (b) load each
// one's private keys from the right backend.
type IdentityIndex struct {
	Name    string `json:"name"`
	Backend string `json:"backend"` // "keychain" or "file"
	HWKey   bool   `json:"hw_key,omitempty"`
	// HWKEK records which passphrase convention the hardware-key KEK was
	// derived with (HKDF IKM): HWKEKNone (keychain-origin, empty passphrase)
	// or HWKEKPassphrase (file-origin, session passphrase). Empty = legacy:
	// infer from Backend. Set explicitly by roaming imports, where the
	// storage backend may differ from the ciphertext's origin convention —
	// the convention must follow the ciphertext, not the storage location.
	HWKEK string `json:"hw_kek,omitempty"`
	// Fingerprint is the identity's public fingerprint (derived from public
	// keys — not secret). Cached in the plaintext index so the cloud-sync layer
	// can detect a default-identity key-swap without unlocking. Empty on legacy
	// entries; the anti-takeover gate skips until it's repopulated on
	// create/rotate/import.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Alias is the identity's short, single-word public handle. Cached in the
	// plaintext index (like Fingerprint) so it is readable without unlocking:
	// it drives backup filenames, doubles as an alternate selector
	// (FindIndexByNameOrAlias), and — fast-follow — will be published to the
	// cloud directory. Locally unique (CheckAliasUnique). Empty on legacy
	// entries; filename/selection code falls back to Name.
	Alias string `json:"alias,omitempty"`
}

// HWKEK conventions — see IdentityIndex.HWKEK.
const (
	HWKEKNone       = "none"
	HWKEKPassphrase = "passphrase"
)

// HWKEKConvention resolves the identity's effective KEK convention,
// applying the legacy backend-based inference when HWKEK is unset.
func (i IdentityIndex) HWKEKConvention() string {
	if i.HWKEK != "" {
		return i.HWKEK
	}
	if i.Backend == BackendKeychain {
		return HWKEKNone
	}
	return HWKEKPassphrase
}

// indexFile is the on-disk wrapper for the identities.json index.
type indexFile struct {
	Version    int             `json:"version"`
	Identities []IdentityIndex `json:"identities"`
}

// metaWrapper is what's age-encrypted into each .meta file. The Identity
// struct's Backend / HWKey fields are intentionally redundant with the
// index entry but kept here for completeness — the LoadMeta method overlays
// the authoritative index values on the decrypted result.
type metaWrapper struct {
	Version  int      `json:"version"`
	Identity Identity `json:"identity"`
}

// NewStore creates a new identity store using the default paths.
func NewStore() (*Store, error) {
	path, err := config.IdentitiesFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving identities file path: %w", err)
	}
	metaDir, err := config.IdentityMetaDir()
	if err != nil {
		return nil, fmt.Errorf("resolving identity meta dir: %w", err)
	}
	return &Store{path: path, metaDir: metaDir}, nil
}

// LoadIndex reads the plaintext index. Returns an empty slice if the index
// file doesn't exist (fresh install).
func (s *Store) LoadIndex() ([]IdentityIndex, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return []IdentityIndex{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading identities index: %w", err)
	}
	var data indexFile
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parsing identities index: %w", err)
	}
	return data.Identities, nil
}

// SaveIndex writes the plaintext index, mode 0600.
func (s *Store) SaveIndex(entries []IdentityIndex) error {
	data := indexFile{Version: 3, Identities: entries}
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling identities index: %w", err)
	}
	return config.WriteFileAtomic(s.path, jsonBytes)
}

// SaveMeta age-encrypts the rich metadata for one identity to its own
// EncPubKey and writes it to <dataDir>/identities/<name>.meta. The Backend
// and HWKey fields on the passed Identity are preserved for completeness
// but the authoritative copy lives in the index.
func (s *Store) SaveMeta(id Identity) error {
	wrapper := metaWrapper{Version: 3, Identity: id}
	jsonBytes, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling identity meta: %w", err)
	}
	encrypted, err := crypto.Encrypt(jsonBytes, []string{id.EncPubKey})
	if err != nil {
		return fmt.Errorf("encrypting identity meta: %w", err)
	}
	return config.WriteFileAtomic(filepath.Join(s.metaDir, id.Name+".meta"), encrypted)
}

// LoadMeta reads and age-decrypts the rich metadata for one identity. The
// encIdentity argument is the identity's own age secret key (typically
// obtained via *Unlocked.openEncForMeta(); see icfx/identity package).
//
// The returned Identity's Backend and HWKey fields are overlaid from the
// authoritative index entry to guard against drift between the two files.
func (s *Store) LoadMeta(name string, encIdentity string, idx IdentityIndex) (Identity, error) {
	path := filepath.Join(s.metaDir, name+".meta")
	raw, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, fmt.Errorf("reading identity meta %s: %w", name, err)
	}
	plaintext, err := crypto.Decrypt(raw, encIdentity)
	if err != nil {
		return Identity{}, fmt.Errorf("decrypting identity meta %s: %w", name, err)
	}
	var wrapper metaWrapper
	if err := json.Unmarshal(plaintext, &wrapper); err != nil {
		return Identity{}, fmt.Errorf("parsing identity meta %s: %w", name, err)
	}
	id := wrapper.Identity
	id.Name = idx.Name
	id.Backend = idx.Backend
	id.HWKey = idx.HWKey
	id.Alias = idx.Alias // index is authoritative for the (plaintext) alias
	return id, nil
}

// FindIndexByNameOrAlias resolves an index entry by an exact name match first,
// then by a case-insensitive alias match. It is the single source of truth for
// selecting a local identity by reference without unlocking — both clients
// route their name-taking selection commands through it so an alias works
// anywhere a name does. Returns ErrNotFound when nothing matches.
func FindIndexByNameOrAlias(entries []IdentityIndex, ref string) (*IdentityIndex, error) {
	for i := range entries {
		if entries[i].Name == ref {
			return &entries[i], nil
		}
	}
	for i := range entries {
		if ref != "" && strings.EqualFold(entries[i].Alias, ref) {
			return &entries[i], nil
		}
	}
	return nil, ErrNotFound
}

// ResolveDefaultIndex returns the index entry for the profile's default
// identity: the entry named defaultName when present, else the first entry, else
// nil for an empty index. Pass config.DefaultIdentity as defaultName. Single
// source of truth for "which identity is the default" over the plaintext index.
func ResolveDefaultIndex(entries []IdentityIndex, defaultName string) *IdentityIndex {
	if defaultName != "" {
		for i := range entries {
			if entries[i].Name == defaultName {
				return &entries[i]
			}
		}
	}
	if len(entries) > 0 {
		return &entries[0]
	}
	return nil
}

// CheckAliasUnique enforces per-profile alias uniqueness AND that an alias never
// collides with a DIFFERENT identity's Name. The Name collision matters because
// selection (FindIndexByNameOrAlias) resolves Name before Alias, so an alias
// equal to another identity's name would be silently unreachable and could
// mis-route a name-typed destructive command — a confused-deputy footgun.
// Comparison is case-insensitive (aliases are lowercased, but Names are not).
// Returns ErrAliasTaken on collision. Pass selfName == "" on create; on edit
// pass the identity's own name so keeping its existing alias is allowed. An
// empty alias is always fine (aliases are optional).
func CheckAliasUnique(entries []IdentityIndex, alias, selfName string) error {
	if alias == "" {
		return nil
	}
	for i := range entries {
		if entries[i].Name == selfName {
			continue
		}
		if strings.EqualFold(entries[i].Alias, alias) || strings.EqualFold(entries[i].Name, alias) {
			return ErrAliasTaken
		}
	}
	return nil
}

// CheckNameAvailable reports whether a NEW identity name is free of collisions
// with any existing identity's Name (exact) or Alias (case-insensitive) — the
// mirror of CheckAliasUnique for the name-creation direction, so a new name
// can't shadow an existing alias. Returns ErrAliasTaken on collision.
func CheckNameAvailable(entries []IdentityIndex, name string) error {
	for i := range entries {
		if entries[i].Name == name || strings.EqualFold(entries[i].Alias, name) {
			return ErrAliasTaken
		}
	}
	return nil
}

// RemoveMeta deletes the per-identity meta file. Idempotent.
func (s *Store) RemoveMeta(name string) error {
	path := filepath.Join(s.metaDir, name+".meta")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing identity meta %s: %w", name, err)
	}
	return nil
}
