//go:build !darwin

package keystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/zalando/go-keyring"
)

// maxKeychainChunk bounds the size of a single keychain value. Windows Credential
// Manager rejects a blob over 2560 bytes (CRED_MAX_CREDENTIAL_BLOB_SIZE), but a
// base64 ML-DSA-65 signing key is ~5376 bytes — so on Windows it must be split.
// base64 is ASCII (1 byte/char), so 2048 stays well under the cap → 3 chunks.
const maxKeychainChunk = 2048

// chunkMarkerPrefix tags the main "-sign" entry as a chunk manifest ("icfx-chunks:N")
// instead of the key itself. A base64 string never contains '-' or ':', so a marker
// is unambiguously distinguishable from a whole (unchunked) key.
const chunkMarkerPrefix = "icfx-chunks:"

// KeychainStore stores keys in the OS keychain via go-keyring, which is pure Go
// (no cgo) and self-dispatches per platform: D-Bus Secret Service on Linux and
// the BSDs (OpenBSD/NetBSD unconditionally; FreeBSD/DragonFly when cgo is on),
// the Credential Manager (wincred) on Windows, and a graceful
// ErrUnsupportedPlatform fallback everywhere else. On platforms with no live
// backend, KeychainAvailable() returns false and callers fall back to the
// encrypted file store — so this one file safely covers every non-macOS target.
// macOS uses the native Security.framework via keychain_darwin.go instead.
type KeychainStore struct{}

// NewKeychainStore creates a new KeychainStore.
func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

// KeychainAvailable probes whether the OS keychain backend is functional.
func KeychainAvailable() bool {
	if err := keyring.Set(keychainService, probeKey, "1"); err != nil {
		return false
	}
	_ = keyring.Delete(keychainService, probeKey)
	return true
}

func (k *KeychainStore) StoreEncryptionIdentity(name string, identity string) error {
	if err := keyring.Set(keychainService, name+encKeySuffix, identity); err != nil {
		return fmt.Errorf("storing encryption identity: %w", err)
	}
	return k.addToIndex(name)
}

func (k *KeychainStore) LoadEncryptionIdentity(name string) (string, error) {
	val, err := keyring.Get(keychainService, name+encKeySuffix)
	if err != nil {
		return "", fmt.Errorf("loading encryption identity: %w", err)
	}
	return val, nil
}

func (k *KeychainStore) StoreSigningKey(name string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	// Only Windows' Credential Manager has the small per-blob cap; every other
	// non-darwin backend (Secret Service) stores the key whole, exactly as before.
	if runtime.GOOS == "windows" && len(encoded) > maxKeychainChunk {
		return k.storeSigningKeyChunked(name, encoded)
	}
	if err := keyring.Set(keychainService, name+signKeySuffix, encoded); err != nil {
		return fmt.Errorf("storing signing key: %w", err)
	}
	return k.addToIndex(name)
}

// storeSigningKeyChunked splits an oversized base64 key across N "-sign.i" entries
// and writes a "chunked:N" marker to the main "-sign" entry. Chunks are written
// BEFORE the marker so an interrupted store can't leave a marker pointing at
// missing chunks. (The ML-DSA key size is fixed, so a re-store yields the same N
// and never orphans a chunk.)
func (k *KeychainStore) storeSigningKeyChunked(name, encoded string) error {
	base := name + signKeySuffix
	chunks := chunkString(encoded, maxKeychainChunk)
	for i, c := range chunks {
		if err := keyring.Set(keychainService, fmt.Sprintf("%s.%d", base, i), c); err != nil {
			return fmt.Errorf("storing signing key chunk %d: %w", i, err)
		}
	}
	if err := keyring.Set(keychainService, base, chunkMarker(len(chunks))); err != nil {
		return fmt.Errorf("storing signing key: %w", err)
	}
	return k.addToIndex(name)
}

func (k *KeychainStore) LoadSigningKey(name string) ([]byte, error) {
	base := name + signKeySuffix
	encoded, err := keyring.Get(keychainService, base)
	if err != nil {
		return nil, fmt.Errorf("loading signing key: %w", err)
	}
	// A chunked key (Windows) stores a "chunked:N" marker here; reassemble the N
	// pieces. Otherwise `encoded` is the whole key (Linux/BSD, or pre-chunking).
	if n, ok := parseChunkMarker(encoded); ok {
		var b strings.Builder
		for i := 0; i < n; i++ {
			c, cerr := keyring.Get(keychainService, fmt.Sprintf("%s.%d", base, i))
			if cerr != nil {
				return nil, fmt.Errorf("loading signing key chunk %d: %w", i, cerr)
			}
			b.WriteString(c)
		}
		encoded = b.String()
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func (k *KeychainStore) HasKeys(name string) bool {
	_, err1 := keyring.Get(keychainService, name+encKeySuffix)
	_, err2 := keyring.Get(keychainService, name+signKeySuffix)
	return err1 == nil && err2 == nil
}

func (k *KeychainStore) Clear(name string) error {
	// Delete is idempotent: missing entries are not an error condition.
	base := name + signKeySuffix
	// If the signing key was chunked (Windows), delete its chunk entries too
	// (best-effort — a missing chunk is not an error).
	if val, err := keyring.Get(keychainService, base); err == nil {
		if n, ok := parseChunkMarker(val); ok {
			for i := 0; i < n; i++ {
				_ = keyring.Delete(keychainService, fmt.Sprintf("%s.%d", base, i))
			}
		}
	}
	if err := keyring.Delete(keychainService, name+encKeySuffix); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("deleting encryption identity: %w", err)
	}
	if err := keyring.Delete(keychainService, base); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("deleting signing key: %w", err)
	}
	return k.removeFromIndex(name)
}

func (k *KeychainStore) ListNames() ([]string, error) {
	data, err := keyring.Get(keychainService, indexKey)
	if err != nil {
		// Missing index = empty keystore (fresh install). Any other error
		// means the keychain itself is broken — surface it.
		if errors.Is(err, keyring.ErrNotFound) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("reading keystore index: %w", err)
	}
	var names []string
	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return nil, fmt.Errorf("parsing keystore index (corrupted?): %w", err)
	}
	return names, nil
}

func (k *KeychainStore) addToIndex(name string) error {
	keychainIndexMu.Lock()
	defer keychainIndexMu.Unlock()
	names, err := k.ListNames()
	if err != nil {
		return fmt.Errorf("reading index: %w", err)
	}
	for _, n := range names {
		if n == name {
			return nil
		}
	}
	names = append(names, name)
	data, err := json.Marshal(names)
	if err != nil {
		return fmt.Errorf("marshaling index: %w", err)
	}
	if err := keyring.Set(keychainService, indexKey, string(data)); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	return nil
}

func (k *KeychainStore) removeFromIndex(name string) error {
	keychainIndexMu.Lock()
	defer keychainIndexMu.Unlock()
	names, err := k.ListNames()
	if err != nil {
		return fmt.Errorf("reading index: %w", err)
	}
	filtered := make([]string, 0, len(names))
	for _, n := range names {
		if n == name {
			continue
		}
		filtered = append(filtered, n)
	}
	data, err := json.Marshal(filtered)
	if err != nil {
		return fmt.Errorf("marshaling index: %w", err)
	}
	if err := keyring.Set(keychainService, indexKey, string(data)); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	return nil
}

// chunkString splits s into consecutive pieces of at most size bytes. Rejoining
// the returned pieces in order reproduces s exactly; a size <= 0 returns s whole.
func chunkString(s string, size int) []string {
	if size <= 0 {
		return []string{s}
	}
	var chunks []string
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	return append(chunks, s)
}

// chunkMarker renders the manifest value stored in the main "-sign" entry.
func chunkMarker(n int) string {
	return chunkMarkerPrefix + strconv.Itoa(n)
}

// parseChunkMarker reports whether v is a chunk manifest and, if so, its count.
func parseChunkMarker(v string) (int, bool) {
	if !strings.HasPrefix(v, chunkMarkerPrefix) {
		return 0, false
	}
	n, err := strconv.Atoi(v[len(chunkMarkerPrefix):])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
