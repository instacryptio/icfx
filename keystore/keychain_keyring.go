//go:build !darwin

package keystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

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
	if err := keyring.Set(keychainService, name+signKeySuffix, encoded); err != nil {
		return fmt.Errorf("storing signing key: %w", err)
	}
	return k.addToIndex(name)
}

func (k *KeychainStore) LoadSigningKey(name string) ([]byte, error) {
	encoded, err := keyring.Get(keychainService, name+signKeySuffix)
	if err != nil {
		return nil, fmt.Errorf("loading signing key: %w", err)
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
	if err := keyring.Delete(keychainService, name+encKeySuffix); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("deleting encryption identity: %w", err)
	}
	if err := keyring.Delete(keychainService, name+signKeySuffix); err != nil && !errors.Is(err, keyring.ErrNotFound) {
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
