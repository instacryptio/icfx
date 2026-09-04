//go:build darwin

package keystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/keybase/go-keychain"
)

// errKeychainItemNotFound signals that a queried keychain item does not exist.
// Distinct from real keychain errors so ListNames/Clear can stay idempotent
// for missing entries while surfacing genuine failures.
var errKeychainItemNotFound = errors.New("keychain item not found")

// KeychainStore stores keys in the macOS/iOS Keychain via the Security framework.
type KeychainStore struct{}

// NewKeychainStore creates a new KeychainStore.
func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

// KeychainAvailable probes whether the OS keychain is functional.
func KeychainAvailable() bool {
	item := keychain.NewGenericPassword(keychainService, probeKey, keychainService, []byte("1"), "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)

	// Try to add — if it already exists, that's fine too
	err := keychain.AddItem(item)
	if err != nil && err != keychain.ErrorDuplicateItem {
		return false
	}
	_ = deleteItem(probeKey)
	return true
}

func (k *KeychainStore) StoreEncryptionIdentity(name string, identity string) error {
	if err := setItem(name+encKeySuffix, []byte(identity)); err != nil {
		return fmt.Errorf("storing encryption identity: %w", err)
	}
	return k.addToIndex(name)
}

func (k *KeychainStore) LoadEncryptionIdentity(name string) (string, error) {
	data, err := getItem(name + encKeySuffix)
	if err != nil {
		return "", fmt.Errorf("loading encryption identity: %w", err)
	}
	return string(data), nil
}

func (k *KeychainStore) StoreSigningKey(name string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := setItem(name+signKeySuffix, []byte(encoded)); err != nil {
		return fmt.Errorf("storing signing key: %w", err)
	}
	return k.addToIndex(name)
}

func (k *KeychainStore) LoadSigningKey(name string) ([]byte, error) {
	data, err := getItem(name + signKeySuffix)
	if err != nil {
		return nil, fmt.Errorf("loading signing key: %w", err)
	}
	return base64.StdEncoding.DecodeString(string(data))
}

func (k *KeychainStore) HasKeys(name string) bool {
	_, err1 := getItem(name + encKeySuffix)
	_, err2 := getItem(name + signKeySuffix)
	return err1 == nil && err2 == nil
}

func (k *KeychainStore) Clear(name string) error {
	// Delete is idempotent: missing items are not errors.
	if err := deleteItem(name + encKeySuffix); err != nil && !errors.Is(err, keychain.ErrorItemNotFound) {
		return fmt.Errorf("deleting encryption identity: %w", err)
	}
	if err := deleteItem(name + signKeySuffix); err != nil && !errors.Is(err, keychain.ErrorItemNotFound) {
		return fmt.Errorf("deleting signing key: %w", err)
	}
	return k.removeFromIndex(name)
}

func (k *KeychainStore) ListNames() ([]string, error) {
	data, err := getItem(indexKey)
	if err != nil {
		// Missing index = empty keystore (fresh install). Surface other errors.
		if errors.Is(err, errKeychainItemNotFound) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("reading keystore index: %w", err)
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
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
	if err := setItem(indexKey, data); err != nil {
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
	if err := setItem(indexKey, data); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	return nil
}

// setItem stores data in the keychain. Updates existing items.
func setItem(account string, data []byte) error {
	// Try to delete first to avoid DuplicateItem errors
	_ = deleteItem(account)

	item := keychain.NewGenericPassword(keychainService, account, keychainService, data, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	return keychain.AddItem(item)
}

// getItem retrieves data from the keychain. Returns errKeychainItemNotFound
// (wrapped) when the item is absent so callers can distinguish missing data
// from genuine keychain failures.
func getItem(account string) ([]byte, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(keychainService)
	query.SetAccount(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("%w: %s", errKeychainItemNotFound, account)
	}
	return results[0].Data, nil
}

// deleteItem removes an item from the keychain.
func deleteItem(account string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainService)
	item.SetAccount(account)
	return keychain.DeleteItem(item)
}
