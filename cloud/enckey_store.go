package cloud

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	keyring "github.com/zalando/go-keyring"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/keystore"
)

// The account encryption key (encKey) is derived from the cloud password and
// protects the identities roaming blob. It is zero-knowledge server-side and
// historically lived only in process memory, which meant every identities
// sync outside a fresh login re-prompted for the cloud password (and re-ran
// 2FA). An EncKeyStore persists it client-side under the SAME policy as
// identity keys: OS keychain when available/configured, otherwise an
// age-scrypt passphrase-encrypted file. The cloud password itself is never
// stored — the encKey is strictly less privileged (it decrypts one blob; it
// cannot authenticate).

// ErrEncKeyMissing is returned when neither the session nor the configured
// EncKeyStore holds an encryption key — callers fall back to the cloud
// password prompt.
var ErrEncKeyMissing = errors.New("no cloud encryption key available — enter the cloud password")

// ErrEncKeyStale is returned when a STORED encryption key fails to open the
// identities blob (the account password changed on another device). Callers
// fall back to the password prompt; the fresh key is re-persisted on success.
var ErrEncKeyStale = errors.New("stored cloud encryption key is stale — the account password changed; enter the cloud password")

// EncKeyStore persists the account encryption key between sessions, keyed by
// account email. Save/Clear are best-effort from the SDK's point of view;
// Load misses must return an error wrapping ErrEncKeyMissing.
type EncKeyStore interface {
	Save(email string, encKey []byte) error
	Load(email string) ([]byte, error)
	Clear(email string) error
}

// --- OS keychain implementation ---------------------------------------------

type keychainEncKeyStore struct{}

// NewKeychainEncKeyStore stores the encKey in the OS keychain under the same
// service as identity keys. Use when keystore.KeychainAvailable().
func NewKeychainEncKeyStore() EncKeyStore { return keychainEncKeyStore{} }

func keychainEntry(email string) string { return "cloud-enckey:" + email }

func (keychainEncKeyStore) Save(email string, encKey []byte) error {
	return keyring.Set(keystore.ServiceName(), keychainEntry(email), base64.StdEncoding.EncodeToString(encKey))
}

func (keychainEncKeyStore) Load(email string) ([]byte, error) {
	val, err := keyring.Get(keystore.ServiceName(), keychainEntry(email))
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, fmt.Errorf("%w (keychain has no entry)", ErrEncKeyMissing)
		}
		return nil, fmt.Errorf("keychain: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("keychain entry corrupt: %w", err)
	}
	return key, nil
}

func (keychainEncKeyStore) Clear(email string) error {
	err := keyring.Delete(keystore.ServiceName(), keychainEntry(email))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// --- passphrase-file implementation ------------------------------------------

type fileEncKeyStore struct {
	dir  string
	pass keystore.PassphraseFunc
}

// NewFileEncKeyStore stores the encKey as an age-scrypt passphrase-encrypted
// file in dir (0600) — the same at-rest primitive and policy as file-backed
// identity keys. pass supplies the keystore passphrase lazily (cached app
// session passphrase, or a CLI prompt).
func NewFileEncKeyStore(dir string, pass keystore.PassphraseFunc) EncKeyStore {
	return fileEncKeyStore{dir: dir, pass: pass}
}

func (s fileEncKeyStore) path(email string) string {
	sum := sha256.Sum256([]byte(email))
	return filepath.Join(s.dir, "cloud_enckey_"+hex.EncodeToString(sum[:8])+".age")
}

func (s fileEncKeyStore) Save(email string, encKey []byte) error {
	pass, err := s.pass()
	if err != nil {
		return err
	}
	ct, err := crypto.EncryptWithPassphrase(encKey, pass)
	if err != nil {
		return fmt.Errorf("encrypting cloud key: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(s.path(email), ct, 0600)
}

func (s fileEncKeyStore) Load(email string) ([]byte, error) {
	ct, err := os.ReadFile(s.path(email))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w (no key file)", ErrEncKeyMissing)
	}
	if err != nil {
		return nil, err
	}
	pass, err := s.pass()
	if err != nil {
		return nil, err
	}
	key, err := crypto.DecryptWithPassphrase(ct, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypting cloud key (wrong keystore passphrase?): %w", err)
	}
	return key, nil
}

func (s fileEncKeyStore) Clear(email string) error {
	err := os.Remove(s.path(email))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
