package keystore

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
)

// PassphraseFunc is a callback that returns a passphrase for encrypting/decrypting key files.
//
// It returns the passphrase as a wipeable []byte rather than an immutable Go
// string: the consumer (this keystore) takes ownership of the returned slice
// and zeroes it after use, so the master passphrase never lingers in an
// un-zeroable string on the heap. Producers that cache a prompt must return a
// FRESH copy each call (the consumer wipes what it receives). An empty/nil
// slice means "no passphrase" (plaintext mode).
type PassphraseFunc func() ([]byte, error)

// FileStore stores keys as files in the keys directory.
// When a PassphraseFunc is set, keys are encrypted at rest using age scrypt.
type FileStore struct {
	dir            string
	passphraseFunc PassphraseFunc

	// allowPlaintextMigration lets a read in encrypted mode accept a key file
	// that is NOT age-framed (i.e. plaintext). Default false: an encrypted-mode
	// store rejects a plaintext key file rather than silently loading a
	// downgraded/tampered key. Callers performing a genuine plaintext→encrypted
	// migration opt in via AllowPlaintextMigration.
	allowPlaintextMigration bool

	mu       sync.Mutex
	cache    map[string]*memguard.Enclave // single cache slot ("") for name-blind callbacks; nil enclave means "resolved to empty"
	resolved map[string]bool              // tracks which keys have been resolved (distinguishes nil-enclave from absent)
}

// AllowPlaintextMigration opts this store into accepting plaintext (non-age)
// key files while in encrypted mode — needed only when migrating a legacy
// plaintext keystore to encrypted-at-rest. Off by default (secure).
func (f *FileStore) AllowPlaintextMigration() { f.allowPlaintextMigration = true }

// NewFileStore creates a new FileStore using the default keys directory (plaintext, no encryption).
// Returns an error if the default keys dir cannot be resolved (mobile platforms
// with no override, broken HOME env, etc).
func NewFileStore() (*FileStore, error) {
	dir, err := config.KeysDir()
	if err != nil {
		return nil, fmt.Errorf("resolving keys directory: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

// NewFileStoreWithDir creates a plaintext FileStore with a custom directory.
func NewFileStoreWithDir(dir string) *FileStore {
	return &FileStore{dir: dir}
}

// NewEncryptedFileStore creates a FileStore that encrypts keys at rest using the default keys directory.
// Returns an error if the default keys dir cannot be resolved.
func NewEncryptedFileStore(fn PassphraseFunc) (*FileStore, error) {
	dir, err := config.KeysDir()
	if err != nil {
		return nil, fmt.Errorf("resolving keys directory: %w", err)
	}
	return &FileStore{dir: dir, passphraseFunc: fn}, nil
}

// NewEncryptedFileStoreWithDir creates an encrypted FileStore with a custom directory.
func NewEncryptedFileStoreWithDir(dir string, fn PassphraseFunc) *FileStore {
	return &FileStore{dir: dir, passphraseFunc: fn}
}

// resolvePassphraseForName returns a FRESH, caller-owned copy of the
// passphrase/KEK bytes used to en/decrypt the given identity's key files. The
// caller MUST wipe the returned slice (crypto.Zero) after use. A nil slice
// means plaintext mode (no passphrase). Caches the result in memguard so
// repeated reads/writes don't re-trigger callbacks. The name parameter is
// currently unused (single-cache-slot mode) but is kept for symmetry with
// read/write call sites and future per-identity key paths.
func (f *FileStore) resolvePassphraseForName(_ string) ([]byte, error) {
	cacheKey := ""

	f.mu.Lock()
	cached, ok := f.cache[cacheKey]
	resolved := f.resolved[cacheKey]
	f.mu.Unlock()

	if resolved {
		if !ok || cached == nil {
			return nil, nil
		}
		buf, err := cached.Open()
		if err != nil {
			return nil, fmt.Errorf("opening cached passphrase: %w", err)
		}
		out := make([]byte, len(buf.Bytes()))
		copy(out, buf.Bytes())
		buf.Destroy()
		return out, nil
	}

	pass, err := f.computePassphraseForName("")
	if err != nil {
		return nil, err
	}
	f.cacheStore(cacheKey, pass) // seals a copy; leaves pass owned by the caller
	return pass, nil
}

// computePassphraseForName invokes the configured callback to derive the
// passphrase for the given identity. No callback set → nil (plaintext mode).
func (f *FileStore) computePassphraseForName(_ string) ([]byte, error) {
	if f.passphraseFunc != nil {
		return f.passphraseFunc()
	}
	return nil, nil
}

// cacheStore seals a COPY of pass into the single-slot memguard cache. It does
// not consume pass — the caller retains and wipes the original.
func (f *FileStore) cacheStore(key string, pass []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cache == nil {
		f.cache = make(map[string]*memguard.Enclave)
		f.resolved = make(map[string]bool)
	}
	f.resolved[key] = true
	if len(pass) == 0 {
		f.cache[key] = nil
		return
	}
	cp := make([]byte, len(pass))
	copy(cp, pass)
	buf := memguard.NewBufferFromBytes(cp) // wipes cp, not pass
	f.cache[key] = buf.Seal()
}

// isAgeEncrypted checks if data begins with the age encryption header.
func isAgeEncrypted(data []byte) bool {
	return bytes.HasPrefix(data, []byte("age-encryption.org"))
}

func (f *FileStore) StoreEncryptionIdentity(name string, identity string) error {
	return f.writeFile(name+".enc", []byte(identity))
}

func (f *FileStore) LoadEncryptionIdentity(name string) (string, error) {
	data, err := f.readFile(name + ".enc")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (f *FileStore) StoreSigningKey(name string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return f.writeFile(name+".sign", []byte(encoded))
}

func (f *FileStore) LoadSigningKey(name string) ([]byte, error) {
	data, err := f.readFile(name + ".sign")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
}

func (f *FileStore) HasKeys(name string) bool {
	_, err1 := os.Stat(filepath.Join(f.dir, name+".enc"))
	_, err2 := os.Stat(filepath.Join(f.dir, name+".sign"))
	return err1 == nil && err2 == nil
}

func (f *FileStore) Clear(name string) error {
	// Idempotent for missing files; surface real errors (perms, etc).
	if err := os.Remove(filepath.Join(f.dir, name+".enc")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s.enc: %w", name, err)
	}
	if err := os.Remove(filepath.Join(f.dir, name+".sign")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s.sign: %w", name, err)
	}
	return nil
}

func (f *FileStore) ListNames() ([]string, error) {
	entries, err := os.ReadDir(f.dir)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading keys directory: %w", err)
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip hardware-key challenge files (suffix-matched, not exact).
		if strings.HasSuffix(name, ".hwchallenge") {
			continue
		}
		name = strings.TrimSuffix(name, ".enc")
		name = strings.TrimSuffix(name, ".sign")
		seen[name] = true
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	return names, nil
}

func (f *FileStore) writeFile(filename string, data []byte) error {
	if err := os.MkdirAll(f.dir, 0700); err != nil {
		return fmt.Errorf("creating keys directory: %w", err)
	}

	pass, err := f.resolvePassphraseForName("")
	if err != nil {
		return fmt.Errorf("resolving passphrase: %w", err)
	}
	defer crypto.Zero(pass)

	if len(pass) != 0 {
		data, err = crypto.EncryptWithPassphraseBytes(data, pass)
		if err != nil {
			return fmt.Errorf("encrypting key file %s: %w", filename, err)
		}
	}

	path := filepath.Join(f.dir, filename)
	return os.WriteFile(path, data, 0600)
}

func (f *FileStore) readFile(filename string) ([]byte, error) {
	path := filepath.Join(f.dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", filename, err)
	}

	pass, err := f.resolvePassphraseForName("")
	if err != nil {
		return nil, fmt.Errorf("resolving passphrase: %w", err)
	}
	defer crypto.Zero(pass)

	if len(pass) != 0 {
		if isAgeEncrypted(data) {
			decrypted, err := crypto.DecryptWithPassphraseBytes(data, pass)
			if err != nil {
				return nil, fmt.Errorf("decrypting key file %s (wrong passphrase?): %w", filename, err)
			}
			return decrypted, nil
		}
		// Encrypted mode, but the on-disk key file is plaintext (not age-framed):
		// a downgraded or tampered key. Refuse it unless the caller explicitly
		// opted into a plaintext→encrypted migration.
		if !f.allowPlaintextMigration {
			return nil, fmt.Errorf("key file %s is not encrypted but the store is in encrypted mode (refusing to load a plaintext key; enable AllowPlaintextMigration to migrate)", filename)
		}
	}

	return data, nil
}
