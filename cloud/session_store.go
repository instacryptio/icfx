package cloud

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	keyring "github.com/zalando/go-keyring"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/keystore"
)

// A cloud session is two very different things stored together: the bearer
// tokens (SECRET — access + refresh credentials) and the sync positions
// (non-secret convergence bookkeeping). SessionStore keeps them apart so the
// tokens get real at-rest protection — the OS keychain, or an age-scrypt
// passphrase-encrypted file, the SAME policy as EncKeyStore and identity keys —
// while the positions live in a plain 0600 file that any signed-in / UI check
// can read without a passphrase. The library owns this so every client (app,
// CLI, agent) shares one implementation instead of hand-rolling a plaintext
// session file.

// ErrNoSession is returned by LoadTokens when no session is stored for the
// account (the caller is signed out).
var ErrNoSession = errors.New("no cloud session stored")

// SyncPositions is the non-secret sync bookkeeping persisted between runs:
// per-resource blob versions, the identities and contacts sync positions, and
// the last-synced settings digest. None of it is a credential.
type SyncPositions struct {
	Versions       map[string]int64    `json:"versions,omitempty"`
	Identities     IdentitiesSyncState `json:"identities"`
	Contacts       ContactsSyncState   `json:"contacts"`
	SettingsDigest string              `json:"settings_digest,omitempty"`
}

// TokenBackend persists the SECRET bearer tokens at rest, keyed by account
// email. It is the platform-swappable half of a SessionStore: the OS keychain
// (desktop), an age-scrypt file (headless / file keystore), or a host-injected
// backend (the Android Keystore, which the library can't import). LoadTokens
// must return ErrNoSession when nothing is stored.
type TokenBackend interface {
	SaveTokens(email string, t *Tokens) error
	LoadTokens(email string) (*Tokens, error)
	HasTokens(email string) bool
	ClearTokens(email string) error
}

// SessionStore persists a whole cloud session for one account: the SECRET
// tokens (via a TokenBackend) and the non-secret SyncPositions. Save/Clear are
// best-effort from the SDK's point of view; LoadTokens misses return
// ErrNoSession.
type SessionStore interface {
	SaveTokens(email string, t *Tokens) error
	// LoadTokens returns the stored tokens, or ErrNoSession. On a file backend
	// this needs the passphrase (decrypt); HasSession does not.
	LoadTokens(email string) (*Tokens, error)
	// HasSession reports whether a session is stored WITHOUT decrypting — cheap
	// enough for signed-in / UI gates on a locked file backend.
	HasSession(email string) bool
	SavePositions(email string, p SyncPositions) error
	LoadPositions(email string) (SyncPositions, error)
	// ActiveAccount reports the email of the last account whose session was
	// saved (ok=false when signed out). It lets a fresh process learn which
	// account to RestoreSession without knowing the email up front — the email
	// is the store key and is non-secret (it's in the JWT and sent to the
	// server). Recorded on SaveTokens, removed on Clear.
	ActiveAccount() (email string, ok bool)
	// Clear removes the tokens, positions, and active-account record.
	Clear(email string) error
}

// NewSessionStore composes a SessionStore from a TokenBackend (secret half)
// and a plain-0600 positions file under dir. Most callers use
// DefaultSessionStore, which picks the TokenBackend by platform policy.
func NewSessionStore(dir string, tokens TokenBackend) SessionStore {
	return sessionStore{dir: dir, tokens: tokens}
}

// DefaultSessionStore picks the token backend by the SAME policy as identity
// keys / EncKeyStore: a host-injected keyring backend if provided (Android),
// else the OS keychain when useKeychain and a keychain is available, else an
// age-scrypt passphrase-file under dir. passFn supplies the keystore
// passphrase lazily (only needed for the file backend).
func DefaultSessionStore(dir string, useKeychain bool, passFn keystore.PassphraseFunc, keyringBackend TokenBackend) SessionStore {
	var tb TokenBackend
	switch {
	case keyringBackend != nil:
		tb = keyringBackend
	case useKeychain && keystore.KeychainAvailable():
		tb = NewKeychainTokenBackend()
	default:
		tb = NewFileTokenBackend(dir, passFn)
	}
	return NewSessionStore(dir, tb)
}

// --- SessionStore: token half delegated, positions in a plain 0600 file ------

type sessionStore struct {
	dir    string
	tokens TokenBackend
}

func (s sessionStore) SaveTokens(email string, t *Tokens) error {
	if err := s.tokens.SaveTokens(email, t); err != nil {
		return err
	}
	// Record the active account (non-secret) so a fresh process can restore it.
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(s.activeAccountPath(), []byte(email), 0600)
}
func (s sessionStore) LoadTokens(email string) (*Tokens, error) { return s.tokens.LoadTokens(email) }
func (s sessionStore) HasSession(email string) bool             { return s.tokens.HasTokens(email) }

func (s sessionStore) activeAccountPath() string {
	return filepath.Join(s.dir, "cloud_account")
}

func (s sessionStore) ActiveAccount() (string, bool) {
	raw, err := os.ReadFile(s.activeAccountPath())
	if err != nil {
		return "", false
	}
	email := string(raw)
	if email == "" {
		return "", false
	}
	return email, true
}

func (s sessionStore) positionsPath(email string) string {
	sum := sha256.Sum256([]byte(email))
	return filepath.Join(s.dir, "cloud_session_"+hex.EncodeToString(sum[:8])+".json")
}

func (s sessionStore) SavePositions(email string, p SyncPositions) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode sync positions: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(s.positionsPath(email), raw, 0600)
}

func (s sessionStore) LoadPositions(email string) (SyncPositions, error) {
	raw, err := os.ReadFile(s.positionsPath(email))
	if os.IsNotExist(err) {
		return SyncPositions{Versions: map[string]int64{}}, nil
	}
	if err != nil {
		return SyncPositions{}, err
	}
	var p SyncPositions
	if err := json.Unmarshal(raw, &p); err != nil {
		return SyncPositions{}, fmt.Errorf("decode sync positions: %w", err)
	}
	if p.Versions == nil {
		p.Versions = map[string]int64{}
	}
	return p, nil
}

func (s sessionStore) Clear(email string) error {
	terr := s.tokens.ClearTokens(email)
	if perr := os.Remove(s.positionsPath(email)); perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	if aerr := os.Remove(s.activeAccountPath()); aerr != nil && !os.IsNotExist(aerr) {
		return aerr
	}
	return terr
}

// --- keychain token backend --------------------------------------------------

type keychainTokenBackend struct{}

// NewKeychainTokenBackend stores tokens in the OS keychain under the same
// service as identity keys and the encKey. Use when keystore.KeychainAvailable().
func NewKeychainTokenBackend() TokenBackend { return keychainTokenBackend{} }

func tokenEntry(email string) string { return "cloud-tokens:" + email }

func (keychainTokenBackend) SaveTokens(email string, t *Tokens) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return keyring.Set(keystore.ServiceName(), tokenEntry(email), string(raw))
}

func (keychainTokenBackend) LoadTokens(email string) (*Tokens, error) {
	val, err := keyring.Get(keystore.ServiceName(), tokenEntry(email))
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("keychain: %w", err)
	}
	var t Tokens
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return nil, fmt.Errorf("keychain session entry corrupt: %w", err)
	}
	return &t, nil
}

func (keychainTokenBackend) HasTokens(email string) bool {
	_, err := keyring.Get(keystore.ServiceName(), tokenEntry(email))
	return err == nil
}

func (keychainTokenBackend) ClearTokens(email string) error {
	err := keyring.Delete(keystore.ServiceName(), tokenEntry(email))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// --- file (age-scrypt) token backend -----------------------------------------

type fileTokenBackend struct {
	dir  string
	pass keystore.PassphraseFunc
}

// NewFileTokenBackend stores tokens as an age-scrypt passphrase-encrypted file
// in dir (0600) — the same at-rest primitive and policy as file-backed
// identity keys and the encKey. pass supplies the keystore passphrase lazily.
func NewFileTokenBackend(dir string, pass keystore.PassphraseFunc) TokenBackend {
	return fileTokenBackend{dir: dir, pass: pass}
}

func (s fileTokenBackend) path(email string) string {
	sum := sha256.Sum256([]byte(email))
	return filepath.Join(s.dir, "cloud_tokens_"+hex.EncodeToString(sum[:8])+".age")
}

func (s fileTokenBackend) SaveTokens(email string, t *Tokens) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	pass, err := s.pass()
	if err != nil {
		return err
	}
	ct, err := crypto.EncryptWithPassphrase(raw, pass)
	if err != nil {
		return fmt.Errorf("encrypting session tokens: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(s.path(email), ct, 0600)
}

func (s fileTokenBackend) LoadTokens(email string) (*Tokens, error) {
	ct, err := os.ReadFile(s.path(email))
	if os.IsNotExist(err) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	pass, err := s.pass()
	if err != nil {
		return nil, err
	}
	raw, err := crypto.DecryptWithPassphrase(ct, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypting session tokens (wrong keystore passphrase?): %w", err)
	}
	var t Tokens
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("session token file corrupt: %w", err)
	}
	return &t, nil
}

func (s fileTokenBackend) HasTokens(email string) bool {
	_, err := os.Stat(s.path(email))
	return err == nil
}

func (s fileTokenBackend) ClearTokens(email string) error {
	err := os.Remove(s.path(email))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
