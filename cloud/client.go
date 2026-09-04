// Package cloud is the Go client SDK for Instacrypt Cloud.
//
// It covers the full client surface: HTTP transport, auth (incl. verification
// and password reset), billing, raw encrypted blob CRUD, pending update I/O,
// public directory, file sharing via presigned URLs, and plan/tier
// introspection.
//
// It also owns the blob-encryption *contract* so every client (ic-cli, ic-app,
// future ic-agent) reads and writes blobs identically and interoperates by
// construction rather than by convention:
//   - SealBlob / OpenBlob — self-lock blobs (contacts, settings): encrypt to the
//     caller's own lock, then PutBlob / GetBlob.
//   - SendToRecipient / ApplyPending — encrypt a bundle to a recipient's lock and
//     route it; on the far side, decrypt and parse by kind.
//
// These helpers add no new cryptography — they compose icfx primitives
// (EncryptToSelf / Decrypt / crypto.Encrypt / bundle.Parse / qr.ParseLockBundle).
//
// Backup / restore reuse icfx/profile (a passphrase-encrypted, multi-identity
// bundle) stored as the "backup" blob — see Backup / FetchBackup. Restoring a
// backup onto a fresh device also bootstraps its keys, which covers the core of
// identity roaming; a separate always-fresh identities auto-sync tier remains a
// future refinement (it needs the passphrase on every key change, so it can't
// be silent like the self-lock contacts/settings blobs).
package cloud

import (
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/instacryptio/icfx/config"
)

// processInstanceID identifies this process to the server (X-IC-Instance
// header) so the event stream can suppress the doorbell for changes this
// process made itself. Random per process; carries no account or device
// identity. Every Client in the process shares it by default — a process IS
// one device — but SetInstanceID can override per client (tests, hosts
// serving several logical devices).
var processInstanceID = uuid.NewString()

// Client talks to a single ic-cloud server.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	mu     sync.RWMutex
	tokens *Tokens
	// refreshMu serializes Refresh calls (held across the network round
	// trip, so it's separate from mu — token readers must not block).
	// Concurrent refreshes would re-POST an already-rotated refresh token,
	// which the server treats as theft and answers by revoking the whole
	// session family.
	refreshMu sync.Mutex
	email     string
	// encKey is the account-password-derived key that encrypts the identities
	// blob. Held in memory after login; never persisted or sent to the server.
	encKey []byte
	// cooldown gates client-initiated emails (verify/reset) so a repeated
	// request usually never reaches the server. Nil disables the gate.
	cooldown CooldownStore
	// encKeyStore optionally persists encKey between sessions (keychain or
	// passphrase-file) so identities sync doesn't re-prompt for the cloud
	// password. Nil keeps the memory-only behavior.
	encKeyStore EncKeyStore
	// sessionStore optionally persists the bearer tokens (protected at rest)
	// and the non-secret sync positions between runs, so the tokens never live
	// in a plaintext client file. Nil keeps the memory-only behavior (the
	// caller persists tokens itself). Tokens are saved through it on every
	// successful auth and on refresh, and cleared on LogOut.
	sessionStore SessionStore
	// instance is sent as X-IC-Instance on every request — the origin tag
	// the event stream uses to suppress this device's own doorbells.
	instance string
	// device is sent as X-IC-Device — the human-readable name shown in the
	// account's Devices list. Empty falls back to runtime.GOOS.
	device string
}

// New constructs a client for the given base URL. It re-validates the URL
// (defense-in-depth: callers build it from validated config, but a raw
// http://remote passed here would otherwise send credentials in cleartext).
func New(baseURL string) (*Client, error) {
	if err := config.ValidateCloudBaseURL(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		BaseURL:  baseURL,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		instance: processInstanceID,
	}, nil
}

// SetInstanceID overrides the client's origin tag (X-IC-Instance). The
// default — shared by every client in the process — is right for apps and
// the CLI; override only when one process intentionally acts as several
// devices (tests, multi-account hosts).
func (c *Client) SetInstanceID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instance = id
}

func (c *Client) instanceID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.instance
}

// SetDeviceLabel names this device in the account's Devices list (sent as
// X-IC-Device; the server stamps it on sessions at login). Unset falls back
// to the OS name — consumers should set something friendlier ("icc · linux").
func (c *Client) SetDeviceLabel(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.device = label
}

func (c *Client) deviceLabel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.device == "" {
		return runtime.GOOS
	}
	return c.device
}

// SetTokens replaces the client's stored credentials. Most callers don't
// need to call this directly — LogIn / LogInTOTP / Refresh do it for them.
//
// When a SessionStore is wired, a non-nil token set is persisted through it
// here — so every auth completion AND every refresh rotation lands in the
// protected store automatically, with no plaintext client file. Persisting
// tokens independently of sync positions means a refresh can never clobber
// them. RestoreSession loads WITHOUT re-persisting (it bypasses this method).
func (c *Client) SetTokens(t *Tokens) {
	c.mu.Lock()
	c.tokens = t
	store, email := c.sessionStore, c.email
	c.mu.Unlock()
	if t != nil && store != nil && email != "" {
		cp := *t
		_ = store.SaveTokens(email, &cp) // best-effort; never fails the auth flow
	}
}

func (c *Client) Tokens() *Tokens {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tokens == nil {
		return nil
	}
	t := *c.tokens
	return &t
}

func (c *Client) accessToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tokens == nil {
		return ""
	}
	return c.tokens.AccessToken
}

// IsAuthenticated reports whether the client has an unexpired access token.
func (c *Client) IsAuthenticated() bool {
	return c.TokenValidFor(0)
}

// TokenValidFor reports whether the access token will still be valid margin
// from now. Callers doing work between the check and the request (key
// derivation, blob crypto) should pass a margin so a token that's valid at
// check time can't expire at use time.
func (c *Client) TokenValidFor(margin time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokens != nil && time.Now().Add(margin).Before(c.tokens.ExpiresAt)
}

// setAuthState records the account email and the password-derived encryption
// key after a successful (or in-progress-TOTP) login. Both stay in memory only.
func (c *Client) setAuthState(email string, encKey []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.email = email
	c.encKey = encKey
}

// encryptionKey returns the in-memory account encryption key, or nil if the
// client hasn't derived one this session (e.g. tokens loaded from disk without
// a fresh login). Callers that need it must LogIn first.
func (c *Client) encryptionKey() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.encKey == nil {
		return nil
	}
	// Return a copy so callers can't mutate (or race on) the client's secret
	// key slice through the returned reference.
	out := make([]byte, len(c.encKey))
	copy(out, c.encKey)
	return out
}

func (c *Client) accountEmail() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.email
}

// HasEncryptionKey reports whether the client holds the account-password-
// derived encryption key this session (fresh LogIn/SignUp — not tokens loaded
// from disk). Identity roaming (Push/PullIdentities, SyncIdentities) requires
// it; without it the SDK falls back to the configured EncKeyStore, and only
// then to a fresh cloud-password login.
func (c *Client) HasEncryptionKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.encKey) > 0
}

// SetAccountEmail records the account email on a client restored from
// persisted tokens (LogIn sets it automatically). The EncKeyStore is keyed by
// email, so token-restored clients need it before identities sync can use a
// stored key.
func (c *Client) SetAccountEmail(email string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.email = email
}

// AuthEmail returns the account email the client is authenticated as (set by
// LogIn / SetAccountEmail / RestoreSession), or "" when signed out.
func (c *Client) AuthEmail() string { return c.accountEmail() }

// SetEncKeyStore wires persistence for the account encryption key (keychain
// or passphrase-file — see EncKeyStore). Successful logins save through it;
// identities sync loads from it; LogOut clears it.
func (c *Client) SetEncKeyStore(s EncKeyStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.encKeyStore = s
}

// persistEncKey best-effort saves the in-memory encKey through the store.
// Persistence failures never fail the auth flow that triggered them.
func (c *Client) persistEncKey() {
	c.mu.RLock()
	store, email, key := c.encKeyStore, c.email, c.encKey
	c.mu.RUnlock()
	if store == nil || email == "" || len(key) == 0 {
		return
	}
	_ = store.Save(email, key)
}

// storedEncKey loads the persisted encKey for the client's account, if a
// store is configured. Misses return ErrEncKeyMissing-wrapped errors.
func (c *Client) storedEncKey() ([]byte, error) {
	c.mu.RLock()
	store, email := c.encKeyStore, c.email
	c.mu.RUnlock()
	if store == nil {
		return nil, ErrEncKeyMissing
	}
	if email == "" {
		return nil, fmt.Errorf("%w (client has no account email — call SetAccountEmail)", ErrEncKeyMissing)
	}
	return store.Load(email)
}

// clearStoredEncKey best-effort removes the persisted encKey (logout).
func (c *Client) clearStoredEncKey() {
	c.mu.RLock()
	store, email := c.encKeyStore, c.email
	c.mu.RUnlock()
	if store == nil || email == "" {
		return
	}
	_ = store.Clear(email)
}

// SetSessionStore wires persistence for the bearer tokens (protected at rest)
// and sync positions. When set, the SDK saves tokens through it on every
// successful auth and on refresh, and clears it on LogOut — the caller no
// longer persists tokens itself. Set SetAccountEmail first (the store is keyed
// by email). See SessionStore / DefaultSessionStore.
func (c *Client) SetSessionStore(s SessionStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionStore = s
}

// SessionStore returns the wired store (or nil) so hosts can read/persist sync
// positions around a sync run without re-selecting a backend.
func (c *Client) SessionStore() SessionStore {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionStore
}

// RestoreSession loads persisted tokens for email into the client (signed-in
// on process start without re-login). Sets the account email so the encKey and
// session stores are keyed correctly. Returns ErrNoSession when nothing is
// stored. Bypasses SetTokens so the restore doesn't re-persist (which would
// re-encrypt / re-prompt on a file backend every start). Positions are read
// separately by the sync flow via SessionStore().
func (c *Client) RestoreSession(email string) error {
	c.mu.Lock()
	store := c.sessionStore
	c.email = email
	c.mu.Unlock()
	if store == nil {
		return ErrNoSession
	}
	t, err := store.LoadTokens(email)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.tokens = t
	c.mu.Unlock()
	return nil
}

// clearStoredSession best-effort removes the persisted session (logout).
func (c *Client) clearStoredSession() {
	c.mu.RLock()
	store, email := c.sessionStore, c.email
	c.mu.RUnlock()
	if store == nil || email == "" {
		return
	}
	_ = store.Clear(email)
}
