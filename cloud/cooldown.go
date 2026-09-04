package cloud

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EmailActionCooldown is the minimum gap the client enforces between emails to
// the same address for the same purpose, mirroring the server default
// (IC_CLOUD_EMAIL_COOLDOWN). It's a UX shortcut so a repeated request usually
// never reaches the server. The server throttle stays authoritative — if an
// operator runs a longer server cooldown, that's still enforced; the client
// just won't always pre-empt it.
const EmailActionCooldown = 60 * time.Second

// Email action purposes for the client-side cooldown gate. They mirror the
// server's email_send_log purposes so the two stay conceptually aligned.
const (
	EmailActionVerify = "verification"
	EmailActionReset  = "reset"
)

// CooldownError is returned by ForgotPassword / RequestVerification when the
// client-side cooldown has not yet elapsed, so the caller can tell the user how
// long to wait without a server round trip.
type CooldownError struct {
	Purpose string
	Retry   time.Duration
}

func (e *CooldownError) Error() string {
	return fmt.Sprintf("please wait %s before requesting another %s email",
		e.Retry.Round(time.Second), e.Purpose)
}

// CooldownStore persists the last-attempt time per key across process runs
// (ic-cli is a fresh process per command, so this must reach durable storage).
// The SDK owns the policy — keying, the window, the decision — and the app
// supplies storage: a file for ic-cli/desktop (NewFileCooldownStore) or
// platform storage on mobile.
type CooldownStore interface {
	LastAttempt(key string) (time.Time, bool)
	Record(key string, t time.Time) error
}

// SetCooldownStore enables the client-side email cooldown gate. With no store
// set, the gate is a no-op and only the server throttle applies.
func (c *Client) SetCooldownStore(s CooldownStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cooldown = s
}

func emailActionKey(purpose, email string) string {
	return purpose + ":" + strings.ToLower(strings.TrimSpace(email))
}

// gateEmailAction returns a *CooldownError if the action is still cooling down.
// A nil store (or no prior attempt) means "clear".
func (c *Client) gateEmailAction(purpose, email string) error {
	c.mu.RLock()
	store := c.cooldown
	c.mu.RUnlock()
	if store == nil {
		return nil
	}
	last, ok := store.LastAttempt(emailActionKey(purpose, email))
	if !ok {
		return nil
	}
	remaining := EmailActionCooldown - time.Since(last)
	if remaining <= 0 {
		return nil
	}
	return &CooldownError{Purpose: purpose, Retry: remaining}
}

// recordEmailAction stamps a completed action so the next one is gated locally.
// Best-effort: a write error must not fail the (already-succeeded) call.
func (c *Client) recordEmailAction(purpose, email string) {
	c.mu.RLock()
	store := c.cooldown
	c.mu.RUnlock()
	if store == nil {
		return
	}
	_ = store.Record(emailActionKey(purpose, email), time.Now())
}

// --- file-backed store -----------------------------------------------------

// NewFileCooldownStore returns a CooldownStore backed by a 0600 JSON file. Used
// by ic-cli and desktop ic-app; mobile can implement CooldownStore differently.
func NewFileCooldownStore(path string) CooldownStore {
	return &fileCooldownStore{path: path}
}

type fileCooldownStore struct {
	path string
	mu   sync.Mutex
}

func (f *fileCooldownStore) load() map[string]int64 {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return map[string]int64{}
	}
	var m map[string]int64
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]int64{}
	}
	return m
}

func (f *fileCooldownStore) LastAttempt(key string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ts, ok := f.load()[key]
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(ts, 0), true
}

func (f *fileCooldownStore) Record(key string, t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.load()
	m[key] = t.Unix()
	if err := os.MkdirAll(filepath.Dir(f.path), 0700); err != nil {
		return fmt.Errorf("creating cooldown dir: %w", err)
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding cooldowns: %w", err)
	}
	return os.WriteFile(f.path, raw, 0600)
}
