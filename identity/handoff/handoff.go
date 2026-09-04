// Package handoff centralizes the "change/remove the default identity" flows so
// ic-cli and ic-app don't each re-implement them. Deleting or changing the
// default identity re-keys the self-lock cloud resources (contacts/groups/
// notifications/settings) to the successor while both are unlockable — otherwise
// those blobs, sealed to the old default's lock, orphan ("incorrect identity for
// recipient block"). The heavy lifting (re-key) lives in icfx/cloud; the
// keystore/UI seams come in through the Host interface.
package handoff

import (
	"context"
	"errors"
	"fmt"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
)

// Host supplies the platform-specific pieces icfx can't do itself, mirroring
// cloud.SyncHost. Every identity handle OpenIdentity returns is owned and closed
// by the host (SelfCrypter is intentionally close-less).
type Host interface {
	// OpenIdentity unlocks an identity for use as a self-lock crypter (HW
	// identities may prompt a tap). The host owns its lifecycle.
	OpenIdentity(name string) (cloud.SelfCrypter, error)
	// ClearKeys wipes an identity's key material (and HW challenge) from the
	// keystore — the backend/HW-aware part the client already implements.
	ClearKeys(name string) error
	GroupStore() (*groups.Store, error)
	NotificationStore() *cloud.NotificationStore // nil when the client has no drawer (ic-cli)
	ResourceIO() cloud.ResourceIO
}

// ErrLastIdentity blocks removing the only identity.
var ErrLastIdentity = errors.New("cannot remove the only identity")

// SuccessorRequiredError asks the client to pick a successor default and retry.
type SuccessorRequiredError struct{ Candidates []string }

func (e *SuccessorRequiredError) Error() string {
	return "removing the default identity requires choosing a successor default"
}

// SetDefault re-keys the self-lock cloud resources from the current default to
// successor (while both are unlockable) and records successor as the new
// default. c may be nil (cloud disabled/unauthed) — then only the local default
// changes and any orphaned cloud blobs are recovered on a later authed sync.
func SetDefault(ctx context.Context, c *cloud.Client, cfg *config.Config, successor string, host Host) error {
	entries, err := loadIndex()
	if err != nil {
		return err
	}
	if !indexHas(entries, successor) {
		return fmt.Errorf("identity %q not found", successor)
	}
	if successor == resolveDefault(cfg, entries) {
		return nil // already the default — nothing to re-key
	}
	if err := rekeyTo(ctx, c, successor, host); err != nil {
		return err
	}
	cfg.DefaultIdentity = successor
	return cfg.Save()
	// NOTE: IsPrimary flag juggling is deliberately deferred — the roamed
	// manifest default pointer (slice 3) + cfg.DefaultIdentity are the
	// load-bearing signals; IsPrimary is display-only today.
}

// HandoffAndDelete blocks last-identity removal (unless force is true); when
// victim is the current default AND other identities remain it re-keys the
// self-lock resources to a successor (returning *SuccessorRequiredError when
// none is supplied) and records the new default before running the delete
// primitives. force bypasses only the last-identity block: it deletes the
// only/default identity without a successor, abandoning any cloud self-lock data
// sealed to it and clearing the default pointer — the caller owns the danger
// confirmation.
func HandoffAndDelete(ctx context.Context, c *cloud.Client, cfg *config.Config, victim, successor string, host Host, force bool) error {
	idStore, err := identity.NewStore()
	if err != nil {
		return err
	}
	entries, err := idStore.LoadIndex()
	if err != nil {
		return fmt.Errorf("loading identity index: %w", err)
	}
	if !indexHas(entries, victim) {
		return fmt.Errorf("identity %q not found", victim)
	}
	// Removing the only identity is blocked unless forced. A forced last-identity
	// deletion has no successor to hand off to, so any cloud self-lock data sealed
	// to it (contacts/groups/settings/notifications) is abandoned — the caller is
	// responsible for the danger confirmation. The default pointer is cleared
	// after deletion below.
	if len(entries) == 1 && !force {
		return ErrLastIdentity
	}

	// A default that still has OTHER identities hands off its self-lock cloud
	// data to a chosen successor before deletion so nothing orphans. (The forced
	// last-identity path skips this — there is no successor.)
	if len(entries) > 1 && victim == resolveDefault(cfg, entries) {
		if successor == "" {
			return &SuccessorRequiredError{Candidates: namesExcept(entries, victim)}
		}
		if successor == victim || !indexHas(entries, successor) {
			return fmt.Errorf("invalid successor identity %q", successor)
		}
		if err := rekeyTo(ctx, c, successor, host); err != nil {
			return err
		}
		cfg.DefaultIdentity = successor
		if err := cfg.Save(); err != nil {
			return err
		}
	}

	// Delete primitives — centralized here, removed from both clients. Write the
	// index (entry removed) BEFORE wiping keys/meta: a crash after the key wipe
	// would otherwise strand a key-less index entry that can never be unlocked.
	// The reverse partial — index removed, keys still present — is the
	// recoverable "orphaned keys" state (`import --reconcile`), a strictly
	// better failure mode.
	filtered := make([]identity.IdentityIndex, 0, len(entries)-1)
	for _, e := range entries {
		if e.Name != victim {
			filtered = append(filtered, e)
		}
	}
	if err := idStore.SaveIndex(filtered); err != nil {
		return fmt.Errorf("saving identity index: %w", err)
	}
	if err := host.ClearKeys(victim); err != nil {
		return fmt.Errorf("clearing keys for %q: %w", victim, err)
	}
	if err := idStore.RemoveMeta(victim); err != nil {
		return fmt.Errorf("removing meta for %q: %w", victim, err)
	}
	// Clear a now-dangling default pointer (forced deletion of the default/only
	// identity left no successor to inherit it).
	if cfg.DefaultIdentity == victim {
		cfg.DefaultIdentity = ""
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("clearing default identity: %w", err)
		}
	}
	return nil
}

// RekeyDefaultAfterRotate re-keys the self-lock cloud resources to newU when the
// just-rotated identity is the current default (whose lock just changed). No-op
// when c is nil (cloud disabled/unauthed) or the rotated identity isn't the
// default (rotating a non-default identity doesn't touch the self-lock blobs).
// Call it right after the new keys are stored, with newU = the identity reopened
// under its NEW keys. The re-key logic is shared with delete/set-default so
// rotation adds no duplicated cloud logic.
//
// NOTE: the rest of the rotation sequence (keygen → archive old → self-sign →
// save meta/index → seal rotation bundle) is still duplicated in the two client
// rotate paths; fully relocating it into icfx is a separate, larger refactor.
func RekeyDefaultAfterRotate(ctx context.Context, c *cloud.Client, cfg *config.Config, rotatedName string, newU cloud.SelfCrypter, host Host) error {
	if c == nil {
		return nil
	}
	entries, err := loadIndex()
	if err != nil {
		return err
	}
	if rotatedName != resolveDefault(cfg, entries) {
		return nil
	}
	gstore, err := host.GroupStore()
	if err != nil {
		return fmt.Errorf("opening groups store: %w", err)
	}
	return c.RekeyDefaultSelfLock(ctx, newU, host.ResourceIO(), gstore, host.NotificationStore())
}

// RekeyDefault re-seals the self-lock cloud resources (contacts snapshot,
// settings, groups, notifications) to the CURRENT default identity from local
// plaintext, unconditionally — the repair/escape hatch for cloud blobs left
// sealed to a superseded key (e.g. after deleting the last identity then
// creating/importing a new default, which no handoff covered, so the blobs were
// never re-keyed and only orphan on a fresh device). No-op when c is nil (cloud
// off/unauthed) or there is no default. Run it on a device that HOLDS the data;
// the reseal empty-source guard makes it a safe no-op on a device without it.
func RekeyDefault(ctx context.Context, c *cloud.Client, cfg *config.Config, host Host) error {
	if c == nil {
		return nil
	}
	entries, err := loadIndex()
	if err != nil {
		return err
	}
	def := resolveDefault(cfg, entries)
	if def == "" {
		return nil
	}
	return rekeyTo(ctx, c, def, host)
}

// rekeyTo opens the successor and re-keys the self-lock cloud resources to it.
// No-op when c is nil (cloud disabled/unauthed).
func rekeyTo(ctx context.Context, c *cloud.Client, successor string, host Host) error {
	if c == nil {
		return nil
	}
	newU, err := host.OpenIdentity(successor)
	if err != nil {
		return fmt.Errorf("opening successor %q: %w", successor, err)
	}
	gstore, err := host.GroupStore()
	if err != nil {
		return fmt.Errorf("opening groups store: %w", err)
	}
	return c.RekeyDefaultSelfLock(ctx, newU, host.ResourceIO(), gstore, host.NotificationStore())
}

func loadIndex() ([]identity.IdentityIndex, error) {
	idStore, err := identity.NewStore()
	if err != nil {
		return nil, err
	}
	entries, err := idStore.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("loading identity index: %w", err)
	}
	return entries, nil
}

// resolveDefault mirrors resolveDefaultIdentityName: cfg default if present,
// else the first index entry.
func resolveDefault(cfg *config.Config, entries []identity.IdentityIndex) string {
	if idx := identity.ResolveDefaultIndex(entries, cfg.DefaultIdentity); idx != nil {
		return idx.Name
	}
	return ""
}

func indexHas(entries []identity.IdentityIndex, name string) bool {
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

func namesExcept(entries []identity.IdentityIndex, victim string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name != victim {
			out = append(out, e.Name)
		}
	}
	return out
}
