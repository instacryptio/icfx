package handoff_test

// Unit tests for the identity hand-off orchestration. They pass c = nil so the
// whole cloud re-key path short-circuits (rekeyTo / RekeyDefaultAfterRotate
// return nil when c == nil) — this exercises all the block/successor/delete
// decision logic + on-disk index/config effects without a cloud server. The
// fake Host only needs a working ClearKeys (the delete primitive); the other
// methods are never reached with c == nil.

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/identity/handoff"
)

// fakeHost implements handoff.Host. With c == nil the cloud re-key path is
// skipped, so the delete flow reaches exactly two host methods: OpenIdentity
// (the unlock-to-delete gate) and ClearKeys (the delete primitive). openErr
// simulates a victim that can't be unlocked (lost/wrong key); cleared records
// the full index entry ClearKeys received.
type fakeHost struct {
	cleared []identity.IdentityIndex
	opened  []string
	openErr error
}

func (h *fakeHost) OpenIdentity(name string) (cloud.SelfCrypter, error) {
	h.opened = append(h.opened, name)
	return nil, h.openErr
}
func (h *fakeHost) ClearKeys(idx identity.IdentityIndex) error {
	h.cleared = append(h.cleared, idx)
	return nil
}
func (h *fakeHost) GroupStore() (*groups.Store, error)          { return nil, nil }
func (h *fakeHost) NotificationStore() *cloud.NotificationStore { return nil }
func (h *fakeHost) ResourceIO() cloud.ResourceIO                { return nil }

// useEnv points the global icfx dirs at an isolated temp tree.
func useEnv(t *testing.T, dir string) {
	t.Helper()
	config.SetConfigDir(filepath.Join(dir, "config"))
	config.SetDataPath(filepath.Join(dir, "data"))
	config.SetKeyPath(filepath.Join(dir, "keys"))
	if err := config.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories: %v", err)
	}
}

// seedIdentity writes an identity's encrypted meta + index entry. No keystore
// keys are stored: with c == nil the handoff never opens the identity, and
// ClearKeys is faked.
func seedIdentity(t *testing.T, name string) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	info := identity.Identity{
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
		Status:      identity.StatusActive,
		Backend:     identity.BackendFile,
	}
	store, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.SaveMeta(info); err != nil {
		t.Fatalf("SaveMeta: %v", err)
	}
	entries, err := store.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	entries = append(entries, identity.IdentityIndex{Name: name, Backend: identity.BackendFile, Fingerprint: kp.Fingerprint})
	if err := store.SaveIndex(entries); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
}

func indexNames(t *testing.T) map[string]bool {
	t.Helper()
	store, err := identity.NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	entries, err := store.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	return names
}

func defaultCfg(name string) *config.Config {
	cfg := config.DefaultConfig()
	cfg.DefaultIdentity = name
	return cfg
}

func TestHandoffAndDelete_LastIdentityBlocked(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "alice", "", &fakeHost{}, false)
	if !errors.Is(err, handoff.ErrLastIdentity) {
		t.Fatalf("expected ErrLastIdentity, got %v", err)
	}
	if !indexNames(t)["alice"] {
		t.Error("alice was removed despite being the only identity")
	}
}

func TestHandoffAndDelete_LastIdentityForced(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	cfg := defaultCfg("alice")
	h := &fakeHost{}
	// force bypasses the last-identity block: alice is deleted with no successor.
	if err := handoff.HandoffAndDelete(context.Background(), nil, cfg, "alice", "", h, true); err != nil {
		t.Fatalf("forced last-identity delete: %v", err)
	}
	if len(h.cleared) != 1 || h.cleared[0].Name != "alice" {
		t.Errorf("cleared = %v, want [alice]", h.cleared)
	}
	if indexNames(t)["alice"] || len(indexNames(t)) != 0 {
		t.Errorf("index = %v, want empty after forced delete", indexNames(t))
	}
	if cfg.DefaultIdentity != "" {
		t.Errorf("default = %q, want cleared", cfg.DefaultIdentity)
	}
}

func TestHandoffAndDelete_DefaultRequiresSuccessor(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "alice", "", &fakeHost{}, false)
	var sre *handoff.SuccessorRequiredError
	if !errors.As(err, &sre) {
		t.Fatalf("expected *SuccessorRequiredError, got %v", err)
	}
	if len(sre.Candidates) != 1 || sre.Candidates[0] != "bob" {
		t.Errorf("candidates = %v, want [bob]", sre.Candidates)
	}
	if !indexNames(t)["alice"] {
		t.Error("alice removed before a successor was chosen")
	}
}

func TestHandoffAndDelete_NonDefaultDeletes(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	cfg := defaultCfg("alice")
	h := &fakeHost{}
	if err := handoff.HandoffAndDelete(context.Background(), nil, cfg, "bob", "", h, false); err != nil {
		t.Fatalf("delete non-default: %v", err)
	}
	if len(h.cleared) != 1 || h.cleared[0].Name != "bob" {
		t.Errorf("cleared = %v, want [bob]", h.cleared)
	}
	// ClearKeys must receive the resolved index entry (backend/HW), not just a name.
	if h.cleared[0].Backend != identity.BackendFile {
		t.Errorf("ClearKeys got backend %q, want %q from the resolved entry", h.cleared[0].Backend, identity.BackendFile)
	}
	names := indexNames(t)
	if names["bob"] || !names["alice"] || len(names) != 1 {
		t.Errorf("index = %v, want only alice", names)
	}
	if cfg.DefaultIdentity != "alice" {
		t.Errorf("default changed to %q, want alice unchanged", cfg.DefaultIdentity)
	}
}

func TestHandoffAndDelete_DefaultWithSuccessor(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	cfg := defaultCfg("alice")
	h := &fakeHost{}
	if err := handoff.HandoffAndDelete(context.Background(), nil, cfg, "alice", "bob", h, false); err != nil {
		t.Fatalf("delete default with successor: %v", err)
	}
	if cfg.DefaultIdentity != "bob" {
		t.Errorf("default = %q, want bob", cfg.DefaultIdentity)
	}
	if len(h.cleared) != 1 || h.cleared[0].Name != "alice" {
		t.Errorf("cleared = %v, want [alice]", h.cleared)
	}
	names := indexNames(t)
	if names["alice"] || !names["bob"] || len(names) != 1 {
		t.Errorf("index = %v, want only bob", names)
	}
}

func TestHandoffAndDelete_InvalidSuccessor(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	if err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "alice", "alice", &fakeHost{}, false); err == nil {
		t.Error("expected error for successor == victim")
	}
	if err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "alice", "ghost", &fakeHost{}, false); err == nil {
		t.Error("expected error for unknown successor")
	}
	if !indexNames(t)["alice"] {
		t.Error("alice removed despite an invalid successor")
	}
}

func TestHandoffAndDelete_VictimNotFound(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	if err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "ghost", "", &fakeHost{}, false); err == nil {
		t.Error("expected error for a victim that doesn't exist")
	}
}

func TestHandoffAndDelete_UnlockGateBlocks(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	// bob is non-default, so the successor path is skipped and the delete goes
	// straight to the unlock gate. A victim that can't be unlocked aborts.
	h := &fakeHost{openErr: errors.New("no hardware key / wrong passphrase")}
	err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "bob", "", h, false)
	if err == nil {
		t.Fatal("expected delete to abort when the victim can't be unlocked")
	}
	if len(h.cleared) != 0 {
		t.Errorf("keys cleared despite the unlock gate failing: %v", h.cleared)
	}
	if !indexNames(t)["bob"] {
		t.Error("bob was removed from the index despite the unlock gate failing")
	}
}

func TestHandoffAndDelete_ForceDoesNotSkipUnlockGate(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	// Only identity + force bypasses the last-identity block, but the unlock gate
	// still applies — force must never be a hardware-key bypass.
	h := &fakeHost{openErr: errors.New("locked")}
	err := handoff.HandoffAndDelete(context.Background(), nil, defaultCfg("alice"), "alice", "", h, true)
	if err == nil {
		t.Fatal("expected forced delete to still require unlocking the victim")
	}
	if len(h.opened) == 0 {
		t.Error("the unlock gate was not invoked on a forced delete")
	}
	if len(h.cleared) != 0 || !indexNames(t)["alice"] {
		t.Error("forced delete proceeded despite the unlock gate failing")
	}
}

func TestSetDefault(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	seedIdentity(t, "bob")
	cfg := defaultCfg("alice")
	if err := handoff.SetDefault(context.Background(), nil, cfg, "bob", &fakeHost{}); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	if cfg.DefaultIdentity != "bob" {
		t.Errorf("default = %q, want bob", cfg.DefaultIdentity)
	}
	// Already the default → no-op, no error.
	if err := handoff.SetDefault(context.Background(), nil, cfg, "bob", &fakeHost{}); err != nil {
		t.Errorf("SetDefault(already-default): %v", err)
	}
	// Unknown identity → error.
	if err := handoff.SetDefault(context.Background(), nil, cfg, "ghost", &fakeHost{}); err == nil {
		t.Error("expected error setting default to an unknown identity")
	}
}

func TestRekeyDefaultAfterRotate_NilClientIsNoop(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	if err := handoff.RekeyDefaultAfterRotate(context.Background(), nil, defaultCfg("alice"), "alice", nil, &fakeHost{}); err != nil {
		t.Errorf("expected nil with c == nil, got %v", err)
	}
}

func TestRekeyDefault_NilClientIsNoop(t *testing.T) {
	useEnv(t, t.TempDir())
	seedIdentity(t, "alice")
	// c == nil → short-circuits before OpenIdentity; must not error.
	if err := handoff.RekeyDefault(context.Background(), nil, defaultCfg("alice"), &fakeHost{}); err != nil {
		t.Errorf("expected nil with c == nil, got %v", err)
	}
	// No default and no identities → also a benign no-op.
	useEnv(t, t.TempDir())
	if err := handoff.RekeyDefault(context.Background(), nil, defaultCfg(""), &fakeHost{}); err != nil {
		t.Errorf("expected nil with no default, got %v", err)
	}
}
