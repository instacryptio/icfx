package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/profile"
)

// This file is the SHARED cloud-sync flow. The library owns the sequence —
// refresh, fetch state, roam identities, sync the self-lock resources, drain
// the pending inbox, and persist the session — so ic-cli, ic-app, and ic-agent
// don't each re-implement it. Everything platform- or UI-specific is injected
// through SyncHost; everything the library can do itself, it does.

// ResourceSelection is which blobs a sync run touches (read from config by the
// host: CloudSyncContacts / Settings / Identities).
type ResourceSelection struct {
	Contacts   bool
	Settings   bool
	Identities bool
	// Notifications syncs the drawer's read/dismiss/content state (a self-lock
	// CRDT blob). Only clients with a notification drawer (ic-app) enable it; a
	// host that enables it must return a non-nil NotificationStore.
	Notifications bool
	// Groups syncs contact groups (name + member contact IDs) as a self-lock
	// CRDT blob. A host that enables it must return a usable GroupStore.
	Groups bool
}

// SyncOptions tunes a run.
type SyncOptions struct {
	// Background is informational: the library no longer skips interactive steps
	// on background runs (it always calls EstablishEncKey / OpenDefaultIdentity
	// and returns pendings). The flag is passed so the CLIENT can choose how to
	// SURFACE a required step — a foreground modal vs a persistent background
	// notification — and so a truly-headless host (ic-agent) can self-skip in
	// its own callbacks. It never silences the gates.
	Background bool
	// ApproveDefaultChange pre-authorizes the default-identity change surfaced by
	// a prior run's *DefaultChangePending (matched by Kind + Incoming).
	ApproveDefaultChange *DefaultChangeApproval
	// ApproveReseal pre-authorizes re-sealing the named orphaned resources from a
	// prior run's *ResealPending. Nil/false = don't reseal (surface again).
	ApproveReseal map[string]bool
}

// ChallengePending is returned by RunSync when re-establishing the account
// encryption key needs a second factor the host can't satisfy inline (the
// app's asynchronous 2FA). The host completes the challenge out of band, then
// calls RunSync again — persisted tokens and positions make the retry
// idempotent.
type ChallengePending struct {
	Factor    string `json:"factor"` // "totp" | "email" | "webauthn"
	TempToken string `json:"temp_token"`
	WebAuthn  []byte `json:"webauthn,omitempty"` // assertion options when Factor=="webauthn"
}

func (e *ChallengePending) Error() string {
	return "cloud: second factor required to unlock identity sync"
}

// DefaultChangePending is returned by RunSync when a sync-down would change this
// device's default identity — the account default POINTER moved (Kind "pointer")
// or the current default identity's KEYS changed via the roam (Kind "key": a
// rotation / key-swap). The host must get the user's approval (foreground modal
// or a persistent background notification) and call RunSync again with
// SyncOptions.ApproveDefaultChange. It is NEVER applied silently — the guard
// against a compromised account key silently swapping your default everywhere.
type DefaultChangePending struct {
	Kind     string `json:"kind"` // "pointer" | "key"
	Current  string `json:"current"`
	Incoming string `json:"incoming"`
}

func (e *DefaultChangePending) Error() string {
	return fmt.Sprintf("cloud: default identity %s change requires confirmation", e.Kind)
}

// ResealPending is returned by RunSync when self-lock resources on the server are
// sealed to a superseded key (orphaned) and can be recovered by re-sealing from
// local plaintext under the current default. Re-sealing OVERWRITES the cloud
// copy, so it needs the user's approval: call RunSync again with
// SyncOptions.ApproveReseal set for the listed resources. Never automatic.
type ResealPending struct {
	Resources []string `json:"resources"`
}

func (e *ResealPending) Error() string {
	return "cloud: reseal confirmation required for " + strings.Join(e.Resources, ", ")
}

// DefaultChangeApproval pre-authorizes one specific default-identity change for a
// single RunSync call (must match that run's detected Kind + Incoming).
type DefaultChangeApproval struct {
	Kind     string
	Incoming string
}

// ErrNoDefaultIdentity tells RunSync to skip the self-lock resources
// (contacts/settings) gracefully — a fresh device with no identity yet — rather
// than failing the whole run. OpenDefaultIdentity returns it.
var ErrNoDefaultIdentity = errors.New("cloud: no default identity to unlock")

// SyncHost supplies the platform- and UI-specific pieces of a sync run; the
// library owns the sequence. Every identity handle the host opens
// (OpenDefaultIdentity / OpenByFingerprint) is owned and CLOSED BY THE HOST
// after RunSync returns — SelfCrypter is intentionally close-less, and reuse
// across the run (an "opened" cache) is the host's concern. Implemented by
// ic-cli (TTY), ic-app (flugo bridge), and ic-agent (daemon).
type SyncHost interface {
	// Resources reports which blobs to sync this run.
	Resources() ResourceSelection

	// --- identities (roam under the account encryption key) ---

	// RoamingExport / RoamingImport are the identity transport callbacks passed
	// to SyncIdentities.
	RoamingExport() profile.IdentityExportFn
	RoamingImport() profile.IdentityImportFn
	// OnOldFormat is called (if non-nil) when the cloud identities blob is an
	// older format being replaced by this device's copy.
	OnOldFormat()
	// EstablishEncKey re-derives the account encryption key when the stored one
	// is missing or stale (the password changed on another device). Complete a
	// fresh login and return nil, or return a *ChallengePending for async 2FA.
	// Always called now (even on background runs) — the host surfaces the need
	// persistently rather than the library silently skipping; a headless host
	// with no user present returns an error to self-skip.
	EstablishEncKey(ctx context.Context) error

	// AdoptDefaultIdentity persists name as this device's default identity AND
	// invalidates any cached opened default, so a subsequent OpenDefaultIdentity
	// (same run) opens name. Called only after the user approved a default change
	// (via SyncOptions.ApproveDefaultChange) — it is an effect hook, never a
	// dialog.
	AdoptDefaultIdentity(ctx context.Context, name string) error

	// --- self-lock resources (contacts, settings) ---

	// OpenDefaultIdentity unlocks the default identity the self-lock blobs are
	// sealed to. Return ErrNoDefaultIdentity to skip them; any other error is
	// recorded as a per-resource Skipped outcome (e.g. a mobile hardware-key
	// tap the host resolves before retrying).
	OpenDefaultIdentity(ctx context.Context) (SelfCrypter, error)
	// ResourceIO reads/writes the settings resource (cloud.ConfigResourceIO(cfg)).
	ResourceIO() ResourceIO
	// NotificationStore is the drawer store to converge when
	// Resources().Notifications is set (synced under the same open default
	// identity, so no extra hardware-key tap). Return nil to opt out.
	NotificationStore() *NotificationStore

	// GroupStore is the contact-groups store to converge when Resources().Groups
	// is set (synced under the same open default identity, no extra tap).
	GroupStore() (*groups.Store, error)

	// --- pending inbox drain ---

	// ContactStore is where drained acceptances / rotations / revocations land.
	ContactStore() (*contacts.Store, error)
	// OpenByFingerprint resolves the local identity for a pending item's routing
	// fingerprint (empty = default). Cache internally; the host closes them.
	OpenByFingerprint(ctx context.Context, fp string) (SelfCrypter, error)
}

// SyncResult is what RunSync produced: per-resource outcomes (each with a
// ready-to-render Message + Level) and the structured pending-drain summary.
// JSON-tagged so ic-app returns it straight over the flugo bridge.
type SyncResult struct {
	Outcomes []SyncOutcome `json:"outcomes"`
	Pending  DrainReport   `json:"pending"`
}

// RunSync runs the shared cloud-sync sequence for the selected resources and
// persists the session (tokens automatically via SetTokens; sync positions via
// the wired SessionStore). It refreshes a stale access token first. Per-resource
// problems are recorded as SyncSkipped outcomes rather than failing the whole
// run; a whole-run failure (or *ChallengePending, meaning "resolve 2FA and call
// again") is returned as the error. Requires a SessionStore (SetSessionStore)
// and an account email (login or RestoreSession).
func (c *Client) RunSync(ctx context.Context, host SyncHost, opts SyncOptions) (SyncResult, error) {
	store := c.SessionStore()
	if store == nil {
		return SyncResult{}, errors.New("cloud: RunSync needs a SessionStore (call SetSessionStore)")
	}
	email := c.accountEmail()
	if email == "" {
		return SyncResult{}, errors.New("cloud: RunSync needs an account (log in or RestoreSession first)")
	}

	// Refresh a stale access token up front; SetTokens persists the rotation.
	if !c.TokenValidFor(30 * time.Second) {
		if err := c.Refresh(ctx); err != nil {
			return SyncResult{}, err
		}
	}

	pos, err := store.LoadPositions(email)
	if err != nil {
		return SyncResult{}, fmt.Errorf("load sync positions: %w", err)
	}
	if pos.Versions == nil {
		pos.Versions = map[string]int64{}
	}

	// One state GET drives every per-resource decision below.
	state, err := c.FetchSyncState(ctx)
	if err != nil {
		return SyncResult{}, fmt.Errorf("fetch sync state: %w", err)
	}

	sel := host.Resources()
	var res SyncResult

	// Identities first: on a fresh device the keys must roam down before the
	// self-lock resources (sealed to the default identity) can sync.
	if sel.Identities {
		outs, cerr := c.runIdentities(ctx, host, &pos, state, opts)
		if cerr != nil {
			var chal *ChallengePending
			var dcp *DefaultChangePending
			switch {
			case errors.As(cerr, &chal):
				// Persist whatever positions moved before bailing for 2FA.
				_ = store.SavePositions(email, pos)
				return res, chal
			case errors.As(cerr, &dcp):
				// The roam outcome (if any) is in outs; surface it, persist, bail
				// for the user to approve the default change.
				res.Outcomes = append(res.Outcomes, outs...)
				_ = store.SavePositions(email, pos)
				return res, dcp
			default:
				outs = []SyncOutcome{skippedOutcome("identities", cerr.Error())}
			}
		}
		res.Outcomes = append(res.Outcomes, outs...)
	}

	// Self-lock resources share one unlock of the default identity.
	if sel.Contacts || sel.Settings {
		outs, rp := c.runSelfLock(ctx, host, &pos, state, sel, opts)
		res.Outcomes = append(res.Outcomes, outs...)
		if rp != nil {
			_ = store.SavePositions(email, pos)
			return res, rp // caller approves the reseal(s) and re-runs
		}
	}

	// Pending inbox drain (best-effort; never sinks the run).
	if cstore, derr := host.ContactStore(); derr == nil {
		rep, perr := DrainPending(ctx, c, cstore, func(fp string) (SelfCrypter, error) {
			return host.OpenByFingerprint(ctx, fp)
		})
		if perr == nil {
			res.Pending = rep
		}
	}

	if err := store.SavePositions(email, pos); err != nil {
		return res, fmt.Errorf("persist sync positions: %w", err)
	}
	return res, nil
}

// runIdentities roams the identity keys, re-establishing the account encKey via
// the host if the stored one is missing/stale (unless Background).
func (c *Client) runIdentities(ctx context.Context, host SyncHost, pos *SyncPositions, state ServerSyncState, opts SyncOptions) ([]SyncOutcome, error) {
	remote := state.Blob("identities")

	// Gate (b): a KEY-SWAP of this device's current default must be confirmed
	// BEFORE the roam overwrites the old key. Best-effort (skips if it can't
	// peek); never blocks unrelated roams silently.
	if pending := c.defaultKeySwapGate(ctx, remote, opts); pending != nil {
		return nil, pending
	}

	action, err := SyncIdentities(ctx, c, host.RoamingExport(), host.RoamingImport(), &pos.Identities, remote, host.OnOldFormat)
	if err != nil && (errors.Is(err, ErrEncKeyMissing) || errors.Is(err, ErrEncKeyStale)) {
		// Always surface the auth need (no background skip): the host decides
		// modal vs persistent; a headless host self-skips by returning an error.
		if eerr := host.EstablishEncKey(ctx); eerr != nil {
			return nil, eerr // includes *ChallengePending
		}
		action, err = SyncIdentities(ctx, c, host.RoamingExport(), host.RoamingImport(), &pos.Identities, remote, host.OnOldFormat)
	}
	if err != nil {
		return nil, err
	}
	o := SyncOutcome{Resource: "identities", Action: action, Version: pos.Identities.Version}
	fillMessage(&o)
	outs := []SyncOutcome{o}

	// Gate (a): adopt a changed default POINTER (post-roam, so the successor's
	// keys are present locally). AdoptDefaultIdentity persists it before the
	// self-lock resources open the default this run.
	adopted, pending, aerr := c.maybeAdoptDefault(ctx, host, opts)
	if aerr != nil {
		outs[0].Message += " (default adoption deferred: " + aerr.Error() + ")"
		return outs, nil
	}
	if pending != nil {
		return outs, pending
	}
	if adopted != "" {
		outs[0].Message += " — adopted new default: " + adopted
	}
	return outs, nil
}

// defaultKeySwapGate returns a *DefaultChangePending{Kind:"key"} when the roaming
// blob would change the CURRENT default identity's keys (fingerprint mismatch)
// and the change isn't pre-approved — blocking the roam before it overwrites the
// old key. Best-effort: returns nil (proceed) if it can't peek (no blob / no
// account key / legacy entry without a fingerprint).
func (c *Client) defaultKeySwapGate(ctx context.Context, remote ServerBlobMeta, opts SyncOptions) *DefaultChangePending {
	if remote.Version == 0 {
		return nil
	}
	cfg, err := config.Load()
	if err != nil || cfg.DefaultIdentity == "" {
		return nil
	}
	def := cfg.DefaultIdentity
	localFP := localIndexFingerprint(def)
	if localFP == "" {
		return nil // legacy entry — can't compare (repopulated on create/rotate)
	}
	m, ok := c.peekRoamingManifest(ctx)
	if !ok {
		return nil
	}
	incomingFP := manifestFingerprint(m, def)
	if incomingFP == "" || incomingFP == localFP {
		return nil // default absent from the incoming manifest, or unchanged
	}
	if a := opts.ApproveDefaultChange; a != nil && a.Kind == "key" && a.Incoming == def {
		return nil // approved — let the roam apply the new key
	}
	return &DefaultChangePending{Kind: "key", Current: def, Incoming: def}
}

// maybeAdoptDefault handles gate (a): if the roaming manifest names a different
// account default than this device's and that identity now exists locally, adopt
// it (on approval) so runSelfLock opens it the same run.
func (c *Client) maybeAdoptDefault(ctx context.Context, host SyncHost, opts SyncOptions) (adopted string, pending *DefaultChangePending, err error) {
	m, ok := c.peekRoamingManifest(ctx)
	if !ok || m.DefaultIdentity == "" {
		return "", nil, nil
	}
	cfg, cerr := config.Load()
	if cerr != nil {
		return "", nil, cerr
	}
	if m.DefaultIdentity == cfg.DefaultIdentity {
		return "", nil, nil // converged
	}
	if !localIdentityExists(m.DefaultIdentity) {
		return "", nil, nil // successor not roamed to this device yet
	}
	if a := opts.ApproveDefaultChange; a != nil && a.Kind == "pointer" && a.Incoming == m.DefaultIdentity {
		if aerr := host.AdoptDefaultIdentity(ctx, m.DefaultIdentity); aerr != nil {
			return "", nil, aerr
		}
		return m.DefaultIdentity, nil, nil
	}
	return "", &DefaultChangePending{Kind: "pointer", Current: cfg.DefaultIdentity, Incoming: m.DefaultIdentity}, nil
}

// peekRoamingManifest fetches + decrypts the identities blob's manifest (default
// pointer + per-identity fingerprints) with no key import. ok=false when there's
// no account key or no blob (both benign — the gates then no-op).
func (c *Client) peekRoamingManifest(ctx context.Context) (profile.Manifest, bool) {
	encKey, _, kerr := c.sessionOrStoredEncKey()
	if kerr != nil {
		return profile.Manifest{}, false
	}
	b, gerr := c.GetBlob(ctx, "identities")
	if gerr != nil {
		return profile.Manifest{}, false
	}
	m, perr := profile.PeekRoamingManifest(b.Ciphertext, encKeyPassphrase(encKey))
	if perr != nil {
		return profile.Manifest{}, false
	}
	return m, true
}

func localIndexFingerprint(name string) string {
	st, err := identity.NewStore()
	if err != nil {
		return ""
	}
	entries, err := st.LoadIndex()
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.Name == name {
			return e.Fingerprint
		}
	}
	return ""
}

func localIdentityExists(name string) bool {
	st, err := identity.NewStore()
	if err != nil {
		return false
	}
	entries, err := st.LoadIndex()
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

func manifestFingerprint(m profile.Manifest, name string) string {
	for _, mi := range m.Identities {
		if mi.Name == name {
			return mi.Fingerprint
		}
	}
	return ""
}

// runSelfLock unlocks the default identity once and syncs the enabled self-lock
// resources under it. A missing default identity skips them gracefully; any
// other unlock error records both as Skipped (the host may resolve and retry).
func (c *Client) runSelfLock(ctx context.Context, host SyncHost, pos *SyncPositions, state ServerSyncState, sel ResourceSelection, opts SyncOptions) ([]SyncOutcome, *ResealPending) {
	notifStore := host.NotificationStore()
	var names []string
	if sel.Contacts {
		names = append(names, "contacts")
	}
	if sel.Groups {
		names = append(names, "groups")
	}
	if sel.Settings {
		names = append(names, "settings")
	}
	if sel.Notifications && notifStore != nil {
		names = append(names, "notifications")
	}

	u, err := host.OpenDefaultIdentity(ctx)
	if err != nil {
		reason := err.Error()
		if errors.Is(err, ErrNoDefaultIdentity) {
			reason = "no local identity yet (enable identity sync, or create/import one)"
		}
		out := make([]SyncOutcome, 0, len(names))
		for _, n := range names {
			out = append(out, skippedOutcome(n, reason))
		}
		return out, nil
	}

	io := host.ResourceIO()
	out := make([]SyncOutcome, 0, len(names))
	var needReseal []string
	for _, n := range names {
		var o SyncOutcome
		var serr error
		switch n {
		case "contacts":
			o, serr = SyncContactsOps(ctx, c, u, &pos.Contacts, state)
		case "groups":
			var gstore *groups.Store
			if gstore, serr = host.GroupStore(); serr == nil {
				o, serr = syncGroupsBlob(ctx, c, u, gstore)
			}
		case "notifications":
			serr = notifStore.Sync(ctx, c, u)
			o = SyncOutcome{Resource: "notifications", Action: SyncSynced, Message: "Notifications: synced", Level: SyncLevelOK}
		default:
			o, serr = SyncSettingsGated(ctx, c, u, io, pos.Versions, &pos.SettingsDigest, state)
		}
		if serr != nil {
			// Recovery: a resource sealed to a superseded key (orphaned) can be
			// re-sealed from local plaintext — but only with the user's OK (it
			// overwrites the cloud copy). Never automatic, and never from a device
			// that lacks the data (recoverOrphan guards against wiping the cloud).
			if isRecipientMismatch(serr) {
				out = append(out, c.recoverOrphan(ctx, host, io, u, n, state, pos, opts, &needReseal))
				continue
			}
			out = append(out, skippedOutcome(n, serr.Error()))
			continue
		}
		if n != "notifications" && n != "groups" {
			fillMessage(&o) // notifications/groups carry no version; message set above
		}
		out = append(out, o)
	}

	// Full-coverage recovery: catch orphaned self-lock blobs for resources NOT in
	// this run's selection, reusing the already-open default identity (no extra
	// unlock/tap). This stops a deselected resource (e.g. settings off, or groups
	// riding the contacts flag) from stranding a superseded-key cloud blob that
	// re-appears on the next device. A deselected resource that opens cleanly is
	// left untouched — its sync opt-out is respected; only orphans are surfaced.
	//
	// Foreground only: probing a deselected resource costs a GET + decrypt per
	// resource, and a straggler it finds raises a ResealPending. Running that on
	// the frequent background auto-syncs (timer + every push) would be wasted work
	// AND would nag with a persistent notification about a resource you turned off.
	// A manual "Sync Now" (or the "Re-key Cloud Data" action) still runs the full
	// check and recovers any stragglers.
	for _, n := range selfLockResources {
		if opts.Background {
			break
		}
		if containsStr(names, n) {
			continue
		}
		if n == "notifications" && notifStore == nil {
			continue
		}
		if !c.probeOrphan(ctx, u, n, state) {
			continue
		}
		out = append(out, c.recoverOrphan(ctx, host, io, u, n, state, pos, opts, &needReseal))
	}

	if len(needReseal) > 0 {
		return out, &ResealPending{Resources: needReseal}
	}
	return out, nil
}

// selfLockResources is the full set of self-lock blobs (all sealed to the
// default identity's EncPubKey), in a stable order for full-coverage recovery.
var selfLockResources = []string{"contacts", "groups", "settings", "notifications"}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// probeOrphan reports whether the cloud copy of a self-lock resource EXISTS but
// can't be opened by u because it's sealed to a superseded key (recipient
// mismatch). Read-only: it never mutates local or cloud state. false when the
// blob is absent, opens cleanly, or fails for any non-recipient reason.
func (c *Client) probeOrphan(ctx context.Context, u SelfCrypter, name string, state ServerSyncState) bool {
	if state.Blob(name).Version == 0 && state.MaxSeq(name) == 0 {
		return false // nothing in the cloud for this resource
	}
	_, _, err := c.OpenBlob(ctx, u, name)
	return isRecipientMismatch(err)
}

// canRecoverLocally reports whether this device holds authoritative local data
// for an orphaned resource — the gate that stops "recover" from overwriting the
// cloud copy with an empty/default source (see ErrNoLocalToRecover).
//
// Settings has no empty state (always a full value), so content can't tell a
// fresh device's defaults from an authoritative copy; instead it's authoritative
// only once this device has actually synced settings (pos.SettingsDigest set).
// This keeps a never-synced device from being nagged to reseal settings — it
// shows the non-destructive "recover elsewhere" line instead.
func canRecoverLocally(name string, host SyncHost, io ResourceIO, pos *SyncPositions) bool {
	if name == "settings" {
		return pos != nil && pos.SettingsDigest != ""
	}
	var local []byte
	var err error
	switch name {
	case "contacts":
		local, err = io.Load(name)
	case "groups":
		g, gerr := host.GroupStore()
		if gerr != nil {
			return false
		}
		local, err = g.SyncBytes()
	case "notifications":
		ns := host.NotificationStore()
		if ns == nil {
			return false
		}
		local, err = ns.SealSource()
	default:
		return false
	}
	if err != nil {
		return false
	}
	return localSourceHasData(name, local)
}

// recoverOrphan decides what to do with an orphaned self-lock resource n: if this
// device has no local data to recover from, record a non-destructive "recover
// from your other device" outcome (never wipe the cloud); if the user hasn't
// approved a reseal yet, queue it for approval; otherwise reseal now. It reuses
// the already-open default identity u.
func (c *Client) recoverOrphan(ctx context.Context, host SyncHost, io ResourceIO, u SelfCrypter, n string, state ServerSyncState, pos *SyncPositions, opts SyncOptions, needReseal *[]string) SyncOutcome {
	if !canRecoverLocally(n, host, io, pos) {
		return unrecoverableOutcome(n)
	}
	if !opts.ApproveReseal[n] {
		*needReseal = append(*needReseal, n)
		return skippedOutcome(n, "sealed to a superseded key — approve re-seal to recover")
	}
	if rerr := c.resealOne(ctx, u, n, host, io, pos, state); rerr != nil {
		if errors.Is(rerr, ErrNoLocalToRecover) {
			return unrecoverableOutcome(n)
		}
		return skippedOutcome(n, rerr.Error())
	}
	return resealedOutcome(n, pos)
}

// unrecoverableOutcome is the non-destructive outcome for an orphaned resource
// whose sealing key isn't on this device and which has no local copy to re-seal
// from — so it must be recovered from the device that holds the original data,
// NOT overwritten here.
func unrecoverableOutcome(resource string) SyncOutcome {
	reason := "sealed to a key that isn't on this device — recover it from the device that has the original data"
	return SyncOutcome{
		Resource: resource,
		Action:   SyncSkipped,
		Skipped:  reason,
		Message:  fmt.Sprintf("%s: %s", titleResource(resource), reason),
		Level:    SyncLevelWarn,
	}
}

// skippedOutcome builds a uniform "couldn't run this resource" outcome.
func skippedOutcome(resource, reason string) SyncOutcome {
	return SyncOutcome{
		Resource: resource,
		Action:   SyncSkipped,
		Skipped:  reason,
		Message:  fmt.Sprintf("%s: skipped — %s", titleResource(resource), reason),
		Level:    SyncLevelWarn,
	}
}

// fillMessage composes the neutral display Message + Level from the machine
// fields, so a thin client can render it directly.
func fillMessage(o *SyncOutcome) {
	name := titleResource(o.Resource)
	switch o.Action {
	case SyncPushedNew:
		o.Message, o.Level = fmt.Sprintf("%s: pushed (new, v%d)", name, o.Version), SyncLevelOK
	case SyncPushed:
		o.Message, o.Level = fmt.Sprintf("%s: pushed (v%d)", name, o.Version), SyncLevelOK
	case SyncSynced:
		o.Message, o.Level = fmt.Sprintf("%s: synced (v%d)", name, o.Version), SyncLevelOK
	case SyncUpToDate:
		o.Message, o.Level = fmt.Sprintf("%s: up to date (v%d)", name, o.Version), SyncLevelInfo
	case SyncPulled:
		o.Message, o.Level = fmt.Sprintf("%s: pulled (v%d)", name, o.Version), SyncLevelOK
		if o.CloudWasNewer {
			o.Message = fmt.Sprintf("%s: pulled (v%d) — cloud was newer, local changes overwritten", name, o.Version)
			o.Level = SyncLevelWarn
		}
	default:
		o.Message, o.Level = fmt.Sprintf("%s: %s (v%d)", name, o.Action, o.Version), SyncLevelInfo
	}
}

// syncGroupsBlob converges this device's contact groups with the account's
// encrypted groups blob (zero-knowledge, sealed to the caller's own lock) via
// the whole-blob CRDT MergeGroups. Model of NotificationStore.Sync.
func syncGroupsBlob(ctx context.Context, c *Client, u SelfCrypter, store *groups.Store) (SyncOutcome, error) {
	local, err := store.SyncBytes()
	if err != nil {
		return SyncOutcome{}, err
	}
	merged, err := c.SyncMergedBlob(ctx, u, "groups", local, groups.MergeGroups)
	if err != nil {
		return SyncOutcome{}, err
	}
	if err := store.ApplyMerged(merged); err != nil {
		return SyncOutcome{}, err
	}
	return SyncOutcome{Resource: "groups", Action: SyncSynced, Message: "Groups: synced", Level: SyncLevelOK}, nil
}

func titleResource(r string) string {
	switch r {
	case "contacts":
		return "Contacts"
	case "groups":
		return "Groups"
	case "settings":
		return "Settings"
	case "identities":
		return "Identities"
	case "notifications":
		return "Notifications"
	default:
		return r
	}
}

// isRecipientMismatch reports whether err is age's "sealed to a different
// recipient" failure — the signal that a self-lock blob is orphaned (its
// recipient key was superseded by a hand-off/rotation).
func isRecipientMismatch(err error) bool {
	var nim *age.NoIdentityMatchError
	return errors.As(err, &nim) || errors.Is(err, age.ErrIncorrectIdentity)
}

// resealOne re-seals a single orphaned self-lock resource from its local
// plaintext under the current default u (force-overwriting the cloud copy).
func (c *Client) resealOne(ctx context.Context, u SelfCrypter, name string, host SyncHost, io ResourceIO, pos *SyncPositions, state ServerSyncState) error {
	switch name {
	case "settings":
		return resealFromLocal(ctx, c, u, "settings", func() ([]byte, error) { return io.Load("settings") }, state, pos.Versions)
	case "groups":
		gstore, err := host.GroupStore()
		if err != nil {
			return err
		}
		return resealFromLocal(ctx, c, u, "groups", gstore.SyncBytes, state, pos.Versions)
	case "notifications":
		nstore := host.NotificationStore()
		if nstore == nil {
			return fmt.Errorf("no notification store")
		}
		return resealFromLocal(ctx, c, u, "notifications", nstore.SealSource, state, pos.Versions)
	case "contacts":
		return resealContacts(ctx, c, u, io, state, pos)
	}
	return fmt.Errorf("cannot reseal unknown resource %q", name)
}

// resealedOutcome is the neutral outcome for a resource recovered by re-sealing.
func resealedOutcome(resource string, pos *SyncPositions) SyncOutcome {
	v := pos.Versions[resource]
	if resource == "contacts" {
		v = pos.Contacts.SnapshotVersion
	}
	return SyncOutcome{
		Resource: resource,
		Action:   SyncSynced,
		Version:  v,
		Message:  fmt.Sprintf("%s: re-sealed to current identity (v%d)", titleResource(resource), v),
		Level:    SyncLevelOK,
	}
}
