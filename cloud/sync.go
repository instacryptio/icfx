package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/profile"
)

// This file is the shared bidirectional sync engine used by every client
// (ic-cli, ic-app, later ic-agent) — ONE implementation of the three-way
// resource sync and the identities roaming orchestration. Clients supply
// storage via ResourceIO and keep their own presentation + version-map
// persistence.

// ResourceIO loads and applies the local copy of a synced resource.
type ResourceIO interface {
	Load(resource string) ([]byte, error)
	Apply(resource string, data []byte) error
}

// Sync outcome actions.
const (
	SyncPushedNew = "pushed-new"
	SyncPushed    = "pushed"
	SyncPulled    = "pulled"
	SyncUpToDate  = "up-to-date"
	SyncSynced    = "synced"  // pulled AND pushed in the same pass
	SyncSkipped   = "skipped" // could not run (no identity, locked, hardware tap needed)
)

// Sync outcome severities (SyncOutcome.Level) — a client colorizes/icons by
// this without re-deriving from Action.
const (
	SyncLevelInfo = "info"
	SyncLevelOK   = "ok"
	SyncLevelWarn = "warn"
)

// SyncOutcome describes what one resource sync did. Beyond the machine fields,
// it carries a neutral, ready-to-display Message and a Level so a thin client
// can render it directly (no per-client formatter); the library never bakes in
// terminal colors or UI widgets.
type SyncOutcome struct {
	Resource string `json:"resource"`
	Action   string `json:"action"` // one of the Sync* constants
	Version  int64  `json:"version"`
	// CloudWasNewer is set on a pull that overwrote local changes (the
	// last-writer-wins MVP behavior) — clients surface it as a warning.
	CloudWasNewer bool `json:"cloud_was_newer"`
	// Skipped reason, set when Action == SyncSkipped (e.g. "no local identity
	// yet", or a hardware-key tap marker the app retries on).
	Skipped string `json:"skipped,omitempty"`
	// Message is a neutral, human-readable summary the client can show as-is;
	// Level ("info"|"ok"|"warn") is the severity to render it at.
	Message string `json:"message"`
	Level   string `json:"level"`
}

// SyncResource performs the three-way sync for one self-lock resource
// (contacts/settings): local bytes vs cloud bytes vs the last synced version
// in versions. Equal → up to date; only-local-changed → push (a version
// conflict falls back to pulling); otherwise adopt the cloud copy
// (last-writer-wins for the MVP). versions is updated in place; the caller
// persists it.
func SyncResource(ctx context.Context, c *Client, u SelfCrypter, resource string, io ResourceIO, versions map[string]int64) (SyncOutcome, error) {
	localBytes, err := io.Load(resource)
	if err != nil {
		return SyncOutcome{}, err
	}

	cloudBytes, cloudVer, err := c.OpenBlob(ctx, u, resource)
	notFound := IsNotFound(err)
	if err != nil && !notFound {
		return SyncOutcome{}, err
	}
	if notFound {
		res, perr := c.SealBlob(ctx, u, resource, localBytes, 0)
		if perr != nil {
			return SyncOutcome{}, perr
		}
		versions[resource] = res.Version
		return SyncOutcome{Resource: resource, Action: SyncPushedNew, Version: res.Version}, nil
	}

	lastVer := versions[resource]
	switch {
	case bytes.Equal(localBytes, cloudBytes):
		versions[resource] = cloudVer
		return SyncOutcome{Resource: resource, Action: SyncUpToDate, Version: cloudVer}, nil
	case lastVer != 0 && cloudVer == lastVer:
		// Only the local copy changed since last sync → push it.
		res, perr := c.SealBlob(ctx, u, resource, localBytes, cloudVer)
		if IsConflict(perr) {
			return pullResource(ctx, c, u, resource, io, versions, true)
		}
		if perr != nil {
			return SyncOutcome{}, perr
		}
		versions[resource] = res.Version
		return SyncOutcome{Resource: resource, Action: SyncPushed, Version: res.Version}, nil
	default:
		// Cloud changed (or first sync on this device) → adopt it. Any local
		// changes are overwritten (last-writer-wins for the MVP).
		return applyPulled(resource, io, versions, cloudBytes, cloudVer, lastVer != 0)
	}
}

// SyncSettingsGated is SyncResource("settings") behind the cheap idle check:
// when the remote blob version matches the last-synced version AND the local
// settings bytes haven't changed since (lastDigest), the pass ends without
// downloading or decrypting anything. remote is the account's FetchSyncState
// result; lastDigest is updated in place and persisted by the caller.
func SyncSettingsGated(ctx context.Context, c *Client, u SelfCrypter, io ResourceIO, versions map[string]int64, lastDigest *string, remote ServerSyncState) (SyncOutcome, error) {
	localBytes, err := io.Load("settings")
	if err != nil {
		return SyncOutcome{}, err
	}
	cur := fmt.Sprintf("%x", sha256.Sum256(localBytes))
	snap := remote.Blob("settings")
	if snap.Version != 0 && snap.Version == versions["settings"] && cur == *lastDigest {
		return SyncOutcome{Resource: "settings", Action: SyncUpToDate, Version: snap.Version}, nil
	}
	out, err := SyncResource(ctx, c, u, "settings", io, versions)
	if err != nil {
		return out, err
	}
	// A pull may have rewritten the local settings; re-digest what's on disk.
	after, lerr := io.Load("settings")
	if lerr != nil {
		return out, lerr
	}
	*lastDigest = fmt.Sprintf("%x", sha256.Sum256(after))
	return out, nil
}

// pullResource re-fetches the latest cloud copy (used after a push conflict)
// and applies it locally.
func pullResource(ctx context.Context, c *Client, u SelfCrypter, resource string, io ResourceIO, versions map[string]int64, hadBaseline bool) (SyncOutcome, error) {
	cloudBytes, cloudVer, err := c.OpenBlob(ctx, u, resource)
	if err != nil {
		return SyncOutcome{}, err
	}
	return applyPulled(resource, io, versions, cloudBytes, cloudVer, hadBaseline)
}

func applyPulled(resource string, io ResourceIO, versions map[string]int64, cloudBytes []byte, cloudVer int64, hadBaseline bool) (SyncOutcome, error) {
	if err := io.Apply(resource, cloudBytes); err != nil {
		return SyncOutcome{}, err
	}
	versions[resource] = cloudVer
	return SyncOutcome{Resource: resource, Action: SyncPulled, Version: cloudVer, CloudWasNewer: hadBaseline}, nil
}

// IdentitiesSyncState is the persisted convergence record for identity
// roaming: the cloud blob version this device last saw and the local set's
// RoamingDigest at that moment. Together they let a sync pass decide
// pull/push/nothing without downloading or re-encrypting anything.
type IdentitiesSyncState struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}

// SyncIdentities converges the identity keys with the cloud, statefully:
//
//	remote version moved  → pull (merge cloud keys into local)
//	local digest changed  → push (upload the local set)
//	neither               → up-to-date: NO network, NO crypto, NO prompts
//
// A pull alone does NOT push back — that symmetry is what killed devices
// ringing their own doorbell forever. remote is the "identities" entry from
// FetchSyncState. st is updated in place; the caller persists it. A cloud
// blob in an older, unimportable roaming format is reported via onOldFormat
// (may be nil) and replaced by a push. Returns the action taken:
// up-to-date | pulled | pushed | pushed-new | synced (pull+push).
func SyncIdentities(ctx context.Context, c *Client, exportFn profile.IdentityExportFn, importFn profile.IdentityImportFn, st *IdentitiesSyncState, remote ServerBlobMeta, onOldFormat func()) (string, error) {
	localDigest, err := profile.RoamingDigest(exportFn)
	if err != nil {
		return "", err
	}

	remoteMoved := remote.Version != st.Version
	localChanged := localDigest != st.Digest

	if !remoteMoved && !localChanged {
		return SyncUpToDate, nil
	}

	// Nothing in the cloud yet → first push.
	if remote.Version == 0 {
		ver, err := c.pushIdentitiesVersioned(ctx, exportFn)
		if err != nil {
			return "", err
		}
		st.Version, st.Digest = ver, localDigest
		return SyncPushedNew, nil
	}

	pulled := false
	if remoteMoved {
		ver, perr := c.pullIdentitiesVersioned(ctx, importFn)
		switch {
		case perr == nil:
			pulled = true
			st.Version = ver
		case errors.Is(perr, profile.ErrUnsupportedRoamingVersion):
			// Old-format blob: nothing to merge; the push below replaces it.
			if onOldFormat != nil {
				onOldFormat()
			}
			st.Version = ver
			localChanged = true
		default:
			return "", perr
		}
		// The merge may have changed the local set; re-digest for the record
		// (and for the push decision when local had ALSO changed).
		localDigest, err = profile.RoamingDigest(exportFn)
		if err != nil {
			return "", err
		}
	}

	if !localChanged {
		// Pull-only pass: record the post-merge digest and stop. The cloud
		// already contains everything it sent us; pushing back would only
		// ring every device's doorbell again.
		st.Digest = localDigest
		return SyncPulled, nil
	}

	ver, err := c.pushIdentitiesVersioned(ctx, exportFn)
	if err != nil {
		return "", err
	}
	st.Version, st.Digest = ver, localDigest
	if pulled {
		return SyncSynced, nil
	}
	return SyncPushed, nil
}

// ConfigResourceIO is the standard ResourceIO over the icfx config + contacts
// stores — the one serialization every client uses, so contacts and settings
// blobs are byte-identical across ic-cli and ic-app.
func ConfigResourceIO(cfg *config.Config) ResourceIO {
	return configResourceIO{cfg: cfg}
}

type configResourceIO struct{ cfg *config.Config }

func (io configResourceIO) Load(resource string) ([]byte, error) {
	switch resource {
	case "contacts":
		store, err := contacts.NewStore()
		if err != nil {
			return nil, err
		}
		list, err := store.Load()
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)
	case "settings":
		return json.Marshal(SyncableSettings(io.cfg))
	default:
		return nil, fmt.Errorf("unknown resource %q", resource)
	}
}

func (io configResourceIO) Apply(resource string, data []byte) error {
	switch resource {
	case "contacts":
		var list []contacts.Contact
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("parsing synced contacts: %w", err)
		}
		store, err := contacts.NewStore()
		if err != nil {
			return err
		}
		return store.Save(list)
	case "settings":
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("parsing synced settings: %w", err)
		}
		for k, v := range m {
			io.cfg.Set(k, v) // unknown/invalid keys are ignored by Set
		}
		return io.cfg.Save()
	default:
		return fmt.Errorf("unknown resource %q", resource)
	}
}

// SyncableSettings is the device-agnostic subset of settings that roams.
// Device-specific settings (paths, keystore, default identity, cloud flags)
// are deliberately excluded.
func SyncableSettings(cfg *config.Config) map[string]string {
	return map[string]string{
		"default_format":    cfg.DefaultFormat,
		"verbose":           strconv.FormatBool(cfg.Verbose),
		"banner":            strconv.FormatBool(cfg.Banner),
		"auto_lock_minutes": strconv.Itoa(cfg.AutoLockMinutes),
	}
}
