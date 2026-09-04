package profile

import (
	"time"

	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
)

// bundleVersion is the on-wire format version embedded in manifest.json.
// Bumped whenever the tarball entry layout or per-identity bundle format
// changes incompatibly. Import refuses to read versions it doesn't
// recognize.
const bundleVersion = 1

// Manifest is the metadata blob at the top of every profile bundle. It's
// the first thing Import decodes; if the manifest is unreadable (e.g. wrong
// passphrase), Import returns the underlying decrypt error before touching
// any local state. If the version is unrecognized, Import refuses with a
// clear error.
//
// Manifest is also useful for the Dart-side preview: PeekManifest returns
// it without doing any destructive operations, letting the UI show
// "this backup contains N identities (M HW-protected) and K contacts"
// before asking the user to confirm.
type Manifest struct {
	Version      int                `json:"version"`
	ExportedAt   time.Time          `json:"exported_at"`
	Identities   []ManifestIdentity `json:"identities"`
	ContactCount int                `json:"contact_count"`
	// DefaultIdentity is the account default this device chose, carried on the
	// identities roaming blob so other devices converge on a hand-off/rotation
	// successor (adopted behind the ConfirmDefaultChange gate). Empty on legacy
	// blobs / the profile tarball manifest.
	DefaultIdentity string `json:"default_identity,omitempty"`
}

// ManifestIdentity is the per-identity summary in the manifest. Carries
// the name (so a preview UI can list them) and the HW flag (so the UI
// can decide whether to surface a "preserve HW" prompt). Protection is set
// only by the identity-roaming bundle (empty for full-profile backups).
type ManifestIdentity struct {
	Name       string            `json:"name"`
	HWKey      bool              `json:"hw_key"`
	Protection RoamingProtection `json:"protection,omitempty"`
	// HWKEK carries the hardware-key KEK passphrase convention of the origin
	// device (identity.HWKEKNone / HWKEKPassphrase) — the ciphertext travels
	// verbatim, so its convention must travel with it regardless of which
	// backend the destination stores it in. Empty on pre-HWKEK bundles.
	HWKEK string `json:"hw_kek,omitempty"`
	// Fingerprint is the identity's public fingerprint, carried so a receiving
	// device can detect a default-identity key-swap pre-import (anti-takeover
	// gate) without unlocking. Empty on legacy bundles.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// RoamingProtection classifies how an identity's key material is protected in a
// roaming bundle — which determines whether it travels as-is (already encrypted
// at rest) or leans on the bundle's outer cloud-key wrap.
type RoamingProtection string

const (
	// ProtectionPassphrase: the key travels as its file-passphrase-encrypted
	// ciphertext, verbatim. Two independent secrets (passphrase never leaves the
	// device that has it); needed only to *use* the key.
	ProtectionPassphrase RoamingProtection = "passphrase"
	// ProtectionHW: the key travels as its hardware-key-encrypted ciphertext plus
	// the challenge, verbatim. Usable only on a device with the same physical key.
	ProtectionHW RoamingProtection = "hw"
	// ProtectionCloud: a plain-keychain key with no independent secret — it
	// travels as raw key material, protected only by the bundle's outer cloud-key
	// wrap (decryptable with the cloud password). Re-wrapped per device at rest.
	ProtectionCloud RoamingProtection = "cloud"
)

// RoamingEntry is one identity's transportable key material, produced by
// IdentityExportFn and consumed by IdentityImportFn. Enc/Sign are ciphertext for
// passphrase/hw and raw key material for cloud; Challenge is set only for hw.
type RoamingEntry struct {
	Protection RoamingProtection
	Enc        []byte // <name>.enc contents (ciphertext) or raw age secret key (cloud)
	Sign       []byte // <name>.sign contents (ciphertext) or raw signing key (cloud)
	Challenge  []byte // <name>.hwchallenge (hw only)
	// HWKEK is the origin device's hardware-key KEK convention (hw only) —
	// see ManifestIdentity.HWKEK.
	HWKEK string
}

// IdentityExportFn returns the at-rest transport form for one identity. The
// caller (ic-cli/ic-app) implements it because backend selection + at-rest byte
// access is caller-specific: file/HW read raw ciphertext; plain keychain extracts
// raw key. It must NOT decrypt file/HW keys — that's the whole point.
type IdentityExportFn func(idx identity.IdentityIndex) (RoamingEntry, error)

// IdentityImportFn stores one identity's transport form on this device according
// to the destination backend, and returns the backend it landed in (for the
// index). The caller implements the destination logic (write ciphertext as-is /
// decrypt into keychain / set a file passphrase). Meta, index, and the manifest
// are handled by the profile package.
type IdentityImportFn func(name string, entry RoamingEntry) (backend string, err error)

// OpenIdentityFn opens the named identity into an *Unlocked handle for
// export. Callers provide this because constructing the right keystore
// (with passphrase prompts or session-passphrase, HW key handling, etc.)
// is caller-specific. ic-cli's openIdentity and ic-app's openIdentity
// both fit this signature directly.
type OpenIdentityFn func(name string) (*identity.Unlocked, error)

// DestinationKeystoreFn returns a non-decorated keystore where imported
// identity keys should be stored, plus the backend name string
// (identity.BackendKeychain / BackendFile) to record in the index. Called
// once per Import after any config changes have been applied — the
// callback should consult the (possibly just-updated) Keystore preference
// to pick its backend.
type DestinationKeystoreFn func() (ks keystore.Keystore, backend string, err error)

// HWRestoreFactoryFn returns an identity.HWRestoreFn bound to the given
// identity name. Called once per HW-flagged identity during Import. The
// returned callback writes the challenge file under the right name and
// returns the HW-decorated keystore that identity.Import should use.
// Return nil to import HW identities as non-HW (drops HW protection).
type HWRestoreFactoryFn func(identityName string) identity.HWRestoreFn

// ImportOptions configures the destructive import.
type ImportOptions struct {
	Passphrase string
	// PassphraseBytes takes precedence over Passphrase when non-empty —
	// the wipeable-bytes path for callers holding the secret in guarded
	// memory (caller retains ownership and wipes it).
	PassphraseBytes []byte
	IncludeSettings bool
	IncludePaths    bool
	HWRestore       HWRestoreFactoryFn
}
