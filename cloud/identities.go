package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/instacryptio/icfx/profile"
)

// encKeyPassphrase renders the raw account encryption key as the passphrase
// string profile export/import expect. The key is already high-entropy (the
// scrypt pass is redundant but harmless), matching the profile-bundle pattern.
func encKeyPassphrase(encKey []byte) string {
	return base64.StdEncoding.EncodeToString(encKey)
}

// sessionOrStoredEncKey resolves the account encryption key: the in-memory
// session key first (fresh login/signup), then the configured EncKeyStore.
// fromStore lets callers map decrypt failures to ErrEncKeyStale — only a
// PERSISTED key can silently go stale (remote password change); a freshly
// derived one was just verified against the server.
func (c *Client) sessionOrStoredEncKey() (key []byte, fromStore bool, err error) {
	if k := c.encryptionKey(); len(k) > 0 {
		return k, false, nil
	}
	k, err := c.storedEncKey()
	if err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// PushIdentities packs every local identity's encrypted-at-rest form and stores
// it as the "identities" blob, wrapped under the account encryption key. File/HW
// keys travel as-is (never decrypted here); only plain-keychain keys lean on the
// cloud-key wrap. Uses the session key or the persisted one (EncKeyStore);
// with neither, returns an ErrEncKeyMissing-wrapped error.
func (c *Client) PushIdentities(ctx context.Context, exportFn profile.IdentityExportFn) error {
	encKey, _, err := c.sessionOrStoredEncKey()
	if err != nil {
		return err
	}
	_, err = c.pushIdentitiesWithKey(ctx, encKey, exportFn)
	return err
}

// pushIdentitiesVersioned is PushIdentities returning the new blob version —
// the stateful sync engine records it so later passes can tell "remote moved"
// apart from "that was my own push".
func (c *Client) pushIdentitiesVersioned(ctx context.Context, exportFn profile.IdentityExportFn) (int64, error) {
	encKey, _, err := c.sessionOrStoredEncKey()
	if err != nil {
		return 0, err
	}
	return c.pushIdentitiesWithKey(ctx, encKey, exportFn)
}

// pushIdentitiesWithKey exports + uploads under an explicit key (used both by
// PushIdentities and by ChangePassword, which re-wraps the outer layer under the
// NEW key before the client's session key is updated). Returns the new version.
func (c *Client) pushIdentitiesWithKey(ctx context.Context, encKey []byte, exportFn profile.IdentityExportFn) (int64, error) {
	data, err := profile.ExportIdentitiesToBytes(encKeyPassphrase(encKey), exportFn)
	if err != nil {
		return 0, fmt.Errorf("export identities: %w", err)
	}
	// Full replace (last-writer-wins): try fresh, then retry at current version.
	res, err := c.PutBlob(ctx, "identities", data, 0)
	if cur, ok := CurrentVersionFromConflict(err); ok {
		res, err = c.PutBlob(ctx, "identities", data, cur)
	}
	return res.Version, err
}

// PullIdentities downloads the identities blob and MERGES its identities into the
// local keystore via importFn (non-destructive — contacts/settings untouched).
// Returns an IsNotFound error when there's no identities blob yet. When a
// PERSISTED key fails to decrypt the blob (the password changed on another
// device), the error wraps ErrEncKeyStale so callers can fall back to a fresh
// cloud-password login.
func (c *Client) PullIdentities(ctx context.Context, importFn profile.IdentityImportFn) error {
	_, err := c.pullIdentitiesVersioned(ctx, importFn)
	return err
}

// pullIdentitiesVersioned is PullIdentities returning the blob version that
// was imported, for the stateful sync engine's bookkeeping.
func (c *Client) pullIdentitiesVersioned(ctx context.Context, importFn profile.IdentityImportFn) (int64, error) {
	encKey, fromStore, err := c.sessionOrStoredEncKey()
	if err != nil {
		return 0, err
	}
	b, err := c.GetBlob(ctx, "identities")
	if err != nil {
		return 0, err
	}
	err = profile.ImportIdentitiesFromBytes(b.Ciphertext, encKeyPassphrase(encKey), importFn)
	if err != nil && fromStore && !errors.Is(err, profile.ErrUnsupportedRoamingVersion) {
		return 0, fmt.Errorf("%w: %v", ErrEncKeyStale, err)
	}
	return b.Version, err
}

// hasIdentitiesBlob reports whether an identities blob exists for the account.
func (c *Client) hasIdentitiesBlob(ctx context.Context) (bool, error) {
	_, err := c.GetBlob(ctx, "identities")
	if IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
