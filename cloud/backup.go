package cloud

import (
	"context"
	"fmt"

	"github.com/instacryptio/icfx/profile"
)

// Backup exports the full local profile (all identities + contacts + settings)
// as a single passphrase-encrypted bundle and stores it as the account's
// "backup" blob. The bundle is opaque to the server (age scrypt over the
// backup passphrase), so backup stays zero-knowledge. The server returns 402
// (IsPaymentRequired) on plans where backup isn't allowed.
//
// openFn opens each identity for export — pass the client's own openIdentity
// (it fits profile.OpenIdentityFn). backupPassphrase is distinct from the
// account password and the identity passphrase.
func (c *Client) Backup(ctx context.Context, backupPassphrase string, openFn profile.OpenIdentityFn) error {
	data, err := profile.ExportToBytes(backupPassphrase, openFn)
	if err != nil {
		return fmt.Errorf("export profile: %w", err)
	}
	// Backup is a full replace (last-writer-wins). Try as first write; if a
	// backup already exists, retry at its current version.
	_, err = c.PutBlob(ctx, "backup", data, 0)
	if cur, ok := CurrentVersionFromConflict(err); ok {
		_, err = c.PutBlob(ctx, "backup", data, cur)
	}
	return err
}

// FetchBackup downloads the raw encrypted backup bundle. The caller decrypts,
// previews (profile.PeekManifestFromBytes), confirms, and imports
// (profile.ImportFromBytes) — those steps involve user confirmation and stay
// client-side. Returns an IsNotFound error when no backup exists.
func (c *Client) FetchBackup(ctx context.Context) ([]byte, error) {
	b, err := c.GetBlob(ctx, "backup")
	if err != nil {
		return nil, err
	}
	return b.Ciphertext, nil
}
