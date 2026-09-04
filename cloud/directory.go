package cloud

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/qr"
)

// PublishDirectory publishes (or updates) one of the authenticated
// account's identities as a public directory entry, keyed by fingerprint.
// The lock is stored plaintext on the server by design — publishing is
// opt-in and exists so other users can find that identity. An account may
// publish several identities; each is an independent row and search never
// reveals they share an owner.
func (c *Client) PublishDirectory(ctx context.Context, in DirectoryPublishInput) error {
	return c.doJSON(ctx, "POST", "/v1/directory", in, nil, true)
}

// PublishIdentityLock publishes one identity's lock (public key) to the
// directory. It owns the shared publish logic every client needs: email
// validation (ErrEmailRequired — the directory's confirmed contract),
// armored lock construction, the API call, and conflict mapping
// (ErrFingerprintTaken). Callers add only presentation — e.g. a
// platform-specific hint for how to set the email. The lock comes from
// identity.LockBundleOf, same as the other discovery lifts.
func PublishIdentityLock(ctx context.Context, c *Client, lock qr.LockBundle) error {
	if lock.Email == "" {
		return ErrEmailRequired
	}

	raw, err := qr.MarshalLockBundle(lock)
	if err != nil {
		return fmt.Errorf("marshaling lock: %w", err)
	}

	err = c.PublishDirectory(ctx, DirectoryPublishInput{
		DisplayName: lock.Name,
		Alias:       lock.Alias,
		Email:       lock.Email,
		Fingerprint: lock.Fingerprint,
		LockArmored: string(format.ArmorEncode(raw, format.ArmorLockLabel)),
	})
	if IsConflict(err) {
		return ErrFingerprintTaken
	}
	return err
}

// UnpublishDirectory removes the identity with the given fingerprint from
// the directory. Other published identities of the account are unaffected.
func (c *Client) UnpublishDirectory(ctx context.Context, fingerprint string) error {
	in := struct {
		Fingerprint string `json:"fingerprint"`
	}{Fingerprint: fingerprint}
	return c.doJSON(ctx, "DELETE", "/v1/directory", in, nil, true)
}

// ListMyDirectory returns the account's OWN published entries — the
// publish-state behind per-identity publish toggles (search excludes self,
// so this is the only way to see your own rows).
func (c *Client) ListMyDirectory(ctx context.Context) ([]DirectoryEntry, error) {
	var raw struct {
		Items []DirectoryEntry `json:"items"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/directory/mine", nil, &raw, true); err != nil {
		return nil, err
	}
	return raw.Items, nil
}

// SearchDirectory matches on display_name, email prefix, or fingerprint prefix.
// limit defaults to 25 if zero, capped at 100 server-side.
func (c *Client) SearchDirectory(ctx context.Context, query string, limit int) ([]DirectoryEntry, error) {
	q := url.Values{}
	q.Set("q", query)
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var raw struct {
		Items []DirectoryEntry `json:"items"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/directory/search?"+q.Encode(), nil, &raw, true); err != nil {
		return nil, err
	}
	return raw.Items, nil
}
