package cloud

import (
	"bytes"
	"context"
	"fmt"
)

// SelfCrypter is the subset of *identity.Unlocked the self-lock blob helpers
// need: encrypt to the identity's own lock and decrypt with its own key.
// Taking an interface keeps this package decoupled from icfx/identity and makes
// the helpers trivially testable; *identity.Unlocked satisfies it.
type SelfCrypter interface {
	EncryptToSelf(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// SealBlob encrypts plaintext to the caller's own lock and uploads it as the
// named blob — the write half of the blob-encryption contract. Every client
// seals a given resource the same way, so they interoperate by construction.
// On a version conflict the returned error satisfies IsConflict; callers
// should OpenBlob, merge, and retry with the reported current version.
func (c *Client) SealBlob(ctx context.Context, u SelfCrypter, name string, plaintext []byte, prevVersion int64) (PutBlobResult, error) {
	ct, err := u.EncryptToSelf(plaintext)
	if err != nil {
		return PutBlobResult{}, fmt.Errorf("seal %q: %w", name, err)
	}
	return c.PutBlob(ctx, name, ct, prevVersion)
}

// OpenBlob fetches the named blob and decrypts it with the caller's own key,
// returning the plaintext and the blob's current version (feed it back as the
// next SealBlob's prevVersion). A resource that was never uploaded surfaces via
// IsNotFound.
func (c *Client) OpenBlob(ctx context.Context, u SelfCrypter, name string) ([]byte, int64, error) {
	blob, err := c.GetBlob(ctx, name)
	if err != nil {
		return nil, 0, err
	}
	plaintext, err := u.Decrypt(blob.Ciphertext)
	if err != nil {
		return nil, 0, fmt.Errorf("open %q: %w", name, err)
	}
	return plaintext, blob.Version, nil
}

// MergeFunc converges the local and remote plaintext of a self-lock blob. It
// MUST be commutative and idempotent (a CRDT merge), so concurrent writes from
// several devices converge regardless of order.
type MergeFunc func(local, remote []byte) ([]byte, error)

// mergeBlobMaxAttempts bounds the read-merge-write retry loop under contention.
const mergeBlobMaxAttempts = 5

// SyncMergedBlob converges a self-lock-encrypted resource that uses CRDT merge
// semantics — the counterpart to the last-writer-wins SyncResource used by
// settings. It pulls the remote blob, merges it with local, and pushes the
// result under optimistic concurrency, retrying the whole read-merge-write on a
// version conflict (another device wrote in between). A resource that was never
// uploaded is created from local. Returns the converged plaintext (what the
// caller should persist locally). Zero-knowledge: only ciphertext crosses the
// wire.
func (c *Client) SyncMergedBlob(ctx context.Context, u SelfCrypter, name string, local []byte, merge MergeFunc) ([]byte, error) {
	for attempt := 0; attempt < mergeBlobMaxAttempts; attempt++ {
		remote, ver, err := c.OpenBlob(ctx, u, name)
		notFound := IsNotFound(err)
		if err != nil && !notFound {
			return nil, err
		}
		merged := local
		if !notFound {
			merged, err = merge(local, remote)
			if err != nil {
				return nil, fmt.Errorf("merge %q: %w", name, err)
			}
			if bytes.Equal(merged, remote) {
				return merged, nil // remote already carries our state — nothing to push
			}
		}
		if _, err := c.SealBlob(ctx, u, name, merged, ver); err != nil {
			if IsConflict(err) {
				local = merged // fold our work forward and re-read the newer remote
				continue
			}
			return nil, err
		}
		return merged, nil
	}
	return nil, fmt.Errorf("sync %q: too many version conflicts", name)
}
