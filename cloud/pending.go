package cloud

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
)

type pendingPostBody struct {
	Kind          string `json:"kind"`
	Ciphertext    string `json:"ciphertext_b64"`
	ToFingerprint string `json:"to_fingerprint,omitempty"`
}

// PostPending queues an encrypted update for delivery to recipientID. The
// ciphertext is opaque to the server — sender should have encrypted it to
// the recipient's lock. toFingerprint optionally hints which of the
// recipient's identity locks the ciphertext is encrypted to.
func (c *Client) PostPending(ctx context.Context, recipientID, kind string, ciphertext []byte, toFingerprint string) (PendingPostResult, error) {
	var res PendingPostResult
	err := c.doJSON(ctx, "POST", "/v1/pending/"+url.PathEscape(recipientID), pendingPostBody{
		Kind:          kind,
		Ciphertext:    base64.StdEncoding.EncodeToString(ciphertext),
		ToFingerprint: toFingerprint,
	}, &res, true)
	return res, err
}

// PostPendingToFingerprint queues an encrypted update for whichever account
// has published the identity with the given fingerprint. The fingerprint →
// account resolution happens server-side, so the sender never learns the
// recipient's account id (and cannot correlate published identities).
func (c *Client) PostPendingToFingerprint(ctx context.Context, fingerprint, kind string, ciphertext []byte) (PendingPostResult, error) {
	var res PendingPostResult
	err := c.doJSON(ctx, "POST", "/v1/pending/fp/"+url.PathEscape(fingerprint), pendingPostBody{
		Kind:       kind,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, &res, true)
	return res, err
}

// ListPending returns the metadata for all pending updates addressed to
// the authenticated account. Ciphertext is omitted — call FetchPending for
// a specific item to retrieve it.
func (c *Client) ListPending(ctx context.Context) ([]PendingItem, error) {
	var raw struct {
		Items []PendingItem `json:"items"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/pending", nil, &raw, true); err != nil {
		return nil, err
	}
	return raw.Items, nil
}

// FetchPending retrieves a single pending update by id.
func (c *Client) FetchPending(ctx context.Context, id string) (PendingFetch, error) {
	var raw struct {
		PendingFetch
		Ciphertext string `json:"ciphertext_b64"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/pending/"+url.PathEscape(id), nil, &raw, true); err != nil {
		return PendingFetch{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(raw.Ciphertext)
	if err != nil {
		return PendingFetch{}, &Error{Status: http.StatusInternalServerError, Code: "decode", Message: err.Error()}
	}
	raw.PendingFetch.Ciphertext = decoded
	return raw.PendingFetch, nil
}

// AckPending deletes a pending update after the client has successfully
// applied it. Idempotent for already-deleted ids.
func (c *Client) AckPending(ctx context.Context, id string) error {
	return c.doJSON(ctx, "DELETE", "/v1/pending/"+url.PathEscape(id), nil, nil, true)
}
