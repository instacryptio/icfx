package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
)

// PutBlob uploads (or updates) the named encrypted blob. prevVersion is the
// version returned by the last GetBlob, or 0 for the very first upload.
// On version conflict the returned error satisfies IsConflict; callers
// should re-fetch, merge, and retry.
func (c *Client) PutBlob(ctx context.Context, name string, ciphertext []byte, prevVersion int64) (PutBlobResult, error) {
	var res PutBlobResult
	err := c.doJSON(ctx, "PUT", "/v1/blob/"+url.PathEscape(name),
		struct {
			Ciphertext  string `json:"ciphertext_b64"`
			PrevVersion int64  `json:"prev_version"`
		}{
			Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
			PrevVersion: prevVersion,
		},
		&res, true)
	return res, err
}

// GetBlob fetches the named encrypted blob. Returns IsNotFound-style error
// when the user has not yet uploaded this resource.
func (c *Client) GetBlob(ctx context.Context, name string) (Blob, error) {
	var raw struct {
		Blob
		Ciphertext string `json:"ciphertext_b64"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/blob/"+url.PathEscape(name), nil, &raw, true); err != nil {
		return Blob{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(raw.Ciphertext)
	if err != nil {
		return Blob{}, &Error{Status: http.StatusInternalServerError, Code: "decode", Message: err.Error()}
	}
	raw.Blob.Ciphertext = decoded
	return raw.Blob, nil
}

// DeleteBlob removes the named blob (opts out of syncing this resource).
func (c *Client) DeleteBlob(ctx context.Context, name string) error {
	return c.doJSON(ctx, "DELETE", "/v1/blob/"+url.PathEscape(name), nil, nil, true)
}

// CurrentVersionFromConflict extracts the server's reported current version
// from a conflict error. Returns 0 (and false) if err is not a conflict.
func CurrentVersionFromConflict(err error) (int64, bool) {
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict {
		return 0, false
	}
	return e.CurrentVersion, true
}
