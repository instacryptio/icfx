package cloud

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// transferHTTP is a dedicated client for share blob transfers (presigned
// up/downloads). Unlike the shared c.HTTP (a 30s whole-request client fit for
// small JSON calls), it has NO overall deadline — a multi-GB transfer can take
// minutes — but bounds the dial / TLS / response-header phases so a dead peer
// still fails fast. The per-request context governs cancellation of the body
// transfer itself. (Mirrors the dedicated streamHTTP used for SSE.)
var transferHTTP = &http.Client{
	Timeout: 0,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// CreateShare initiates a new share and returns a presigned PUT URL the
// sender should use to upload the ciphertext directly to the object store.
// After upload the sender calls FinalizeShare to mark uploaded and trigger
// the recipient notification email.
func (c *Client) CreateShare(ctx context.Context, in ShareCreateInput) (ShareCreateResult, error) {
	var res ShareCreateResult
	body := struct {
		Recipients []string `json:"recipient_fingerprints"`
		ToSelf     bool     `json:"to_self"`
		TTLSec     int64    `json:"ttl_seconds"`
		SingleUse  bool     `json:"single_use"`
		FileName   string   `json:"file_name"`
		FileSize   int64    `json:"file_size"`
	}{
		Recipients: in.RecipientFingerprints,
		ToSelf:     in.ToSelf,
		TTLSec:     int64(in.TTL.Seconds()),
		SingleUse:  in.SingleUse,
		FileName:   in.FileName,
		FileSize:   in.FileSize,
	}
	err := c.doJSON(ctx, "POST", "/v1/share", body, &res, true)
	return res, err
}

// UploadStreamToPresignedURL puts size bytes from r to the URL returned by
// CreateShare without materializing the payload in memory (large files).
// size must be the exact byte count — the server verifies it at finalize.
func (c *Client) UploadStreamToPresignedURL(ctx context.Context, presignedURL string, r io.Reader, size int64) error {
	if err := validatePresignedURL(presignedURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, presignedURL, r)
	if err != nil {
		return err
	}
	req.ContentLength = size
	resp, err := transferHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// FetchPresignedURL GETs a presigned download URL and returns the body
// stream. The caller must Close the returned reader.
func (c *Client) FetchPresignedURL(ctx context.Context, presignedURL string) (io.ReadCloser, error) {
	if err := validatePresignedURL(presignedURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, presignedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := transferHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("download: status %d: %s", resp.StatusCode, string(body))
	}
	return resp.Body, nil
}

// validatePresignedURL constrains a server-supplied object-store URL before the
// client fetches/PUTs to it: require https (no cleartext downgrade) and a host.
// The server names this URL, so under the zero-knowledge threat model it's
// untrusted input; https-only bounds SSRF to TLS endpoints and the payload is
// already E2E-encrypted, so a rogue URL leaks only ciphertext.
func validatePresignedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid presigned URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https presigned URL (scheme %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("presigned URL has no host")
	}
	return nil
}

// FinalizeShare verifies the upload server-side and publishes the share to
// the recipient's inbox. notify=false suppresses the recipient email (the
// share still appears in their inbox/notifications).
func (c *Client) FinalizeShare(ctx context.Context, shareID string, notify bool) (ShareFinalizeResult, error) {
	var res ShareFinalizeResult
	body := struct {
		Notify bool `json:"notify"`
	}{Notify: notify}
	err := c.doJSON(ctx, "POST", "/v1/share/"+url.PathEscape(shareID)+"/finalize", body, &res, true)
	return res, err
}

// DownloadShare requests a presigned GET URL for the named share. The
// authenticated account must own the published directory entry whose
// fingerprint matches the share's intended recipient.
func (c *Client) DownloadShare(ctx context.Context, shareID string) (ShareDownload, error) {
	var res ShareDownload
	err := c.doJSON(ctx, "POST", "/v1/share/"+url.PathEscape(shareID)+"/download", nil, &res, true)
	return res, err
}

// DownloadShareRaw requests a presigned GET URL for a share's raw encrypted
// .icfx blob. Unlike DownloadShare this is authorized to the SENDER of the
// share (not a recipient) and performs no decrypt — it lets a sender retrieve
// the ciphertext they uploaded. The server returns 403 for anyone but the sender.
func (c *Client) DownloadShareRaw(ctx context.Context, shareID string) (ShareDownload, error) {
	var res ShareDownload
	err := c.doJSON(ctx, "POST", "/v1/share/"+url.PathEscape(shareID)+"/raw-download", nil, &res, true)
	return res, err
}

// CompleteShare marks a single-use share consumed AFTER the recipient has
// successfully downloaded AND decrypted it. Requesting the download URL
// (DownloadShare) no longer burns the share, so an aborted or failed transfer
// leaves it receivable; only a completed receive calls this. Idempotent and
// best-effort — a share that was never single-use is unaffected.
func (c *Client) CompleteShare(ctx context.Context, shareID string) error {
	return c.doJSON(ctx, "POST", "/v1/share/"+url.PathEscape(shareID)+"/complete", nil, nil, true)
}

func (c *Client) ListShares(ctx context.Context, limit int) ([]ShareSummary, error) {
	path := "/v1/share/list"
	if limit > 0 {
		path += "?" + url.Values{"limit": []string{strconv.Itoa(limit)}}.Encode()
	}
	var raw struct {
		Items []ShareSummary `json:"items"`
	}
	if err := c.doJSON(ctx, "GET", path, nil, &raw, true); err != nil {
		return nil, err
	}
	return raw.Items, nil
}

func (c *Client) CancelShare(ctx context.Context, shareID string) error {
	return c.doJSON(ctx, "DELETE", "/v1/share/"+url.PathEscape(shareID), nil, nil, true)
}

// ShareInbox lists downloadable shares addressed to any of the account's
// published directory fingerprints.
func (c *Client) ShareInbox(ctx context.Context, limit int) ([]ShareInboxItem, error) {
	path := "/v1/share/inbox"
	if limit > 0 {
		path += "?" + url.Values{"limit": []string{strconv.Itoa(limit)}}.Encode()
	}
	var raw struct {
		Items []ShareInboxItem `json:"items"`
	}
	if err := c.doJSON(ctx, "GET", path, nil, &raw, true); err != nil {
		return nil, err
	}
	return raw.Items, nil
}
