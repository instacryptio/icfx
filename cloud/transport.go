package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Response-size ceilings. Under the zero-knowledge threat model the server is
// untrusted, so a compromised/rogue server must not be able to OOM the client
// with an unbounded body. maxResponseBytes bounds control JSON and the base64
// metadata blobs (contacts/notifications/identities) that ride inside it — large
// enough for any legitimate blob (base64 inflates ~33%), small enough to bound
// memory. Share file payloads do NOT flow through here (they use presigned
// object-store URLs). maxErrorBytes bounds error-response bodies.
const (
	maxResponseBytes = 32 << 20 // 32 MiB
	maxErrorBytes    = 64 << 10 // 64 KiB
)

// doJSON sends a JSON request and decodes the JSON response into out (if
// non-nil and the status is 2xx). Bearer auth is attached automatically
// when authed is true.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any, authed bool) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-IC-Instance", c.instanceID())
	req.Header.Set("X-IC-Device", c.deviceLabel())
	if authed {
		token := c.accessToken()
		if token == "" {
			return &Error{Status: http.StatusUnauthorized, Code: "no_token", Message: "client has no access token"}
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return decodeError(resp)
	}
	// Cap the body an untrusted server can make us read into memory.
	limited := io.LimitReader(resp.Body, maxResponseBytes)
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil && err != io.EOF {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func decodeError(resp *http.Response) error {
	e := &Error{Status: resp.StatusCode}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
	if len(body) > 0 {
		_ = json.Unmarshal(body, e)
	}
	if e.Code == "" {
		e.Code = "http_" + http.StatusText(resp.StatusCode)
	}
	if e.Message == "" {
		e.Message = strings.TrimSpace(string(body))
	}
	return e
}

func (c *Client) url(path string) string {
	return strings.TrimRight(c.BaseURL, "/") + path
}
