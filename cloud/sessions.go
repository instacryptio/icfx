package cloud

import (
	"context"
	"net/url"
	"time"
)

// Session is one of the account's live logins (devices), as listed by the
// server's Devices API.
type Session struct {
	ID         string    `json:"id"`
	Device     string    `json:"device"`
	CreatedAt  time.Time `json:"created_at"`
	LastActive time.Time `json:"last_active"`
	// Current is true for the session making this request.
	Current bool `json:"current"`
}

// ListSessions returns the account's live sessions, newest activity first.
func (c *Client) ListSessions(ctx context.Context) ([]Session, error) {
	var out []Session
	err := c.doJSON(ctx, "GET", "/v1/sessions", nil, &out, true)
	return out, err
}

// RevokeSession logs the identified session's device out. Revoking your own
// current session is a logout.
func (c *Client) RevokeSession(ctx context.Context, id string) error {
	return c.doJSON(ctx, "DELETE", "/v1/sessions/"+url.PathEscape(id), nil, nil, true)
}
