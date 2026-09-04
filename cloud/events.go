package cloud

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ChangeEvent is one server doorbell: which resource kind changed for the
// account (contacts/settings/identities/backup/pending). It carries no
// content — clients react by running a normal sync.
type ChangeEvent struct {
	Kind string `json:"kind"`
}

// streamHTTP is a dedicated client for the SSE stream: no overall timeout
// (the connection is long-lived by design), but bounded dial/handshake via
// the default transport.
var streamHTTP = &http.Client{Timeout: 0}

// StreamEvents subscribes to the account's change feed (SSE) and invokes
// onEvent for each doorbell until ctx is canceled (returns nil) or the
// stream drops (returns the error; callers reconnect with backoff, refreshing
// the token first on auth failures). Heartbeat comments are consumed
// silently. Requires a live session token.
func (c *Client) StreamEvents(ctx context.Context, onEvent func(ChangeEvent)) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/v1/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken())
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-IC-Instance", c.instanceID())

	resp, err := streamHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &Error{Status: resp.StatusCode, Code: "stream", Message: "event stream refused: " + resp.Status}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// SSE framing: comments (heartbeats) start with ':'; we only care
		// about data lines — the event name is always "change".
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		var ev ChangeEvent
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		onEvent(ev)
	}
	if ctx.Err() != nil {
		return nil
	}
	err = scanner.Err()
	if err == nil {
		err = &Error{Status: 0, Code: "stream_closed", Message: "event stream closed by server"}
	}
	return err
}

// StreamEventsWithRetry runs StreamEvents in a reconnect loop with
// exponential backoff (5s → maxBackoff), invoking beforeConnect (may be nil)
// before each attempt — the hook for refreshing an expired token. Returns
// only when ctx is canceled.
func (c *Client) StreamEventsWithRetry(ctx context.Context, onEvent func(ChangeEvent), beforeConnect func(context.Context) error) {
	const maxBackoff = 60 * time.Second
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		if beforeConnect != nil {
			if err := beforeConnect(ctx); err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < maxBackoff {
					backoff *= 2
				}
				continue
			}
		}
		start := time.Now()
		err := c.StreamEvents(ctx, onEvent)
		if err == nil {
			return // ctx canceled
		}
		// A stream that lived a while earns a fresh backoff.
		if time.Since(start) > time.Minute {
			backoff = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}
