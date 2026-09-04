//go:build integration

package cloud_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/instacryptio/icfx/cloud"
)

// TestSessionsDeviceLabelEndToEnd covers the full header→middleware→session
// path the Devices UI depends on: the label set on the client must come back
// from ListSessions for a fresh login, current must be flagged, and revoking
// the session must log the device out.
func TestSessionsDeviceLabelEndToEnd(t *testing.T) {
	c, _ := cloud.New(baseURL())
	c.SetDeviceLabel("it-device")
	email := fmt.Sprintf("devices-%d@example.com", time.Now().UnixNano())
	mustSignUp(t, c, email, "correcthorsebatterystaple")

	sessions, err := c.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("fresh account: want exactly 1 session, got %d: %+v", len(sessions), sessions)
	}
	s := sessions[0]
	if s.Device != "it-device" {
		t.Fatalf("device label: want %q, got %q", "it-device", s.Device)
	}
	if !s.Current {
		t.Fatalf("the only session must be current: %+v", s)
	}
	if s.ID == "" || s.CreatedAt.IsZero() || s.LastActive.IsZero() {
		t.Fatalf("incomplete session info: %+v", s)
	}

	// Revoking your own session is a logout: the next authed call fails.
	if err := c.RevokeSession(context.Background(), s.ID); err != nil {
		t.Fatalf("revoke own session: %v", err)
	}
	if _, err := c.ListSessions(context.Background()); err == nil {
		t.Fatal("authed call after revoking own session must fail")
	}
}
