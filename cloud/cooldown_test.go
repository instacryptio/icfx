package cloud

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestFileCooldownStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "cooldown.json")
	store := NewFileCooldownStore(path)

	if _, ok := store.LastAttempt("reset:a@b.com"); ok {
		t.Fatal("expected no attempt before Record")
	}
	now := time.Now()
	if err := store.Record("reset:a@b.com", now); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, ok := store.LastAttempt("reset:a@b.com")
	if !ok {
		t.Fatal("expected an attempt after Record")
	}
	if got.Unix() != now.Unix() {
		t.Fatalf("stored time = %v, want %v", got.Unix(), now.Unix())
	}
	// A fresh store over the same path reads persisted state.
	if _, ok := NewFileCooldownStore(path).LastAttempt("reset:a@b.com"); !ok {
		t.Fatal("expected persisted attempt across store instances")
	}
}

func TestForgotPasswordCooldownGate(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, _ := New(srv.URL)
	c.SetCooldownStore(NewFileCooldownStore(filepath.Join(t.TempDir(), "cd.json")))
	ctx := context.Background()

	// First call reaches the server and records.
	if err := c.ForgotPassword(ctx, "user@example.com"); err != nil {
		t.Fatalf("first forgot: %v", err)
	}
	if hits != 1 {
		t.Fatalf("server hits = %d, want 1", hits)
	}

	// Second call within the cooldown is blocked locally — no round trip.
	err := c.ForgotPassword(ctx, "user@example.com")
	var cd *CooldownError
	if !errors.As(err, &cd) {
		t.Fatalf("second forgot: want *CooldownError, got %v", err)
	}
	if cd.Retry <= 0 || cd.Retry > EmailActionCooldown {
		t.Fatalf("retry = %v, want in (0, %v]", cd.Retry, EmailActionCooldown)
	}
	if hits != 1 {
		t.Fatalf("server hits after blocked call = %d, want 1 (no round trip)", hits)
	}

	// A different address is unaffected.
	if err := c.ForgotPassword(ctx, "other@example.com"); err != nil {
		t.Fatalf("other-address forgot: %v", err)
	}
	if hits != 2 {
		t.Fatalf("server hits = %d, want 2", hits)
	}
}

func TestCooldownGateDisabledWithoutStore(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, _ := New(srv.URL) // no cooldown store
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := c.ResendSignupCode(ctx, "user@example.com"); err != nil {
			t.Fatalf("verify #%d: %v", i+1, err)
		}
	}
	if hits != 3 {
		t.Fatalf("server hits = %d, want 3 (no gate without a store)", hits)
	}
}
