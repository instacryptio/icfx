package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestRefreshSingleFlight pins the coalescing contract: concurrent Refresh
// calls on one client must produce exactly ONE server round trip. The server
// rotates refresh tokens with reuse detection — a second POST of the same
// token would revoke the whole session family (forced logout).
func TestRefreshSingleFlight(t *testing.T) {
	var (
		mu       sync.Mutex
		requests int
		current  = "rt-1"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/refresh" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		requests++
		first := requests == 1
		reused := body.RefreshToken != current
		if !reused {
			current = "rt-2"
		}
		mu.Unlock()

		// Hold the first request open long enough that, without
		// single-flight, the other goroutines' requests would be in flight
		// concurrently and hit the reuse branch.
		if first {
			time.Sleep(100 * time.Millisecond)
		}
		if reused {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"code": "token_reused", "message": "refresh token reuse detected",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(Tokens{
			AccessToken:      "at-2",
			RefreshToken:     "rt-2",
			ExpiresAt:        time.Now().Add(time.Hour),
			RefreshExpiresAt: time.Now().Add(24 * time.Hour),
		})
	}))
	defer srv.Close()

	c, _ := New(srv.URL)
	c.SetTokens(&Tokens{
		AccessToken:      "at-1",
		RefreshToken:     "rt-1",
		ExpiresAt:        time.Now().Add(-time.Minute), // expired → everyone wants a refresh
		RefreshExpiresAt: time.Now().Add(24 * time.Hour),
	})

	const callers = 8
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.Refresh(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("want exactly 1 refresh request, server saw %d", requests)
	}
	if got := c.Tokens(); got == nil || got.RefreshToken != "rt-2" {
		t.Fatalf("client should hold rotated tokens, got %+v", got)
	}
}
