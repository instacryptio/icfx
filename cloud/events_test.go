package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestStreamEventsParsesSSE: data lines dispatch, heartbeats are ignored,
// server close ends the stream with an error, ctx cancel ends it cleanly.
func TestStreamEventsParsesSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f := w.(http.Flusher)
		fmt.Fprint(w, ": connected\n\n")
		f.Flush()
		fmt.Fprint(w, ": ping\n\n")
		f.Flush()
		fmt.Fprint(w, "event: change\ndata: {\"kind\":\"contacts\"}\n\n")
		f.Flush()
		fmt.Fprint(w, "event: change\ndata: {\"kind\":\"pending\"}\n\n")
		f.Flush()
		// then close → client sees stream_closed
	}))
	defer srv.Close()

	c, _ := New(srv.URL)
	var got []string
	err := c.StreamEvents(context.Background(), func(ev ChangeEvent) {
		got = append(got, ev.Kind)
	})
	if err == nil {
		t.Fatal("server close must surface an error (reconnect signal)")
	}
	if len(got) != 2 || got[0] != "contacts" || got[1] != "pending" {
		t.Fatalf("events parsed wrong: %v", got)
	}
}

func TestStreamEventsCtxCancelClean(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		cl, _ := New(srv.URL)
		done <- cl.StreamEvents(ctx, func(ChangeEvent) {})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ctx cancel must return nil, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not end on ctx cancel")
	}
}

func TestStreamEventsAuthRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	cl, _ := New(srv.URL)
	err := cl.StreamEvents(context.Background(), func(ChangeEvent) {})
	var e *Error
	if !asError(err, &e) || e.Status != http.StatusUnauthorized {
		t.Fatalf("want 401 Error, got %v", err)
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	*target = e
	return true
}
