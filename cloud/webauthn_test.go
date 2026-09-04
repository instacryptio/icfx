package cloud

// Unit tests for the WebAuthn ceremony primitives + the desktop convenience
// wrappers. An httptest server captures the exact request bodies so we prove
// (a) desktop RegisterWebAuthn/LogInWebAuthn still drive begin→ceremony→finish,
// and (b) the mobile primitives (RegisterWebAuthnBegin/Finish,
// LogInWebAuthnResponse) POST byte-identical bodies without an Authenticator.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuthenticator returns canned response JSON and records the options it saw,
// so a test can assert the desktop path fed it the server's options verbatim.
type fakeAuthenticator struct {
	makeResp    []byte
	getResp     []byte
	sawMakeOpts []byte
	sawGetOpts  []byte
}

func (f *fakeAuthenticator) MakeCredential(_ context.Context, opts []byte) ([]byte, error) {
	f.sawMakeOpts = opts
	return f.makeResp, nil
}

func (f *fakeAuthenticator) GetAssertion(_ context.Context, opts []byte) ([]byte, error) {
	f.sawGetOpts = opts
	return f.getResp, nil
}

type waServer struct {
	beginOptions json.RawMessage
	beginHandle  string
	tokens       Tokens
	gotFinish    map[string]json.RawMessage // parsed /register/finish body
	gotLogin     map[string]json.RawMessage // parsed /login/webauthn body
	srv          *httptest.Server
}

func newWAServer(t *testing.T) *waServer {
	t.Helper()
	s := &waServer{
		beginOptions: json.RawMessage(`{"publicKey":{"challenge":"abc"}}`),
		beginHandle:  "handle-123",
		tokens:       Tokens{AccessToken: "at", RefreshToken: "rt"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/account/2fa/webauthn/register/begin", func(w http.ResponseWriter, _ *http.Request) {
		bsJSON(w, http.StatusOK, map[string]any{"options": s.beginOptions, "handle": s.beginHandle})
	})
	mux.HandleFunc("/v1/account/2fa/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
		s.gotFinish = decodeRawBody(t, r)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/auth/login/webauthn", func(w http.ResponseWriter, r *http.Request) {
		s.gotLogin = decodeRawBody(t, r)
		bsJSON(w, http.StatusOK, s.tokens)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func decodeRawBody(t *testing.T, r *http.Request) map[string]json.RawMessage {
	t.Helper()
	raw, _ := io.ReadAll(r.Body)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode request body %q: %v", raw, err)
	}
	return m
}

func TestRegisterWebAuthnDesktopDrivesBeginFinish(t *testing.T) {
	s := newWAServer(t)
	c := newRekeyTestClient(t, s.srv.URL)
	authn := &fakeAuthenticator{makeResp: []byte(`{"id":"cred","type":"public-key"}`)}

	if err := c.RegisterWebAuthn(context.Background(), "my key", authn); err != nil {
		t.Fatalf("RegisterWebAuthn: %v", err)
	}
	// The authenticator was fed the server's creation options verbatim.
	if string(authn.sawMakeOpts) != string(s.beginOptions) {
		t.Errorf("authn saw options %q, want %q", authn.sawMakeOpts, s.beginOptions)
	}
	// Finish body carries the begin handle + the authenticator's response.
	if got := string(s.gotFinish["handle"]); got != `"handle-123"` {
		t.Errorf("finish handle = %s, want \"handle-123\"", got)
	}
	if got := string(s.gotFinish["response"]); got != `{"id":"cred","type":"public-key"}` {
		t.Errorf("finish response = %s", got)
	}
}

func TestLogInWebAuthnDesktopDrivesAssertion(t *testing.T) {
	s := newWAServer(t)
	c := newRekeyTestClient(t, s.srv.URL)
	authn := &fakeAuthenticator{getResp: []byte(`{"id":"cred","response":{}}`)}

	opts := []byte(`{"publicKey":{"challenge":"xyz"}}`)
	if err := c.LogInWebAuthn(context.Background(), "tok-1", opts, authn); err != nil {
		t.Fatalf("LogInWebAuthn: %v", err)
	}
	if string(authn.sawGetOpts) != string(opts) {
		t.Errorf("authn saw options %q, want %q", authn.sawGetOpts, opts)
	}
	if got := string(s.gotLogin["temp_token"]); got != `"tok-1"` {
		t.Errorf("login temp_token = %s, want \"tok-1\"", got)
	}
	if got := string(s.gotLogin["response"]); got != `{"id":"cred","response":{}}` {
		t.Errorf("login response = %s", got)
	}
	if c.Tokens() == nil || c.Tokens().AccessToken != "at" {
		t.Errorf("expected session tokens persisted after webauthn login")
	}
}

func TestWebAuthnMobilePrimitives(t *testing.T) {
	s := newWAServer(t)
	c := newRekeyTestClient(t, s.srv.URL)

	// Registration: begin returns options + handle; finish posts the native response.
	options, handle, err := c.RegisterWebAuthnBegin(context.Background(), "phone key")
	if err != nil {
		t.Fatalf("RegisterWebAuthnBegin: %v", err)
	}
	if string(options) != string(s.beginOptions) || handle != s.beginHandle {
		t.Errorf("begin returned options=%q handle=%q", options, handle)
	}
	nativeReg := []byte(`{"id":"native","type":"public-key"}`)
	if err := c.RegisterWebAuthnFinish(context.Background(), handle, nativeReg); err != nil {
		t.Fatalf("RegisterWebAuthnFinish: %v", err)
	}
	if string(s.gotFinish["handle"]) != `"handle-123"` || string(s.gotFinish["response"]) != string(nativeReg) {
		t.Errorf("finish body = %v", s.gotFinish)
	}

	// Login: response-only primitive posts temp_token + response and persists tokens.
	nativeAssert := []byte(`{"id":"native","response":{"signature":"s"}}`)
	if err := c.LogInWebAuthnResponse(context.Background(), "tok-9", nativeAssert); err != nil {
		t.Fatalf("LogInWebAuthnResponse: %v", err)
	}
	if string(s.gotLogin["temp_token"]) != `"tok-9"` || string(s.gotLogin["response"]) != string(nativeAssert) {
		t.Errorf("login body = %v", s.gotLogin)
	}
	if c.Tokens() == nil || c.Tokens().AccessToken != "at" {
		t.Errorf("expected session tokens persisted after native webauthn login")
	}
}
