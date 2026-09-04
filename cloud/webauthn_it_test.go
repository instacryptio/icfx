//go:build integration

package cloud_test

import (
	"context"
	"errors"
	"testing"

	vwa "github.com/descope/virtualwebauthn"

	"github.com/instacryptio/icfx/cloud"
)

// vwAuthenticator adapts descope/virtualwebauthn to the cloud.Authenticator
// interface, standing in for a real FIDO2 device in tests. RP must match the
// server's WebAuthn config (RPID=localhost, origin=http://localhost:8080).
type vwAuthenticator struct {
	rp   vwa.RelyingParty
	auth vwa.Authenticator
	cred vwa.Credential
}

func newVWAuthenticator() *vwAuthenticator {
	return &vwAuthenticator{
		rp:   vwa.RelyingParty{Name: "Instacrypt Cloud", ID: "localhost", Origin: "http://localhost:8080"},
		auth: vwa.NewAuthenticator(),
		cred: vwa.NewCredential(vwa.KeyTypeEC2),
	}
}

func (a *vwAuthenticator) MakeCredential(_ context.Context, optionsJSON []byte) ([]byte, error) {
	opts, err := vwa.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		return nil, err
	}
	resp := vwa.CreateAttestationResponse(a.rp, a.auth, a.cred, *opts)
	a.auth.AddCredential(a.cred)
	return []byte(resp), nil
}

func (a *vwAuthenticator) GetAssertion(_ context.Context, optionsJSON []byte) ([]byte, error) {
	opts, err := vwa.ParseAssertionOptions(string(optionsJSON))
	if err != nil {
		return nil, err
	}
	cred := a.auth.FindAllowedCredential(*opts)
	if cred == nil {
		return nil, errors.New("no allowed credential")
	}
	resp := vwa.CreateAssertionResponse(a.rp, a.auth, *cred, *opts)
	return []byte(resp), nil
}

// TestWebAuthnRegisterAndLogin drives the full hardware-key ceremony via the SDK
// against a live server, using a virtual authenticator in place of a FIDO2 key.
func TestWebAuthnRegisterAndLogin(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	email := randEmail()
	mustSignUp(t, c, email, validPW)

	authn := newVWAuthenticator()
	if err := c.RegisterWebAuthn(ctx, "primary key", authn); err != nil {
		t.Fatalf("register webauthn: %v", err)
	}

	// The account is now webauthn-gated.
	if info, err := c.AccountInfo(ctx); err != nil || info.ActiveFactor != "webauthn" {
		t.Fatalf("want webauthn active factor, got %q (err %v)", info.ActiveFactor, err)
	}
	keys, err := c.ListWebAuthnKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Label != "primary key" {
		t.Fatalf("list keys: %+v (err %v)", keys, err)
	}

	// Fresh client: login now returns a WebAuthn challenge; the assertion completes it.
	c2, _ := cloud.New(baseURL())
	challenge, lerr := c2.LogIn(ctx, email, validPW)
	if !errors.Is(lerr, cloud.ErrWebAuthnRequired) {
		t.Fatalf("expected ErrWebAuthnRequired, got %v", lerr)
	}
	if len(challenge.WebAuthnOptions) == 0 {
		t.Fatal("expected assertion options in challenge")
	}
	if err := c2.LogInWebAuthn(ctx, challenge.TempToken, challenge.WebAuthnOptions, authn); err != nil {
		t.Fatalf("login webauthn: %v", err)
	}
	if !c2.IsAuthenticated() {
		t.Fatal("expected authentication after webauthn login")
	}

	// Register a second key (backup), then delete the first.
	authn2 := newVWAuthenticator()
	if err := c.RegisterWebAuthn(ctx, "backup key", authn2); err != nil {
		t.Fatalf("register 2nd key: %v", err)
	}
	keys, err = c.ListWebAuthnKeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("want 2 keys, got %+v (err %v)", keys, err)
	}
	if err := c.DeleteWebAuthnKey(ctx, email, validPW, keys[0].ID); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	keys, err = c.ListWebAuthnKeys(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("want 1 key after delete, got %+v (err %v)", keys, err)
	}

	// Wrong password can't delete.
	if err := c.DeleteWebAuthnKey(ctx, email, "wrong-password-here", keys[0].ID); err == nil {
		t.Fatal("delete with wrong password should fail")
	}

	// Delete the last key → falls back to the email factor (account is verified?
	// No — unverified here, so it falls back to "none").
	if err := c.DeleteWebAuthnKey(ctx, email, validPW, keys[0].ID); err != nil {
		t.Fatalf("delete last key: %v", err)
	}
	c3, _ := cloud.New(baseURL())
	ch, err := c3.LogIn(ctx, email, validPW)
	if err != nil {
		t.Fatalf("login after removing all keys: %v", err)
	}
	if ch != nil {
		t.Fatalf("expected no second factor after removing all keys, got %q", ch.Factor)
	}
}
