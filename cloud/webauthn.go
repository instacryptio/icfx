package cloud

import (
	"context"
	"encoding/json"
	"fmt"
)

// Authenticator abstracts the FIDO2 ceremony so the SDK stays free of any CGO /
// libfido2 dependency. Implementations (e.g. an ic-cli libfido2 authenticator)
// take the server's WebAuthn options JSON and return the authenticator's
// response JSON, in the shapes go-webauthn parses.
type Authenticator interface {
	// MakeCredential performs a registration (attestation) ceremony.
	MakeCredential(ctx context.Context, optionsJSON []byte) (responseJSON []byte, err error)
	// GetAssertion performs a login (assertion) ceremony.
	GetAssertion(ctx context.Context, optionsJSON []byte) (responseJSON []byte, err error)
}

// RegisterWebAuthnBegin starts hardware-key enrollment: it fetches the creation
// (attestation) options plus an opaque server handle. The caller runs the
// authenticator ceremony over optionsJSON, then completes via
// RegisterWebAuthnFinish. Must be logged in; label names the key. This is the
// primitive mobile drives with a native authenticator (the OS ceremony); desktop
// goes through RegisterWebAuthn.
func (c *Client) RegisterWebAuthnBegin(ctx context.Context, label string) (optionsJSON []byte, handle string, err error) {
	var begin struct {
		Options json.RawMessage `json:"options"`
		Handle  string          `json:"handle"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/account/2fa/webauthn/register/begin",
		map[string]string{"label": label}, &begin, true); err != nil {
		return nil, "", err
	}
	return []byte(begin.Options), begin.Handle, nil
}

// RegisterWebAuthnFinish submits the authenticator's attestation response to
// complete enrollment for the handle returned by RegisterWebAuthnBegin.
func (c *Client) RegisterWebAuthnFinish(ctx context.Context, handle string, responseJSON []byte) error {
	return c.doJSON(ctx, "POST", "/v1/account/2fa/webauthn/register/finish",
		map[string]json.RawMessage{
			"handle":   mustJSONString(handle),
			"response": json.RawMessage(responseJSON),
		}, nil, true)
}

// RegisterWebAuthn enrolls a new hardware key end-to-end, using authn to produce
// the attestation response. Thin desktop convenience over the Begin/Finish
// primitives. Must be logged in.
func (c *Client) RegisterWebAuthn(ctx context.Context, label string, authn Authenticator) error {
	options, handle, err := c.RegisterWebAuthnBegin(ctx, label)
	if err != nil {
		return err
	}
	response, err := authn.MakeCredential(ctx, options)
	if err != nil {
		return fmt.Errorf("authenticator make credential: %w", err)
	}
	return c.RegisterWebAuthnFinish(ctx, handle, response)
}

// LogInWebAuthnResponse completes a WebAuthn-gated login by submitting an
// already-produced assertion response for tempToken (from the LogIn challenge)
// and persisting the resulting session. The encryption key derived during LogIn
// is already held on the client. This is the primitive mobile drives with a
// native authenticator; desktop goes through LogInWebAuthn.
func (c *Client) LogInWebAuthnResponse(ctx context.Context, tempToken string, responseJSON []byte) error {
	var t Tokens
	if err := c.doJSON(ctx, "POST", "/v1/auth/login/webauthn",
		map[string]json.RawMessage{
			"temp_token": mustJSONString(tempToken),
			"response":   json.RawMessage(responseJSON),
		}, &t, false); err != nil {
		return err
	}
	c.SetTokens(&t)
	return nil
}

// LogInWebAuthn completes a WebAuthn-gated login by running authn's assertion
// ceremony over the challenge options and submitting the result. Thin desktop
// convenience over LogInWebAuthnResponse.
func (c *Client) LogInWebAuthn(ctx context.Context, tempToken string, optionsJSON []byte, authn Authenticator) error {
	response, err := authn.GetAssertion(ctx, optionsJSON)
	if err != nil {
		return fmt.Errorf("authenticator get assertion: %w", err)
	}
	return c.LogInWebAuthnResponse(ctx, tempToken, response)
}

// ListWebAuthnKeys returns the account's registered hardware keys. Must be logged in.
func (c *Client) ListWebAuthnKeys(ctx context.Context) ([]WebAuthnKey, error) {
	var res struct {
		Keys []WebAuthnKey `json:"keys"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/account/2fa/webauthn", nil, &res, true); err != nil {
		return nil, err
	}
	return res.Keys, nil
}

// DeleteWebAuthnKey removes one registered hardware key, re-authenticating with
// the account password (derived on-device into a verifier). Must be logged in;
// email is needed to fetch the KDF salt.
func (c *Client) DeleteWebAuthnKey(ctx context.Context, email, password, keyID string) error {
	salt, err := c.getSalt(ctx, email)
	if err != nil {
		return err
	}
	verifier, _, err := deriveAuth(password, salt)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, "POST", "/v1/account/2fa/webauthn/delete",
		map[string]string{"key_id": keyID, "auth_verifier": verifier}, nil, true)
}

// mustJSONString encodes a string as a JSON RawMessage so heterogeneous request
// bodies can mix strings and pre-encoded JSON in one map.
func mustJSONString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
