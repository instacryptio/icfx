//go:build !android && !ios

// Package fido2 drives a physical FIDO2 security key through the client half
// of the WebAuthn ceremonies (registration attestation + login assertion),
// producing the spec-shaped response JSON the ic-cloud server's go-webauthn
// parses. It is a thin layer over libfido2 (via keys-pub/go-libfido2), the
// same C library ssh-sk and many others build on.
//
// The package carries no user interaction: callers inject the PIN prompt and
// an optional notify sink (Prompts), so ic-cli and ic-app share ONE ceremony
// implementation (the icfx/hardware/chalresp pattern).
//
// Build dependency (desktop only; mobile builds get the stub):
//
//	Linux (Arch):     pacman -S libfido2
//	Linux (Debian):   apt install libfido2-dev
//	Linux (Fedora):   dnf install libfido2-devel
//	macOS:            brew install libfido2
//	Windows:          install libfido2 (mingw or vcpkg)
package fido2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	libfido2 "github.com/keys-pub/go-libfido2"

	"github.com/instacryptio/icfx/cloud"
)

// Supported reports whether this build can drive hardware security keys
// (true on desktop; the mobile stub returns false).
func Supported() bool { return true }

// Prompts injects the user interaction the ceremonies need.
type Prompts struct {
	// PIN obtains the security key's PIN (user verification is required).
	PIN func() (string, error)
	// Notify optionally receives human-readable progress messages
	// (e.g. "Touch your security key…"). Nil discards them.
	Notify func(msg string)
}

// b64 is the WebAuthn wire encoding for binary fields: base64url without padding.
var b64 = base64.RawURLEncoding

// authenticator implements cloud.Authenticator against a physical FIDO2
// device via libfido2: build clientDataJSON, drive the device (touch + PIN,
// UV required), and assemble the response JSON.
type authenticator struct {
	origin  string
	prompts Prompts
}

// NewAuthenticator returns a cloud.Authenticator for the given WebAuthn
// origin (the cloud base URL) with the caller's prompts injected.
func NewAuthenticator(origin string, p Prompts) (cloud.Authenticator, error) {
	if p.PIN == nil {
		return nil, fmt.Errorf("fido2: a PIN prompt is required (user verification is enforced)")
	}
	return &authenticator{origin: origin, prompts: p}, nil
}

func (a *authenticator) notify(msg string) {
	if a.prompts.Notify != nil {
		a.prompts.Notify(msg)
	}
}

// --- options parsing (the subset we need from go-webauthn's option JSON) ------

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"` // base64url
		RP        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			ID          string `json:"id"` // base64url
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"` // base64url
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"` // base64url
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *authenticator) clientDataJSON(typ, challenge string) []byte {
	// challenge is already base64url (no padding), matching WebAuthn clientData.
	cd := map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      a.origin,
		"crossOrigin": false,
	}
	b, _ := json.Marshal(cd)
	return b
}

func openDevice() (*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("listing FIDO2 devices: %w", err)
	}
	if len(locs) == 0 {
		return nil, fmt.Errorf("no FIDO2 security key detected — plug one in and retry")
	}
	dev, err := libfido2.NewDevice(locs[0].Path)
	if err != nil {
		return nil, fmt.Errorf("opening FIDO2 device: %w", err)
	}
	return dev, nil
}

// MakeCredential runs the registration (attestation) ceremony.
func (a *authenticator) MakeCredential(_ context.Context, optionsJSON []byte) ([]byte, error) {
	var opts creationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("parsing creation options: %w", err)
	}
	userID, err := b64.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("decoding user id: %w", err)
	}

	clientData := a.clientDataJSON("webauthn.create", opts.PublicKey.Challenge)
	hash := sha256.Sum256(clientData)

	dev, err := openDevice()
	if err != nil {
		return nil, err
	}
	pin, err := a.prompts.PIN()
	if err != nil {
		return nil, err
	}
	a.notify("Touch your security key…")

	att, err := dev.MakeCredential(
		hash[:],
		libfido2.RelyingParty{ID: opts.PublicKey.RP.ID, Name: opts.PublicKey.RP.Name},
		libfido2.User{ID: userID, Name: opts.PublicKey.User.Name, DisplayName: opts.PublicKey.User.DisplayName},
		libfido2.ES256,
		pin,
		&libfido2.MakeCredentialOpts{UV: libfido2.True},
	)
	if err != nil {
		return nil, fmt.Errorf("make credential: %w", err)
	}

	// libfido2 returns CBOR-wrapped authData; unwrap to raw authenticator data.
	rawAuthData, err := cborUnwrapBytes(att.AuthData)
	if err != nil {
		return nil, fmt.Errorf("decode authdata: %w", err)
	}
	// Assemble a "none"-format attestation object — the server does not require
	// attestation (conveyance preference is unset), and the credential public key
	// travels inside authData regardless.
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": rawAuthData,
	})
	if err != nil {
		return nil, fmt.Errorf("encode attestation object: %w", err)
	}

	resp := map[string]any{
		"id":    b64.EncodeToString(att.CredentialID),
		"rawId": b64.EncodeToString(att.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(attObj),
		},
	}
	return json.Marshal(resp)
}

// GetAssertion runs the login (assertion) ceremony.
func (a *authenticator) GetAssertion(_ context.Context, optionsJSON []byte) ([]byte, error) {
	var opts requestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("parsing request options: %w", err)
	}
	var credIDs [][]byte
	for _, ac := range opts.PublicKey.AllowCredentials {
		id, err := b64.DecodeString(ac.ID)
		if err != nil {
			return nil, fmt.Errorf("decoding allowed credential id: %w", err)
		}
		credIDs = append(credIDs, id)
	}

	clientData := a.clientDataJSON("webauthn.get", opts.PublicKey.Challenge)
	hash := sha256.Sum256(clientData)

	dev, err := openDevice()
	if err != nil {
		return nil, err
	}
	pin, err := a.prompts.PIN()
	if err != nil {
		return nil, err
	}
	a.notify("Touch your security key…")

	assertion, err := dev.Assertion(opts.PublicKey.RPID, hash[:], credIDs, pin, &libfido2.AssertionOpts{UV: libfido2.True})
	if err != nil {
		return nil, fmt.Errorf("assertion: %w", err)
	}

	rawAuthData, err := cborUnwrapBytes(assertion.AuthDataCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode authdata: %w", err)
	}
	// Which credential responded: libfido2 reports it, else the single allowed one.
	credID := assertion.CredentialID
	if len(credID) == 0 && len(credIDs) > 0 {
		credID = credIDs[0]
	}

	respBody := map[string]any{
		"clientDataJSON":    b64.EncodeToString(clientData),
		"authenticatorData": b64.EncodeToString(rawAuthData),
		"signature":         b64.EncodeToString(assertion.Sig),
	}
	if len(assertion.User.ID) > 0 {
		respBody["userHandle"] = b64.EncodeToString(assertion.User.ID)
	}
	resp := map[string]any{
		"id":       b64.EncodeToString(credID),
		"rawId":    b64.EncodeToString(credID),
		"type":     "public-key",
		"response": respBody,
	}
	return json.Marshal(resp)
}

// cborUnwrapBytes decodes a CBOR byte-string (libfido2 returns authData CBOR-
// wrapped) into its raw bytes.
func cborUnwrapBytes(wrapped []byte) ([]byte, error) {
	var raw []byte
	if err := cbor.Unmarshal(wrapped, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
