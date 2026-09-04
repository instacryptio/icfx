package cloud

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is the structured error the server returns in JSON form on non-2xx.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// CurrentVersion is set when the server returns a 409 from a blob PUT.
	CurrentVersion int64 `json:"current_version,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("ic-cloud %d %s: %s", e.Status, e.Code, e.Message)
}

// IsConflict reports whether err is a blob-versioning conflict. Callers
// should refetch the current blob, merge, and retry on this case.
func IsConflict(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

// IsUnauthorized reports whether err is a 401 — typically means the access
// token expired and the caller should Refresh().
func IsUnauthorized(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// IsPaymentRequired reports whether err is a 402 — the account's plan doesn't
// allow the operation (e.g. storage quota exceeded or backup not on the tier).
// Callers should prompt the user to upgrade.
func IsPaymentRequired(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusPaymentRequired
}

// IsDeviceLimit reports whether err is the account's device (session) cap —
// the user must log a device out (Devices UI / `icc cloud sessions rm`) or
// reset the password before another login succeeds.
func IsDeviceLimit(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "device_limit_reached"
}

// IsAlreadySubscribed reports the checkout double-billing guard's 409: the
// account already has a live subscription (possibly just adopted/healed
// server-side from the provider). Clients should refresh the plan view and
// route further changes through the plan-change path, not surface an error.
func IsAlreadySubscribed(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "subscription_exists"
}

// ErrTOTPRequired signals that LogIn returned a TOTP challenge instead of
// tokens — prompt for a TOTP (or recovery) code and call LogInTOTP /
// LogInRecovery with the TempToken from LoginTOTPChallenge.
var ErrTOTPRequired = errors.New("totp required")

// ErrEmailCodeRequired signals that LogIn returned an email-code challenge — the
// server has emailed a one-time code; prompt for it and call LogInEmail with the
// TempToken from LoginTOTPChallenge.
var ErrEmailCodeRequired = errors.New("email code required")

// ErrWebAuthnRequired signals that LogIn returned a WebAuthn (hardware-key)
// challenge — run the FIDO2 assertion over LoginTOTPChallenge.WebAuthnOptions and
// call LogInWebAuthn with the TempToken.
var ErrWebAuthnRequired = errors.New("webauthn assertion required")

// ErrEmailRequired reports a publish attempt for an identity without an
// email — the directory requires one so published identities stay findable
// by a stable identifier. Callers should prompt the user to add an email to
// the identity, with their platform's remediation hint.
var ErrEmailRequired = errors.New("publishing requires an email on this identity")

// ErrFingerprintTaken reports that the fingerprint is already published by a
// DIFFERENT account (server 409). Squatting is denial-only — a republished
// public lock decrypts nothing — but the publish is rejected.
var ErrFingerprintTaken = errors.New("this lock's fingerprint is already published by another account")
