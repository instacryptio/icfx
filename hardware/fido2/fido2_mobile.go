//go:build android || ios || nohw

// No-hardware stub: used on mobile (android/ios) AND on desktop with
// `-tags nohw` (encryption-only consumers who don't want the libfido2 cgo
// dependency). libfido2 (CGO, USB HID) is desktop-only. Mobile hardware-key
// support means platform passkey APIs (Play Services FIDO2 / ASAuthorization)
// — a separate integration, deferred.
package fido2

import (
	"errors"

	"github.com/instacryptio/icfx/cloud"
)

// Supported reports whether this build can drive hardware security keys.
func Supported() bool { return false }

// Prompts injects the user interaction the ceremonies need (unused on mobile).
type Prompts struct {
	PIN    func() (string, error)
	Notify func(msg string)
}

// NewAuthenticator always fails on mobile builds.
func NewAuthenticator(origin string, p Prompts) (cloud.Authenticator, error) {
	return nil, errors.New("hardware security keys aren't supported on mobile yet — use the desktop app or CLI")
}
