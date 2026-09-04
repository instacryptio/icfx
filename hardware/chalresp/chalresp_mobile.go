//go:build android || ios

// Package chalresp's mobile stub. The desktop implementation
// (chalresp.go) wraps libykpers via CGO, which is desktop-only — Android
// and iOS can't link against ykpers-1. On mobile, ic-app's keystore
// dispatch rejects HW-protected identities before any caller here is
// reached (see ic-app/backend/service.go::keystoreForIdentity), so these
// stubs exist purely to keep the package compilable and the call sites
// in ic-cli/ic-app's backend unchanged across platforms.
//
// Actual mobile HW key support is provided by a separate package in
// flugo (flugo/pkg/hardware/nfckey), which talks to YubiKey via the
// official yubikit-android / yubikit-ios SDKs and to NitroKey 3 NFC via
// custom IsoDep / NFCISO7816Tag clients.
package chalresp

import "errors"

// ErrNotSupported is returned by every function/method on mobile. The
// existing ErrSlotNotConfigured / ErrTouchTimeout / ErrNoDevice errors
// are kept here so type-switch callers and any callers comparing against
// the package's error vars still compile cleanly.
var (
	ErrSlotNotConfigured = errors.New("chalresp: slot not configured")
	ErrTouchTimeout      = errors.New("chalresp: timeout waiting for device touch")
	ErrNoDevice          = errors.New("chalresp: no compatible hardware key detected")
	ErrNotSupported      = errors.New("chalresp: hardware key challenge-response is not supported on this platform (use flugo/pkg/hardware/nfckey for mobile)")
)

// DeviceDescriptor mirrors the desktop type so callers compile unchanged.
type DeviceDescriptor struct {
	Family string
	Serial string
}

// List returns ErrNotSupported on mobile.
func List() ([]DeviceDescriptor, error) {
	return nil, ErrNotSupported
}

// Detect returns ErrNotSupported on mobile.
func Detect() (*DeviceDescriptor, error) {
	return nil, ErrNotSupported
}

// IsSlot2Programmed returns ErrNotSupported on mobile.
func IsSlot2Programmed(_ DeviceDescriptor) (bool, error) {
	return false, ErrNotSupported
}

// Key mirrors the desktop type's exported surface so it still satisfies
// crypto.HardwareKey. All method calls return ErrNotSupported / empty
// strings on mobile.
type Key struct {
	desc DeviceDescriptor
}

// Open returns ErrNotSupported on mobile.
func Open(_ DeviceDescriptor) (*Key, error) {
	return nil, ErrNotSupported
}

// Challenge returns ErrNotSupported on mobile.
func (k *Key) Challenge(_ []byte) ([]byte, error) {
	return nil, ErrNotSupported
}

// Serial returns the empty string on mobile.
func (k *Key) Serial() string { return "" }

// Type returns the empty string on mobile.
func (k *Key) Type() string { return "" }

// Descriptor returns the zero DeviceDescriptor on mobile.
func (k *Key) Descriptor() DeviceDescriptor { return k.desc }
