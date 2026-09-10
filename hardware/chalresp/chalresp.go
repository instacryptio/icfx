//go:build !android && !ios && !nohw

// Package chalresp performs HMAC-SHA1 challenge-response against OTP slot 2 of a
// YubiKey (or a compatible device) to derive a hardware-augmented KEK.
//
// It speaks the YubiKey OTP-over-HID feature-report protocol directly via hidapi
// (github.com/sstallion/go-hid) — no libykpers, no libusb. This is what KeePassXC
// and ykman do, and it works on macOS/Windows/Linux/BSD without claiming the USB
// interface or any entitlement. icfx does not provision hardware keys; slot
// programming is delegated to the user's tool (Yubico Authenticator, ykman,
// KeePassXC, the OnlyKey app, etc.).
//
// Supported today (verified against device firmware / KeePassXC):
//   - YubiKey — the reference implementation of this HID protocol.
//   - OnlyKey (firmware >=2.1.0) — implements the identical HID protocol.
//
// Nitrokey 3 uses a different transport (CCID/PC-SC) and is handled by a separate
// backend (added in a follow-up); Nitrokey Pro/Storage do not support HMAC-SHA1
// challenge-response at all.
//
// The exported surface is unchanged from the former libykpers binding, so
// ic-cli and ic-app compile without modification.
package chalresp

import (
	"errors"
	"fmt"
)

var (
	// ErrSlotNotConfigured is returned when the targeted slot is empty.
	ErrSlotNotConfigured = errors.New("chalresp: slot not configured")
	// ErrTouchTimeout is returned when a slot configured to require a button
	// press is not touched within the wait window.
	ErrTouchTimeout = errors.New("chalresp: timeout waiting for device touch")
	// ErrNoDevice is returned when no compatible hardware key is detected.
	ErrNoDevice = errors.New("chalresp: no compatible hardware key detected")
	// ErrNotSupported mirrors the stub build's symbol so callers can reference
	// chalresp.ErrNotSupported in ANY build (desktop, mobile, or -tags nohw).
	// The desktop path never returns it (hardware IS supported here).
	ErrNotSupported = errors.New("chalresp: hardware key challenge-response is not supported in this build")
)

// backendKind selects the transport a descriptor was found on. The zero value
// is backendHID, so HID descriptors need not set it explicitly.
type backendKind uint8

const (
	backendHID  backendKind = iota // YubiKey / OnlyKey over the OTP HID interface
	backendPCSC                    // Nitrokey 3 / YubiKey over CCID (PC/SC), build tag `pcsc`
)

// DeviceDescriptor identifies a connected hardware key. Family is filled in for
// display; Serial may be empty if the firmware doesn't expose one. The
// unexported routing fields locate the device for Open/Challenge.
type DeviceDescriptor struct {
	Family string // "yubikey", "onlykey", or "nitrokey"
	Serial string // device serial; empty if unavailable

	backend backendKind
	path    string // HID device path (backendHID)
	//lint:ignore U1000 set/read only in the pcsc-tagged backend (chalresp_pcsc.go)
	reader string // PC/SC reader name (backendPCSC)
}

// List returns descriptors for connected hardware keys across all transports.
// Returns an empty slice (not an error) when none are present. PC/SC is
// best-effort: a missing pcscd / no readers must never break HID enumeration.
func List() ([]DeviceDescriptor, error) {
	hids, err := hidList()
	if err != nil {
		return nil, err
	}
	pcs, _ := pcscList() // best-effort; errors (no PC/SC service) are non-fatal
	return append(hids, pcs...), nil
}

// Detect returns the first connected supported device, or ErrNoDevice.
func Detect() (*DeviceDescriptor, error) {
	devices, err := List()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, ErrNoDevice
	}
	return &devices[0], nil
}

// IsSlot2Programmed reports whether slot 2 has a valid HMAC-SHA1 configuration,
// by reading the device status and checking CONFIG2_VALID. No challenge issued,
// no touch required.
func IsSlot2Programmed(desc DeviceDescriptor) (bool, error) {
	if desc.backend == backendPCSC {
		return pcscIsSlot2Programmed(desc)
	}
	return hidIsSlot2Programmed(desc)
}

// Key implements crypto.HardwareKey. It records a descriptor at Open time and
// opens the device per Challenge call. In-process calls are serialized (the
// device's OTP state machine is global to the physical key), and the per-call
// open lets other applications take turns with the device between calls.
type Key struct {
	desc DeviceDescriptor
}

// Open prepares a Key bound to the given device.
func Open(desc DeviceDescriptor) (*Key, error) {
	return &Key{desc: desc}, nil
}

// Challenge sends the challenge bytes to slot 2 and returns the 20-byte
// HMAC-SHA1 response. Slots configured to require a button touch (recommended)
// will wait for the user to touch rather than failing immediately.
func (k *Key) Challenge(challenge []byte) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, errors.New("chalresp: empty challenge")
	}
	if len(challenge) > frameDataSize {
		return nil, fmt.Errorf("chalresp: challenge too long (%d > %d bytes)", len(challenge), frameDataSize)
	}
	if k.desc.backend == backendPCSC {
		return pcscChallenge(k.desc, challenge)
	}
	return hidChallenge(k.desc, challenge, true /* may_block: wait for touch if required */)
}

// Serial returns the device's serial number string (may be empty).
func (k *Key) Serial() string { return k.desc.Serial }

// Type returns the device family string ("yubikey" / "onlykey").
func (k *Key) Type() string { return k.desc.Family }

// Descriptor returns a copy of the device descriptor.
func (k *Key) Descriptor() DeviceDescriptor { return k.desc }

// wipe best-effort zeroes an intermediate buffer that held the secret HMAC
// response. The final returned copy is wiped by the caller (DeriveHardwareKEK);
// this clears the transient accumulators before they're garbage-collected.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// APDU status words + GET RESPONSE chaining, used by the PC/SC backend. Kept
// here (transport-agnostic, no scard dependency) so the DoS bounds are unit-
// testable without a PC/SC stack.
const (
	insGetResp = 0xc0
	swMore     = 0x61 // "61 xx": xx more bytes available via GET RESPONSE
	swOKHi     = 0x90
	swOKLo     = 0x00

	// Bound the GET RESPONSE chain so a malicious/buggy card can't hang the
	// unlock forever (bare "61 01") or grow the buffer without bound. The
	// expected HMAC response is 20 bytes; both caps are far above any legit exchange.
	maxAPDUChain = 16
	maxAPDUBytes = 4096
)

// transmitChain sends an APDU via transmit and follows ISO-7816 "61 xx" GET
// RESPONSE chaining, returning the accumulated data (without status words). It
// errors on any status word other than 90 00 / 61 xx, and bounds both the chain
// length and total size.
func transmitChain(transmit func(apdu []byte) ([]byte, error), apdu []byte) ([]byte, error) {
	var out []byte
	for i := 0; ; i++ {
		if i >= maxAPDUChain {
			return nil, errors.New("chalresp: too many GET RESPONSE chunks")
		}
		resp, err := transmit(apdu)
		if err != nil {
			return nil, fmt.Errorf("chalresp: APDU transmit: %w", err)
		}
		if len(resp) < 2 {
			return nil, errors.New("chalresp: truncated APDU response")
		}
		sw1, sw2 := resp[len(resp)-2], resp[len(resp)-1]
		out = append(out, resp[:len(resp)-2]...)
		if len(out) > maxAPDUBytes {
			return nil, errors.New("chalresp: APDU response too large")
		}
		switch {
		case sw1 == swOKHi && sw2 == swOKLo:
			return out, nil
		case sw1 == swMore:
			apdu = []byte{0x00, insGetResp, 0x00, 0x00, sw2}
		default:
			return nil, fmt.Errorf("chalresp: APDU error SW=%02x%02x", sw1, sw2)
		}
	}
}
