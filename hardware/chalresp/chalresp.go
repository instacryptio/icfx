//go:build !android && !ios && !nohw

// Package chalresp performs HMAC-SHA1 challenge-response against the OTP
// slot 2 of a Yubikey (or compatible: NitroKey Pro/Storage, OnlyKey).
//
// This is a thin CGO wrapper around Yubico's libykpers — the same C library
// that KeePassXC, ykman, and pam_yubico build on. We delegate the wire
// protocol entirely; this package's job is just to expose libykpers as a Go
// API that satisfies icfx's crypto.HardwareKey contract.
//
// Build dependency:
//
//	Linux (Arch):     pacman -S yubikey-personalization
//	Linux (Debian):   apt install libykpers-1-dev
//	Linux (Fedora):   dnf install ykpers-devel
//	macOS:            brew install ykpers
//	Windows:          install yubikey-personalization (mingw or vcpkg)
//
// Single-device assumption: this package picks the first detected device
// (libykpers' yk_open_first_key). Multi-device support is post-MVP.
package chalresp

/*
#cgo pkg-config: ykpers-1
#include <stdlib.h>
#include <string.h>
#include <ykpers-1/ykcore.h>
#include <ykpers-1/ykdef.h>
#include <ykpers-1/ykstatus.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// hmacSHA1OutLen is the byte length of an HMAC-SHA1 response.
const hmacSHA1OutLen = 20

// responseBufSize is what we hand to libykpers as the response buffer.
// libykpers internally reads response data in 7-byte chunks until it sees
// a termination marker, and the buffer must be at least 28 bytes (20-byte
// HMAC + 2-byte CRC, padded to the next multiple of 7). KeePassXC uses 64
// — we mirror that for headroom.
const responseBufSize = 64

var (
	// ErrSlotNotConfigured is returned when the targeted slot is empty.
	ErrSlotNotConfigured = errors.New("chalresp: slot not configured")
	// ErrTouchTimeout is returned when the device is configured to require
	// a button press and the user does not touch it within libykpers'
	// internal wait window.
	ErrTouchTimeout = errors.New("chalresp: timeout waiting for device touch")
	// ErrNoDevice is returned when no compatible hardware key is detected.
	ErrNoDevice = errors.New("chalresp: no compatible hardware key detected")
	// ErrNotSupported mirrors the stub build's symbol so callers can reference
	// chalresp.ErrNotSupported in ANY build (cgo desktop, mobile, or -tags nohw).
	// The desktop cgo path never returns it (hardware IS supported here); the
	// mobile/nohw stub returns it from every operation.
	ErrNotSupported = errors.New("chalresp: hardware key challenge-response is not supported in this build")
)

var (
	initOnce sync.Once
	initErr  error
)

// ensureInit lazily initializes libykpers. yk_init() / yk_release() are
// global; we init once for the process lifetime and never explicitly release
// (the OS reclaims on exit).
func ensureInit() error {
	initOnce.Do(func() {
		if C.yk_init() == 0 {
			initErr = errors.New("chalresp: yk_init failed (libykpers/libusb couldn't initialize)")
		}
	})
	return initErr
}

// DeviceDescriptor identifies a connected hardware key. With the
// single-device assumption baked in here, the descriptor is a thin marker
// — Family is filled in for display purposes; Serial may be empty if the
// device's firmware doesn't expose one. Future multi-device support will
// add path / index fields.
type DeviceDescriptor struct {
	Family string // always "yubikey" today (libykpers auto-detects compatible devices)
	Serial string // device serial; empty if not available
}

// List returns descriptors for connected hardware keys. Currently returns
// at most one descriptor (the first device libykpers can open). Returns
// nil, nil if no device is present — the empty list signals "none" without
// being an error condition.
func List() ([]DeviceDescriptor, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	yk := C.yk_open_first_key()
	if yk == nil {
		return nil, nil
	}
	defer C.yk_close_key(yk)

	desc := DeviceDescriptor{Family: "yubikey"}
	if s, err := readSerial(yk); err == nil {
		desc.Serial = s
	}
	return []DeviceDescriptor{desc}, nil
}

// Detect returns the first connected supported device, or ErrNoDevice if
// none is found.
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

// IsSlot2Programmed reports whether slot 2 has a valid HMAC-SHA1
// configuration on the device, by reading YK_STATUS.touchLevel and
// checking the CONFIG2_VALID bit. No challenge issued, no touch required.
func IsSlot2Programmed(_ DeviceDescriptor) (bool, error) {
	if err := ensureInit(); err != nil {
		return false, err
	}
	yk := C.yk_open_first_key()
	if yk == nil {
		return false, ErrNoDevice
	}
	defer C.yk_close_key(yk)

	status := C.ykds_alloc()
	defer C.ykds_free(status)
	if C.yk_get_status(yk, status) == 0 {
		return false, errors.New("chalresp: yk_get_status failed")
	}
	touchLevel := C.ykds_touch_level(status)
	return (touchLevel & C.CONFIG2_VALID) != 0, nil
}

// Key implements crypto.HardwareKey. It records a descriptor at Open time
// but defers the actual USB device handle to each Challenge call — this
// matches KeePassXC's pattern and lets concurrent applications (ykman,
// other ic-cli invocations) take turns with the device cleanly.
type Key struct {
	desc DeviceDescriptor
}

// Open prepares a Key bound to the given device. The actual libykpers
// device handle is opened per Challenge call.
func Open(desc DeviceDescriptor) (*Key, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	return &Key{desc: desc}, nil
}

// Challenge implements crypto.HardwareKey. Sends the challenge bytes to
// slot 2 over libykpers and returns the 20-byte HMAC-SHA1 response.
//
// may_block is set to true so that slots configured to require a button
// touch (KeePassXC's recommended setup) will wait for the user to touch
// rather than failing immediately.
func (k *Key) Challenge(challenge []byte) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, errors.New("chalresp: empty challenge")
	}

	yk := C.yk_open_first_key()
	if yk == nil {
		return nil, ErrNoDevice
	}
	defer C.yk_close_key(yk)

	resp := make([]byte, responseBufSize)
	res := C.yk_challenge_response(
		yk,
		C.uint8_t(C.SLOT_CHAL_HMAC2),
		C.int(1), // may_block: wait for touch if slot requires it
		C.uint(len(challenge)),
		(*C.uchar)(unsafe.Pointer(&challenge[0])),
		C.uint(len(resp)),
		(*C.uchar)(unsafe.Pointer(&resp[0])),
	)
	if res == 0 {
		// Map the one reliably-distinguishable libykpers errno to the documented
		// sentinel; touch-required slots return YK_EWOULDBLOCK when the user
		// doesn't press in time. (libykpers has no distinct "slot not configured"
		// errno, so that case stays a generic failure.)
		if C.yk_errno == C.YK_EWOULDBLOCK {
			return nil, ErrTouchTimeout
		}
		return nil, fmt.Errorf("chalresp: yk_challenge_response failed: %s (slot empty? device removed? wrong slot configuration?)", C.GoString(C.yk_strerror(C.yk_errno)))
	}
	return resp[:hmacSHA1OutLen], nil
}

// Serial returns the device's serial number string. May be empty if the
// device firmware doesn't expose it via the OTP HID interface.
func (k *Key) Serial() string { return k.desc.Serial }

// Type returns the device family string. Currently always "yubikey" since
// libykpers' detection is family-agnostic for compatible devices.
func (k *Key) Type() string { return k.desc.Family }

// Descriptor returns a copy of the device descriptor.
func (k *Key) Descriptor() DeviceDescriptor { return k.desc }

// readSerial queries the device's serial number via libykpers. Returns
// the empty string + nil error if the device doesn't expose a serial
// (older firmware, NitroKey, OnlyKey).
func readSerial(yk *C.YK_KEY) (string, error) {
	var serial C.uint
	if C.yk_get_serial(yk, 0, 0, &serial) == 0 {
		return "", nil
	}
	if serial == 0 {
		return "", nil
	}
	return fmt.Sprintf("%d", uint32(serial)), nil
}
