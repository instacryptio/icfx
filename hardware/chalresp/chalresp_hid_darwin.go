//go:build darwin && !android && !ios && !nohw

package chalresp

import hid "github.com/sstallion/go-hid"

// hidConfigureOpen makes the macOS backend open devices NON-exclusively
// (kIOHIDOptionsTypeNone) instead of hidapi's default kIOHIDOptionsTypeSeizeDevice.
// Seizing a keyboard-class HID device (the YubiKey OTP interface) requires more
// privilege than the "Input Monitoring" permission grants, so a seizing open fails
// with kIOReturnNotPermitted (0xE00002C1) even when Input Monitoring IS granted.
// Opening non-exclusively — as ykman does — succeeds with the permission. This only
// affects challenge-response feature reports, which never need exclusive access.
func hidConfigureOpen() {
	hid.SetOpenExclusive(false)
}
