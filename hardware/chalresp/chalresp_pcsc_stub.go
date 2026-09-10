//go:build !pcsc && !android && !ios && !nohw

package chalresp

// The PC/SC backend (Nitrokey 3 + YubiKey-CCID) is compiled in only with
// `-tags pcsc`, which pulls in a PC/SC stack (libpcsclite + pcscd on Linux).
// Without that tag these no-ops keep the default HID-only desktop build free of
// any PC/SC dependency: List() surfaces no PC/SC devices, so no descriptor is
// ever backendPCSC and the Challenge/IsSlot2Programmed dispatch never routes
// here. Build the release (and Nitrokey support) with `-tags pcsc`.

func pcscList() ([]DeviceDescriptor, error) { return nil, nil }

func pcscIsSlot2Programmed(_ DeviceDescriptor) (bool, error) { return false, ErrNotSupported }

func pcscChallenge(_ DeviceDescriptor, _ []byte) ([]byte, error) { return nil, ErrNotSupported }
