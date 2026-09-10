# chalresp

HMAC-SHA1 challenge-response against OTP slot 2 of Yubico-compatible hardware
keys, implementing `crypto.HardwareKey` for icfx.

It speaks the wire protocols directly — **no libykpers, no libusb** — via
[hidapi][gohid] (and optionally [PC/SC][scard]). This is what `ykman` and
KeePassXC do, and it works on macOS/Windows/Linux/BSD without claiming the USB
interface or any code-signing/entitlement.

icfx does NOT program slots. Slot 2 must be pre-programmed for HMAC-SHA1
challenge-response by the user's tool (`ykman otp chalresp --generate 2`,
Yubico Authenticator, KeePassXC's setup, the OnlyKey app, `nitropy nk3 secrets
add-challenge-response 2 …`) before icfx can use it.

## Supported devices

| Device | Transport | Build | Notes |
|---|---|---|---|
| **YubiKey** (OTP-capable models) | HID (keyboard interface) | default | reference implementation; hardware-validated |
| **OnlyKey** (firmware ≥2.1.0) | HID (keyboard interface) | default | firmware mirrors the YubiKey protocol byte-for-byte |
| **Nitrokey 3** | CCID / PC-SC (Yubico OATH applet) | `-tags pcsc` | implemented to spec, **untested pending hardware** |
| YubiKey over CCID | CCID / PC-SC | `-tags pcsc` | bonus of the PC/SC path |

**Not supported:** Nitrokey Pro / Storage (they have no YubiKey-style HMAC-SHA1
challenge-response — the earlier "NitroKey Pro/Storage" claim was never real).

## Build dependencies

- **Default (HID: YubiKey + OnlyKey)** — cgo via `sstallion/go-hid`, which
  bundles hidapi. Linux uses the hidraw backend (a `libudev` dev package may be
  needed to build; a `/dev/hidraw*` udev rule for VID `1050`/`1d50` for runtime
  access). macOS/Windows need no extra packages.
- **`-tags pcsc` (adds Nitrokey 3 + YubiKey-CCID)** — cgo via `ebfe/scard`.
  macOS (`PCSC.framework`) and Windows (`WinSCard`) ship PC/SC in the system;
  **Linux needs `libpcsclite`-dev to build and `pcscd` running at runtime.**
  Keep `github.com/ebfe/scard` in `go.mod` — a bare `go mod tidy` (without the
  `pcsc` tag) will prune it and break the tagged build.
- **No hardware keys?** Build the module with `-tags nohw` for the pure-Go stub
  — cgo can be disabled entirely and neither dependency is required.

## Multi-transport enumeration

`chalresp.List()` merges HID and (when built with `-tags pcsc`) PC/SC results;
`Open`/`Challenge`/`IsSlot2Programmed` route to the transport the device was
found on. PC/SC enumeration is best-effort — a missing `pcscd` never breaks HID.

## Mobile (Android / iOS) is out of scope

The desktop files are `//go:build !android && !ios && !nohw`; mobile uses the
`chalresp_mobile.go` stub. Actual mobile HW-key support lives in flugo
(`flugo/pkg/hardware/nfckey`) via the Yubico Android/iOS SDKs.

[gohid]: https://github.com/sstallion/go-hid
[scard]: https://github.com/ebfe/scard
