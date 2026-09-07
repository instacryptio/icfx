# chalresp

HMAC-SHA1 challenge-response against the OTP slot 2 of Yubikey-compatible
hardware keys (Yubikey, NitroKey Pro/Storage, OnlyKey). CGO wrapper around
[Yubico's libykpers][libykpers] — the same C library KeePassXC, ykman, and
pam_yubico build on. Implements `crypto.HardwareKey` for icfx.

icfx does NOT program slots. Slot 2 must be pre-programmed for HMAC-SHA1
challenge-response by the user's preferred tool (`ykman otp chalresp
--generate 2`, KeePassXC's setup flow, `ykpersonalize`, etc.) before icfx
can use it.

## Build dependency

| Platform | Install |
|---|---|
| Linux (Arch / CachyOS) | `sudo pacman -S yubikey-personalization` |
| Linux (Debian / Ubuntu) | `sudo apt install libykpers-1-dev` |
| Linux (Fedora / RHEL) | `sudo dnf install ykpers-devel` |
| macOS | `brew install ykpers` |
| Windows | install the [yubikey-personalization Windows build][ykpers-win] (bundles the DLL); link via mingw or vcpkg |

`pkg-config --modversion ykpers-1` should report a version after install.
The `#cgo pkg-config: ykpers-1` directive in `chalresp.go` resolves the
include path and link flags from there.

**Don't need hardware keys?** Build the whole module with `-tags nohw` (see the top-level README) to compile the
pure-Go stub instead — then libykpers-1 is not required and cgo can be disabled entirely.

## Single-device today

`chalresp.List()` opens via libykpers' `yk_open_first_key`, which picks the
first detected device. Multi-device support (plug in two keys, choose one
by serial) is post-MVP — the existing `DeviceDescriptor.Serial` field is
populated for forward compatibility.

## Mobile (Android / iOS) is out of scope

Mobile USB / NFC access does not flow through libykpers — Android requires
the Yubico Android SDK (Java/Kotlin via JNI) and iOS requires the Yubico
iOS SDK (Swift, with NFC for non-MFi access). Each is a separate flugo
bridge effort. Desktop only here.

[libykpers]: https://github.com/Yubico/yubikey-personalization
[ykpers-win]: https://developers.yubico.com/yubikey-personalization/Releases/
