# icfx - Instacrypt Cryptographic Library


### 👁️‍🗨️ Summary
---

A Go library providing post-quantum ready encryption, signing, key management, and the `.icfx` container format for [Instacrypt](https://instacrypt.io).


### 🪶 Features
---

- Hybrid post-quantum encryption ([Age](https://github.com/FiloSottile/age) X25519 + ML-KEM-768)
- Digital signatures (ML-DSA-65 / FIPS 204)
- Git commit signing (post-quantum ML-DSA-65 signatures via `GitSign`) — a drop-in for git's `gpg.program`
- `.icfx` binary container format (metadata + payload + signature) across four format profiles
- Constant-memory streaming encryption for large files (digest-signed)
- Container decrypt with signature verification (against current keys, rotated-out keys, and self)
- Encrypted file sharing (upload/download of pre-encrypted `.icfx` ciphertext)
- Contact groups / multi-recipient encryption
- Cloud client SDK (auth, billing, encrypted blob storage, directory, notification sync)
- Key fingerprinting (128-bit, truncated SHA-256)
- PEM-style armor encoding/decoding
- Format auto-detection (ICFX, Age, Armored)
- OS keychain integration (macOS Keychain, Linux libsecret, Windows Credential Manager)
- File-based keystore fallback with passphrase encryption
- Optional hardware-key support (Yubikey challenge-response, FIDO2/WebAuthn security keys)
- Encrypted-at-rest identity storage (per-identity metadata sealed to its own key)
- Memory-protected operations API (`identity.Unlocked`) — private keys held in [memguard](https://github.com/awnumar/memguard) enclaves; `Sign`, `Decrypt`, `Encrypt`, `GitSign`, and `Export` operations never expose plaintext key bytes to callers
- Passphrase-protected identity export/import (`Unlocked.Export` / `identity.Import`)
- Identity removal with cloud-safe handoff — deleting the default re-keys its self-lock cloud data (contacts/groups/settings/notifications) to a chosen successor; the last identity is protected, with an opt-in force delete (its cloud data is then unreadable until re-keyed from a device that still holds the up-to-date copy)
- Profile export/import (encrypted tarball)
- TOML-based configuration (XDG-compliant paths)


### 📦 Packages
---

| Package | Description |
|---------|-------------|
| `crypto` | Hybrid encryption (Age + ML-KEM-768), ML-DSA-65 signing, git commit signing, key generation, 128-bit fingerprinting |
| `format` | ICFX binary container format, Age format support, PEM armor, format detection |
| `encrypt` | Produces `.icfx` containers across all four format profiles, including constant-memory digest-signed streaming |
| `decrypt` | Container-aware decrypt and signature verification (resolves the signer against contacts, rotated-out keys, and self) |
| `recipient` | Resolves a recipient reference (alias, email, nickname, contact, own identity, or raw `age1pq1` lock) to key material, with one shared resolution order across clients |
| `identity` | Encrypted identity store, primary identity enforcement, and `Unlocked` operations API (memguard-backed Sign/Decrypt/Encrypt/GitSign/Export) |
| `identity/handoff` | Identity removal & set-default orchestration — re-keys self-lock cloud data (contacts/groups/settings/notifications) to a successor/new default; blocks last-identity removal unless forced |
| `contacts` | Contact store (public keys + labels only; no secrets) with unique alias management |
| `bundle` | Unified `Parse()` of lock/revocation/rotation bundles, plus revocation and rotation bundle creation |
| `qr` | QR and animated-QR (GIF) encoding/decoding of lock bundles for key exchange |
| `groups` | Named contact groups (lists of contact IDs) for encrypting or sharing to several people at once |
| `sharing` | Transport for encrypted file shares — uploads/downloads pre-encrypted `.icfx` ciphertext (does no cryptography itself) |
| `cloud` | Go client SDK for Instacrypt Cloud: transport, auth, billing, encrypted blob CRUD, directory, notification sync |
| `keystore` | Abstract key storage — OS keychain or encrypted file backend |
| `hardware/chalresp` | Optional YubiKey/compatible HMAC-SHA1 challenge-response over HID (go-hid); optional PC/SC backend for Nitrokey 3 |
| `hardware/fido2` | Optional FIDO2/WebAuthn security-key client (libfido2) — registration and login |
| `config` | TOML configuration and XDG-compliant path management |
| `profile` | Full profile backup/restore via encrypted tarballs |
| `validate` | Input validation for keys, fingerprints, files, lock bundles, and contact fields |


### ⚙️ Requirements
---

- Go 1.26.6+
- **Hardware-key support is optional and can be switched off at build time.** `hardware/chalresp` (YubiKey) and
  `hardware/fido2` (FIDO2/WebAuthn) pull in the cgo C libraries listed below. If you use icfx only for encryption,
  build with **`-tags nohw`** to stub them out — no cgo, no C libraries required:
  ```
  CGO_ENABLED=0 go build -tags nohw ./...
  ```
  (On macOS the OS keychain still uses the system Security.framework; use file-based key storage for a fully
  cgo-free build there.)
- OS keychain (optional — falls back to file-based storage)
- libudev (optional — required only if you import `hardware/chalresp` for hardware-key support). `hardware/chalresp`
  talks to the device directly over HID via [go-hid](https://github.com/sstallion/go-hid); on Linux its hidraw
  backend links libudev. macOS and Windows use the system HID APIs — no extra library needed there.
  - Linux (Debian/Ubuntu): `sudo apt install libudev-dev`
  - Linux (Arch): `sudo pacman -S systemd` (provides libudev)
  - Linux (Fedora): `sudo dnf install systemd-devel`
  - macOS / Windows: none (system HID)
  - Optional PC/SC backend (Nitrokey 3): build with `-tags pcsc`. On Linux this additionally needs
    `libpcsclite-dev` + a running `pcscd`; macOS/Windows use the system PC/SC service.
  - See `hardware/chalresp/README.md` for details
- libfido2 (optional — required only if you import `hardware/fido2` for FIDO2/WebAuthn security keys)
  - Linux (Debian/Ubuntu): `sudo apt install libfido2-dev`
  - Linux (Arch): `sudo pacman -S libfido2`
  - Linux (Fedora): `sudo dnf install libfido2-devel`
  - macOS: `brew install pkg-config libfido2 openssl@3` — go-libfido2 links openssl statically, so export the
    keg-only paths so cgo can find them:
    ```
    export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$PKG_CONFIG_PATH"
    export CGO_CFLAGS="-I$(brew --prefix openssl@3)/include"
    export CGO_LDFLAGS="-L$(brew --prefix openssl@3)/lib"
    ```
  - Windows: install libfido2; link via mingw or vcpkg


### ⚗️ Tech Stack
---

This library was built with [Go](https://go.dev/), [Age](https://github.com/FiloSottile/age), [CIRCL](https://github.com/cloudflare/circl), and [go-keyring](https://github.com/zalando/go-keyring).


### 📜 License
---

[Apache 2.0](LICENSE)


### 💰 Support
---

This project hopes to remain sustainable via the Instacrypt Cloud paid plans. By including the cloud service and exposing the paid subscription in your implementation will automatically help support the project.

Otherwise, you can support this project simply by giving our repo a star or buying us a coffee:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://www.buymeacoffee.com/3dfosi)

Be sure to mention "Instacrypt" in the "Say something nice..." field so we know what project the coffee is for. 🙏

### 🔌 Used By

- [Instacrypt CLI](https://github.com/instacryptio/ic-cli)
- [Instacrypt App](https://github.com/instacryptio/ic-app)

