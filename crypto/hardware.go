package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HardwareKey abstracts a hardware token capable of HMAC-SHA1
// challenge-response (Yubikey-compatible OTP slot 2 protocol).
//
// icfx does not provision hardware keys — slot programming is delegated to
// the user's preferred tool (Yubico's `ykman`, Yubico Authenticator,
// KeePassXC, etc). This interface only models the runtime "send a
// challenge, get a response" capability needed for KEK derivation.
type HardwareKey interface {
	// Challenge sends the given bytes to the device's configured slot,
	// performs HMAC-SHA1 on the device, and returns the response. Most
	// devices require a physical touch to confirm.
	Challenge(challenge []byte) ([]byte, error)
	// Serial returns a stable identifier for the device.
	Serial() string
	// Type returns the device family ("yubikey", "nitrokey", "onlykey").
	Type() string
}

// hardwareKEKInfo is the HKDF info string used to derive the augmented KEK.
// Bumping this would invalidate all existing hardware-protected keystores.
const hardwareKEKInfo = "instacrypt-hardware-kek-v1"

// hardwareKEKLength is the byte length of the derived KEK.
const hardwareKEKLength = 32

// DeriveHardwareKEK combines a user passphrase with a hardware HMAC-SHA1
// challenge response to produce a key-encryption-key.
//
// The hardware response is used as the HKDF salt and the passphrase as the
// input keying material. This means the hardware response is required to
// recompute the same KEK; without the device, the KEK cannot be derived
// from the passphrase alone.
//
// Returns 32 bytes suitable for use as a high-entropy passphrase to age scrypt.
func DeriveHardwareKEK(passphrase string, hwResponse []byte) ([]byte, error) {
	return DeriveHardwareKEKBytes([]byte(passphrase), hwResponse)
}

// DeriveHardwareKEKBytes is the wipeable-bytes core of DeriveHardwareKEK.
// HKDF is byte-native, so this path creates NO passphrase string at all.
// The caller retains ownership of pass and wipes it.
func DeriveHardwareKEKBytes(pass, hwResponse []byte) ([]byte, error) {
	if len(hwResponse) == 0 {
		return nil, fmt.Errorf("empty hardware response")
	}
	// NOTE: an empty passphrase is intentionally allowed. Keychain-origin
	// identities (HWKEKNone) derive the KEK from the hardware response alone,
	// with the OS keychain (Android Keystore / macOS Keychain) as the second
	// factor rather than a passphrase. Whether a passphrase is REQUIRED is a
	// KEK-convention policy the caller enforces (the file-backend passFn rejects
	// an empty passphrase); the primitive must not hardcode it, or HW-only
	// keychain identities can't be unlocked.

	r := hkdf.New(sha256.New, pass, hwResponse, []byte(hardwareKEKInfo))
	kek := make([]byte, hardwareKEKLength)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("deriving KEK: %w", err)
	}
	return kek, nil
}
