package crypto

import (
	"fmt"

	"github.com/awnumar/memguard"
)

// CachedHWResponse satisfies HardwareKey from a pre-fetched response.
//
// Mobile platforms can't reach a hardware key from Go code at runtime —
// NFC/USB transport lives in platform UI (Flutter plugins wrapping
// yubikit-android / yubikit-ios). The Dart layer performs the
// challenge-response interaction, then injects the resulting 20-byte
// HMAC-SHA1 bytes into Go via an ic-app backend method. Crypto code
// downstream (HardwareKeyDecorator) consumes those bytes through this
// type, which behaves like an in-memory HardwareKey.
//
// The response is SEALED in a memguard enclave for its cached lifetime —
// same posture as the session passphrase (the other KEK factor). The
// plaintext exists only transiently inside Challenge(), for the single
// operation's KEK derivation, mirroring the KEK itself.
//
// Lifecycle: the response is valid for as long as the identity's stored
// challenge is unchanged; app-layer caches tie it to the session lock and
// drop it on auto-lock/Lock. A response captured against a ROTATED
// challenge would silently derive the wrong KEK and decryption would fail
// with an opaque scrypt error — setup flows that rewrite the challenge
// must discard any cached response.
type CachedHWResponse struct {
	sealed *memguard.Enclave
	serial string
	family string
}

// NewCachedHWResponse seals the pre-fetched 20-byte HMAC-SHA1 response.
// The caller's buffer is copied first (the Dart side often passes a
// Uint8List backed by FFI-allocated memory that may be wiped after the
// dispatch); memguard then wipes our copy as it seals it. serial and
// family are best-effort device metadata for display / logging; they may
// be empty if the transport layer can't surface them.
func NewCachedHWResponse(response []byte, serial, family string) (*CachedHWResponse, error) {
	if len(response) == 0 {
		return nil, fmt.Errorf("cached hw response: empty")
	}
	buf := make([]byte, len(response))
	copy(buf, response)
	// NewEnclave takes ownership of buf and wipes it after sealing.
	return &CachedHWResponse{
		sealed: memguard.NewEnclave(buf),
		serial: serial,
		family: family,
	}, nil
}

// Challenge ignores the challenge bytes and returns the cached response.
// The challenge argument is required by HardwareKey but unused here —
// the device-side challenge already happened on the Dart side. The
// returned copy is per-operation plaintext; callers hand it straight to
// the KEK derivation and let it fall out of scope with the op.
func (c *CachedHWResponse) Challenge(_ []byte) ([]byte, error) {
	if c == nil || c.sealed == nil {
		return nil, fmt.Errorf("cached hw response: not initialized")
	}
	lb, err := c.sealed.Open()
	if err != nil {
		return nil, fmt.Errorf("cached hw response: unseal: %w", err)
	}
	out := make([]byte, lb.Size())
	copy(out, lb.Bytes())
	lb.Destroy()
	return out, nil
}

// Serial returns the device serial captured at injection time, or empty
// if the transport didn't surface one.
func (c *CachedHWResponse) Serial() string { return c.serial }

// Type returns the device family ("yubikey", "nitrokey", etc.) captured
// at injection time, or empty if unknown.
func (c *CachedHWResponse) Type() string { return c.family }
