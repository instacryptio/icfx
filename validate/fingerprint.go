package validate

import (
	"encoding/hex"
	"fmt"

	"github.com/instacryptio/icfx/crypto"
)

// ValidateFingerprint checks that fp is a valid hex fingerprint of the
// expected length (crypto.FingerprintHexLen).
func ValidateFingerprint(fp string) error {
	if fp == "" {
		return fmt.Errorf("fingerprint is required")
	}
	if len(fp) != crypto.FingerprintHexLen {
		return fmt.Errorf("fingerprint must be exactly %d characters, got %d", crypto.FingerprintHexLen, len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return fmt.Errorf("fingerprint must be hexadecimal: %w", err)
	}
	return nil
}
