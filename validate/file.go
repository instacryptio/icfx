package validate

import (
	"fmt"

	"github.com/instacryptio/icfx/format"
)

// ValidateICFXFile checks that data is a valid encrypted file (ICFX, Age, or Armored format).
// This performs structural validation only — it does NOT decrypt the data.
func ValidateICFXFile(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("file is empty")
	}

	detected := format.Detect(data)
	switch detected {
	case format.FormatICFX:
		if _, err := format.Deserialize(data); err != nil {
			return fmt.Errorf("invalid ICFX file: %w", err)
		}
		return nil
	case format.FormatArmored:
		if _, _, err := format.ArmorDecode(data); err != nil {
			return fmt.Errorf("invalid armored file: %w", err)
		}
		return nil
	case format.FormatAge:
		// Age format detected by magic bytes — structural validation is sufficient
		return nil
	default:
		return fmt.Errorf("unrecognized file format: not an ICFX, Age, or armored file")
	}
}
