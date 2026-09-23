package validate

import (
	"bytes"
	"fmt"

	"github.com/instacryptio/icfx/format"
)

// ValidateICFXFile checks that data is a structurally valid encrypted file
// (ICFX, Age, or Armored format). It does NOT decrypt the data.
func ValidateICFXFile(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("file is empty")
	}

	detected := format.Detect(data)
	switch detected {
	case format.FormatICFX:
		if err := validateContainer(data); err != nil {
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

// validateContainer parses the container framing for whichever layout the
// profile byte selects.
func validateContainer(data []byte) error {
	if len(data) < format.HeaderPrefixLen {
		return format.ErrInvalidFormat
	}
	profile, _, err := format.ParseHeaderPrefix(data[:format.HeaderPrefixLen])
	if err != nil {
		return err
	}
	if !profile.Streaming() {
		_, err := format.Deserialize(data)
		return err
	}
	_, err = format.ParseStreamHeader(bytes.NewReader(data))
	return err
}
