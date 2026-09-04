package format

import (
	"os"
)

// WriteAgeFile writes age-encrypted data directly to a file (mode 0600, to
// match the rest of icfx's on-disk artifacts).
func WriteAgeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
