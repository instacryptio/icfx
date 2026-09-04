package format

// Format represents the detected file format.
type Format int

const (
	FormatUnknown Format = iota
	FormatICFX
	FormatAge
	FormatArmored
)

func (f Format) String() string {
	switch f {
	case FormatICFX:
		return "icfx"
	case FormatAge:
		return "age"
	case FormatArmored:
		return "armored"
	default:
		return "unknown"
	}
}

// ageMagic is the beginning of age-encrypted files
var ageMagic = []byte("age-encryption.org")

// Detect determines the format of the given data by examining magic bytes.
func Detect(data []byte) Format {
	if IsArmored(data) {
		return FormatArmored
	}
	if len(data) >= 4 && string(data[0:4]) == string(MagicBytes) {
		return FormatICFX
	}
	if len(data) >= len(ageMagic) && string(data[0:len(ageMagic)]) == string(ageMagic) {
		return FormatAge
	}
	return FormatUnknown
}
