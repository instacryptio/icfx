package keystore

const (
	keychainService = "icfx"
	encKeySuffix    = "-enc"
	signKeySuffix   = "-sign"
	indexKey        = "_icfx_index"
	probeKey        = "_icfx_probe"
)

// ServiceName is the OS-keychain service under which icfx stores entries.
// Exported so other icfx packages (e.g. the cloud encKey store) file their
// secrets under the same keychain "app" as identity keys.
func ServiceName() string { return keychainService }
