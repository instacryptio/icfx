package keystore

import "sync"

// keychainIndexMu serializes the read-modify-write of the OS-keychain name
// index. The keychain stores the identity-name list as a single JSON blob (no
// atomic list primitive), so concurrent identity creation/removal would
// otherwise race on ListNames→mutate→Set and lose an entry, making a stored key
// invisible to ListNames. Shared by the linux and darwin keychain backends.
var keychainIndexMu sync.Mutex
