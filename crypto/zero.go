package crypto

// Zero overwrites b with zero bytes. Use it to wipe transient secret material
// (derived keys, hardware responses, decoded passphrases) as soon as it is no
// longer needed, to shorten the window it lingers in the heap. It is a no-op for
// nil/empty slices. Note this cannot help data already copied into an immutable
// Go string — keep secrets in []byte where possible.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
