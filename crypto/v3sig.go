package crypto

import (
	"crypto/sha512"
	"hash"
)

// V3SigDomain domain-separates the ICFX v3 container's digest-based signature
// (the message signed is this tag followed by the payload digest). It binds the
// signature to the v3 context so a v3 signature can never be reinterpreted as a
// v2 signature (which is taken over the raw ciphertext) or vice versa — belt and
// suspenders on top of the version-byte dispatch.
const V3SigDomain = "ICFXv3\x00"

// NewV3Digest returns the hash used for the v3 payload digest (SHA-512, 256-bit
// collision resistance). The encrypt (sign) and decrypt (verify) sides MUST use
// this same constructor so their digests agree.
func NewV3Digest() hash.Hash { return sha512.New() }

// V3SignedMessage builds the small, fixed-size message that a v3 container
// signs/verifies: the domain tag followed by the payload digest. Signing this
// (~72 bytes) instead of the whole ciphertext lets the digest be computed
// incrementally, so sign/verify use constant memory.
func V3SignedMessage(payloadDigest []byte) []byte {
	msg := make([]byte, 0, len(V3SigDomain)+len(payloadDigest))
	msg = append(msg, V3SigDomain...)
	msg = append(msg, payloadDigest...)
	return msg
}
