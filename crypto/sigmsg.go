package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// containerCanonicalTag domain-separates container signatures from every other
// message an identity's signing key produces (lock self-signatures, rotations,
// revocations — see qr.lockCanonicalTag and the bundle tags). Each message
// begins with its own length-framed tag, so no two protocols can ever sign the
// same bytes.
const containerCanonicalTag = "ICFX-CONTAINER-V1"

// NewContainerDigest returns the hash used for both digests in a container's
// signed message (SHA-512). The encrypt (sign) and decrypt (verify) sides MUST
// use this same constructor so their digests agree.
func NewContainerDigest() hash.Hash { return sha512.New() }

// SignedMessage builds the fixed-size message a container signature covers:
//
//	tag || profile || SHA-512(plaintext) || SHA-512(ciphertext)
//
// with every field 8-byte big-endian length-framed. Binding the plaintext
// digest proves the signer knew the content, not merely a ciphertext somebody
// else produced. Binding the ciphertext digest ties the signature to this exact
// encryption — recipients included — so a recipient cannot re-encrypt the
// plaintext to a third party under the original signature. Binding the profile
// byte stops a container from being re-labelled as another layout.
func SignedMessage(profile byte, plaintextDigest, ciphertextDigest []byte) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(containerCanonicalTag))
	writeField(&b, []byte{profile})
	writeField(&b, plaintextDigest)
	writeField(&b, ciphertextDigest)
	return b.Bytes()
}

// writeField appends an 8-byte big-endian length followed by the bytes — the
// same framing every other canonical signed message in icfx uses.
func writeField(buf *bytes.Buffer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}
