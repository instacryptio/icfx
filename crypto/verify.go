package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Verify checks an ML-DSA-65 (FIPS 204) signature against the given data and public key.
func Verify(data []byte, signature []byte, publicKey []byte) (bool, error) {
	pubKey := new(mldsa65.PublicKey)
	if err := pubKey.UnmarshalBinary(publicKey); err != nil {
		return false, fmt.Errorf("unmarshaling public key: %w", err)
	}

	// nil context mirrors Sign (which signs with an empty context).
	return mldsa65.Verify(pubKey, data, nil, signature), nil
}
