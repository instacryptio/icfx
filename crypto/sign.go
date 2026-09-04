package crypto

import (
	"crypto"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Sign signs the given data using an ML-DSA-65 (FIPS 204) private key.
// Returns the signature bytes.
func Sign(data []byte, privateKey []byte) ([]byte, error) {
	privKey := new(mldsa65.PrivateKey)
	if err := privKey.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("unmarshaling private key: %w", err)
	}

	// ML-DSA-65 signs with an empty context (nil), deterministic — Verify mirrors this.
	sig, err := privKey.Sign(nil, data, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return sig, nil
}
