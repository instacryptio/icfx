package crypto

import (
	"encoding/base64"
	"fmt"

	"filippo.io/age"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// DerivePublic recomputes an identity's PUBLIC material — the encryption
// recipient (age1pq1…), the base64 ML-DSA-65 signing public key, and the
// fingerprint — from its PRIVATE keys. Used on import to bind the advertised
// public fields to the keys that are actually present, instead of trusting a
// bundle's self-reported (and unauthenticated) public fields.
func DerivePublic(encIdentity string, signPrivKey []byte) (encPubKey, signPubKeyB64 string, signPubKey []byte, fingerprint string, err error) {
	id, err := age.ParseHybridIdentity(encIdentity)
	if err != nil {
		return "", "", nil, "", fmt.Errorf("parsing encryption identity: %w", err)
	}
	encPubKey = id.Recipient().String()

	priv := new(mldsa65.PrivateKey)
	if err := priv.UnmarshalBinary(signPrivKey); err != nil {
		return "", "", nil, "", fmt.Errorf("parsing signing private key: %w", err)
	}
	pub, ok := priv.Public().(*mldsa65.PublicKey)
	if !ok {
		return "", "", nil, "", fmt.Errorf("unexpected signing public key type")
	}
	signPubKey, err = pub.MarshalBinary()
	if err != nil {
		return "", "", nil, "", fmt.Errorf("marshaling signing public key: %w", err)
	}
	signPubKeyB64 = base64.StdEncoding.EncodeToString(signPubKey)
	fingerprint = Fingerprint(encPubKey, signPubKey)
	return encPubKey, signPubKeyB64, signPubKey, fingerprint, nil
}
