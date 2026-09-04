package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// KeyPair holds generated encryption and signing key material
type KeyPair struct {
	EncryptionIdentity  string // AGE-SECRET-KEY-PQ-1... (hybrid X25519 + ML-KEM-768)
	EncryptionRecipient string // age1pq1... (hybrid public key)
	SigningPrivateKey   []byte // ML-DSA-65 (FIPS 204) private key
	SigningPublicKey    []byte // ML-DSA-65 (FIPS 204) public key
	Fingerprint         string // truncated SHA-256 of public keys
}

// GenerateKeyPair creates a new hybrid PQ age identity (X25519 + ML-KEM-768)
// and an ML-DSA-65 (FIPS 204) signing keypair
func GenerateKeyPair() (*KeyPair, error) {
	// Generate hybrid PQ age identity (X25519 + ML-KEM-768)
	ageIdentity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, fmt.Errorf("generating age identity: %w", err)
	}

	// Generate ML-DSA-65 signing keypair
	sigPub, sigPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating signing keypair: %w", err)
	}

	sigPubBytes, err := sigPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling signing public key: %w", err)
	}

	sigPrivBytes, err := sigPriv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling signing private key: %w", err)
	}

	kp := &KeyPair{
		EncryptionIdentity:  ageIdentity.String(),
		EncryptionRecipient: ageIdentity.Recipient().String(),
		SigningPrivateKey:   sigPrivBytes,
		SigningPublicKey:    sigPubBytes,
	}
	kp.Fingerprint = Fingerprint(kp.EncryptionRecipient, kp.SigningPublicKey)

	return kp, nil
}

// GenerateInstacryptID creates a stable identifier from the initial keypair and creation time.
// This ID never changes across key rotations.
func GenerateInstacryptID(encPubKey string, signPubKey []byte, createdAt time.Time) string {
	h := sha256.New()
	h.Write([]byte(encPubKey))
	h.Write(signPubKey)
	_ = binary.Write(h, binary.BigEndian, createdAt.Unix())
	return "IC-" + hex.EncodeToString(h.Sum(nil))[:16]
}
