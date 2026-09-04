package validate

import (
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ValidateEncPubKey checks that key is a valid hybrid PQ encryption lock (age1pq1...).
// The function name keeps the generic "PubKey" suffix to match the rest of icfx's
// internal API; the error messages it returns use the user-facing "lock" vocabulary.
func ValidateEncPubKey(key string) error {
	if key == "" {
		return fmt.Errorf("encryption lock (public key) is required")
	}
	if !strings.HasPrefix(key, "age1pq1") {
		return fmt.Errorf("encryption lock (public key) must start with age1pq1")
	}
	if _, err := age.ParseHybridRecipient(key); err != nil {
		return fmt.Errorf("invalid encryption lock (public key): %w", err)
	}
	return nil
}

// ValidateEncIdentity checks that key is a valid hybrid PQ encryption identity (AGE-SECRET-KEY-PQ-1...).
func ValidateEncIdentity(key string) error {
	if key == "" {
		return fmt.Errorf("encryption identity is required")
	}
	if !strings.HasPrefix(key, "AGE-SECRET-KEY-PQ-1") {
		return fmt.Errorf("encryption identity must start with AGE-SECRET-KEY-PQ-1")
	}
	if _, err := age.ParseHybridIdentity(key); err != nil {
		return fmt.Errorf("invalid encryption identity: %w", err)
	}
	return nil
}

// ValidateSignPubKey checks that base64Key is a valid base64-encoded ML-DSA-65 (FIPS 204) lock.
// As with ValidateEncPubKey, the function name keeps "PubKey" for internal API
// consistency; user-facing errors use "lock (public key)".
func ValidateSignPubKey(base64Key string) error {
	if base64Key == "" {
		return fmt.Errorf("signing lock (public key) is required")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return fmt.Errorf("signing lock (public key) is not valid base64: %w", err)
	}
	pubKey := new(mldsa65.PublicKey)
	if err := pubKey.UnmarshalBinary(keyBytes); err != nil {
		return fmt.Errorf("invalid signing lock (public key): %w", err)
	}
	return nil
}

// ValidateSignPrivateKey checks that keyBytes is a valid ML-DSA-65 (FIPS 204) private key.
func ValidateSignPrivateKey(keyBytes []byte) error {
	if len(keyBytes) == 0 {
		return fmt.Errorf("signing private key is required")
	}
	privKey := new(mldsa65.PrivateKey)
	if err := privKey.UnmarshalBinary(keyBytes); err != nil {
		return fmt.Errorf("invalid signing private key: %w", err)
	}
	return nil
}
