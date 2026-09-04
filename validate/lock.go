package validate

import (
	"fmt"
	"strings"

	"github.com/instacryptio/icfx/qr"
)

// ValidateLockBundle checks that all fields in a LockBundle are valid.
func ValidateLockBundle(bundle qr.LockBundle) error {
	if bundle.Name == "" {
		return fmt.Errorf("lock bundle: name is required")
	}
	// Labels aren't covered by the self-signature, so a signed lock can still
	// carry terminal-escape / newline bytes — reject them so a hostile lock
	// can't spoof CLI output when displayed.
	for _, f := range []struct{ name, val string }{
		{"name", bundle.Name}, {"alias", bundle.Alias}, {"email", bundle.Email},
	} {
		if err := ValidateNoControlChars(f.name, f.val); err != nil {
			return fmt.Errorf("lock bundle: %w", err)
		}
	}
	// Bound label lengths — they are attacker-controlled (unsigned) and get
	// stored in contacts.json and re-displayed, so an unbounded label is a
	// storage/DoS and display vector.
	if len(bundle.Name) > maxNameLen {
		return fmt.Errorf("lock bundle: name is too long (max %d)", maxNameLen)
	}
	if len(bundle.Alias) > maxAliasLen {
		return fmt.Errorf("lock bundle: alias is too long (max %d)", maxAliasLen)
	}
	if err := ValidateEncPubKey(bundle.EncPubKey); err != nil {
		return fmt.Errorf("lock bundle: %w", err)
	}
	if bundle.SignPubKey != "" {
		if err := ValidateSignPubKey(bundle.SignPubKey); err != nil {
			return fmt.Errorf("lock bundle: %w", err)
		}
	}
	if bundle.Fingerprint != "" {
		if err := ValidateFingerprint(bundle.Fingerprint); err != nil {
			return fmt.Errorf("lock bundle: %w", err)
		}
	}
	if bundle.Email != "" {
		if err := validateEmail(bundle.Email); err != nil {
			return fmt.Errorf("lock bundle: %w", err)
		}
	}
	// Authenticity: a sealed lock must verify (covers fingerprint binding);
	// an unsigned lock that still carries both keys + a fingerprint must at
	// least have that fingerprint bound to the actual keys. Manual-entry
	// locks (no signer) legitimately have no Sig and rely on the binding
	// check plus the human's out-of-band fingerprint comparison.
	if bundle.Sig != "" {
		if err := qr.VerifyLockSelfSig(bundle); err != nil {
			return fmt.Errorf("lock bundle: %w", err)
		}
		return nil
	}
	if bundle.EncPubKey != "" && bundle.SignPubKey != "" && bundle.Fingerprint != "" {
		if err := qr.VerifyFingerprint(bundle); err != nil {
			return fmt.Errorf("lock bundle: %w", err)
		}
	}
	return nil
}

// validateEmail performs a basic email format check.
func validateEmail(email string) error {
	atIdx := strings.Index(email, "@")
	if atIdx < 1 {
		return fmt.Errorf("invalid email: missing @ sign")
	}
	domain := email[atIdx+1:]
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid email: domain must contain a dot")
	}
	if len(email) > 254 {
		return fmt.Errorf("invalid email: too long (max 254 characters)")
	}
	return nil
}
