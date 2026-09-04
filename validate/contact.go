package validate

import "fmt"

// ValidateContactFields validates fields for manual contact entry.
// Returns the first validation error found, or nil if all fields are valid.
// Pass "" for nickname when the caller has none.
func ValidateContactFields(alias, encPubKey, signPubKey, fingerprint, email, nickname string) error {
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	if len(alias) > 256 {
		return fmt.Errorf("alias is too long (max 256 characters)")
	}
	if err := ValidateNoControlChars("alias", alias); err != nil {
		return err
	}
	if nickname != "" {
		if err := ValidateNoControlChars("nickname", nickname); err != nil {
			return err
		}
	}
	if email != "" {
		if err := ValidateNoControlChars("email", email); err != nil {
			return err
		}
	}
	if err := ValidateEncPubKey(encPubKey); err != nil {
		return fmt.Errorf("alias %q: %w", alias, err)
	}
	if signPubKey != "" {
		if err := ValidateSignPubKey(signPubKey); err != nil {
			return fmt.Errorf("alias %q: %w", alias, err)
		}
	}
	if fingerprint != "" {
		if err := ValidateFingerprint(fingerprint); err != nil {
			return fmt.Errorf("alias %q: %w", alias, err)
		}
	}
	if email != "" {
		if err := validateEmail(email); err != nil {
			return fmt.Errorf("alias %q: %w", alias, err)
		}
	}
	return nil
}
