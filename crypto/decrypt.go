package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

// Decrypt decrypts age-encrypted data using the given hybrid PQ identity string (AGE-SECRET-KEY-PQ-1...).
func Decrypt(data []byte, identityStr string) ([]byte, error) {
	identity, err := age.ParseHybridIdentity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	return plaintext, nil
}

// DecryptWithPassphrase decrypts data that was encrypted with a passphrase.
func DecryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	return DecryptWithPassphraseBytes(data, []byte(passphrase))
}

// DecryptWithPassphraseBytes is the wipeable-bytes core of
// DecryptWithPassphrase — see EncryptWithPassphraseBytes for the rationale.
// The caller retains ownership of pass and wipes it.
func DecryptWithPassphraseBytes(data, pass []byte) ([]byte, error) {
	identity, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, fmt.Errorf("creating scrypt identity: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	return plaintext, nil
}

// DecryptStream returns a reader that age-decrypts r using the given hybrid
// PQ identity, streaming — no full-file buffer materializes (large file
// shares). Header parsing (and recipient mismatch) fails here; body
// integrity failures surface from the returned reader.
func DecryptStream(r io.Reader, identityStr string) (io.Reader, error) {
	identity, err := age.ParseHybridIdentity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	out, err := age.Decrypt(r, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return out, nil
}
