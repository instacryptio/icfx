package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

// parseRecipients parses one or more hybrid PQ recipient public key strings
// (age1pq1...) into age recipients. age.Encrypt is variadic, so a single
// ciphertext encrypted to N recipients is decryptable by any one of them —
// this is the basis for multi-recipient (group) encryption. At least one
// recipient is required.
func parseRecipients(recipientStrs []string) ([]age.Recipient, error) {
	if len(recipientStrs) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	recipients := make([]age.Recipient, 0, len(recipientStrs))
	for _, s := range recipientStrs {
		r, err := age.ParseHybridRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("parsing recipient: %w", err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

// Encrypt encrypts data for the given hybrid PQ recipient public key strings
// (age1pq1...). Encrypting to multiple recipients yields one ciphertext that
// any one of them can decrypt. Returns the encrypted ciphertext.
func Encrypt(data []byte, recipientStrs []string) ([]byte, error) {
	recipients, err := parseRecipients(recipientStrs)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("creating encryption writer: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("writing encrypted data: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing encryption writer: %w", err)
	}

	return buf.Bytes(), nil
}

// EncryptWithPassphrase encrypts data using a scrypt-derived key from a passphrase.
func EncryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	return EncryptWithPassphraseBytes(data, []byte(passphrase))
}

// EncryptWithPassphraseBytes is the wipeable-bytes core of
// EncryptWithPassphrase: callers holding the passphrase in guarded memory
// pass it as []byte so no additional Go string materializes upstream. The
// ONE unavoidable string conversion happens here, at the age constructor
// (its public API takes a string), with the tightest possible lifetime.
// The caller retains ownership of pass and wipes it.
func EncryptWithPassphraseBytes(data, pass []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(string(pass))
	if err != nil {
		return nil, fmt.Errorf("creating scrypt recipient: %w", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("creating encryption writer: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("writing encrypted data: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing encryption writer: %w", err)
	}

	return buf.Bytes(), nil
}

// EncryptStream returns a WriteCloser that age-encrypts everything written
// to it for the given hybrid PQ recipients, streaming into w — no full-file
// buffer materializes (large file shares). Encrypting to multiple recipients
// yields one ciphertext any one of them can decrypt. Close flushes the final
// chunk and MUST be checked.
func EncryptStream(w io.Writer, recipientStrs []string) (io.WriteCloser, error) {
	recipients, err := parseRecipients(recipientStrs)
	if err != nil {
		return nil, err
	}
	ew, err := age.Encrypt(w, recipients...)
	if err != nil {
		return nil, fmt.Errorf("creating encryption writer: %w", err)
	}
	return ew, nil
}
