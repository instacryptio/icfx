package cloud

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Client-side password KDF params (match the server's Argon2id tuning).
const (
	kdfMemKiB      = 64 * 1024
	kdfIters       = 3
	kdfParallel    = 4
	kdfKeyLen      = 32
	kdfSaltLen     = 16
	minPasswordLen = 12
)

// deriveAuth turns the account password + per-account salt into an auth verifier
// (sent to the server) and an encryption key (kept on-device). The raw password
// never leaves the client. masterKey is HKDF-split so the verifier can't be used
// to recover encKey — the server, which sees only the verifier, can't derive the
// key that decrypts the identities blob. This is what keeps cloud key-roaming
// zero-knowledge.
func deriveAuth(password string, salt []byte) (authVerifier string, encKey []byte, err error) {
	if len(password) < minPasswordLen {
		return "", nil, fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	master := argon2.IDKey([]byte(password), salt, kdfIters, kdfMemKiB, kdfParallel, kdfKeyLen)
	authKey, err := hkdfKey(master, "instacrypt-cloud-auth")
	if err != nil {
		return "", nil, err
	}
	encKey, err = hkdfKey(master, "instacrypt-cloud-enc")
	if err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(authKey), encKey, nil
}

func hkdfKey(master []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, master, nil, []byte(info))
	out := make([]byte, kdfKeyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf %s: %w", info, err)
	}
	return out, nil
}

func newSalt() ([]byte, error) {
	s := make([]byte, kdfSaltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return s, nil
}
