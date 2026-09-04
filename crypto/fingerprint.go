package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// FingerprintHexLen is the fingerprint length in hex characters: 32 hex = 128
// bits of SHA-256, the out-of-band verification anchor and the value that
// gates key trust. 128 bits puts a targeted second-preimage far out of reach.
const FingerprintHexLen = 32

// Fingerprint computes a truncated SHA-256 fingerprint from the encryption
// public key string and signing public key bytes: the first FingerprintHexLen
// hex characters of SHA-256(encPubKey || signPubKey).
func Fingerprint(encPubKey string, signPubKey []byte) string {
	h := sha256.New()
	h.Write([]byte(encPubKey))
	h.Write(signPubKey)
	return hex.EncodeToString(h.Sum(nil))[:FingerprintHexLen]
}

// FormatGrouped renders a fingerprint in space-separated blocks of 4 for
// readable out-of-band comparison (e.g. "a1b2 c3d4 e5f6 0718 ..."). Both
// clients use this so the displayed grouping never diverges.
func FormatGrouped(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		b.WriteString(fp[i:end])
	}
	return b.String()
}
