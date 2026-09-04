package crypto

import (
	"fmt"
	"io"

	"github.com/instacryptio/icfx/format"
)

// ArmorGitSignatureLabel is the PEM-style armor label for git commit signatures.
const ArmorGitSignatureLabel = "ICFX GIT SIGNATURE"

// ArmorGitFingerprintHeader is the armor header key carrying the signer's
// fingerprint in a git signature. Used by callers to look up the signer's
// public key without trying every known signer.
const ArmorGitFingerprintHeader = "Fingerprint"

// GitSign reads commit content from r, signs it with the given ML-DSA-65
// private key, and writes the armored signature to w. The signer's fingerprint
// is embedded as an armor header so verifiers can look up the public key
// without trying every known signer.
//
// Designed to be invoked by ic-cli's git-sign subcommand wired to git's
// gpg.program. Git pipes the commit content to stdin and reads the armored
// signature from stdout.
func GitSign(r io.Reader, w io.Writer, privKey []byte, fingerprint string) error {
	if fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading content: %w", err)
	}

	sig, err := Sign(data, privKey)
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	armored := ArmorGitSignature(sig, fingerprint)
	if _, err := w.Write(armored); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}
	return nil
}

// GitVerify verifies that armoredSig is a valid signature over the content
// read from r, made with the private key paired with pubKey. The fingerprint
// header (if present) is ignored — pubKey is the source of truth for which
// public key to verify against.
func GitVerify(r io.Reader, armoredSig []byte, pubKey []byte) (bool, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return false, fmt.Errorf("reading content: %w", err)
	}

	sig, _, err := ParseGitSignature(armoredSig)
	if err != nil {
		return false, fmt.Errorf("parsing signature: %w", err)
	}

	return Verify(data, sig, pubKey)
}

// ParseGitSignature extracts the raw signature bytes and the signer's
// fingerprint header (if present) from an armored git signature without
// verifying. Used by callers that need to look up the signer's public key
// before verifying.
//
// If the signature has no fingerprint header (legacy format), fingerprint is
// returned as an empty string.
func ParseGitSignature(armoredSig []byte) (sig []byte, fingerprint string, err error) {
	payload, label, headers, err := format.ArmorDecodeWithHeaders(armoredSig)
	if err != nil {
		return nil, "", err
	}
	if label != ArmorGitSignatureLabel {
		return nil, "", fmt.Errorf("unexpected armor label %q (want %q)", label, ArmorGitSignatureLabel)
	}
	return payload, headers[ArmorGitFingerprintHeader], nil
}

// ArmorGitSignature wraps a raw ML-DSA-65 signature in PEM-style armor for
// git's expected output format, embedding the signer fingerprint as a header.
//
// If fingerprint is empty, no header is included (legacy format).
func ArmorGitSignature(sig []byte, fingerprint string) []byte {
	if fingerprint == "" {
		return format.ArmorEncode(sig, ArmorGitSignatureLabel)
	}
	return format.ArmorEncodeWithHeaders(sig, ArmorGitSignatureLabel, map[string]string{
		ArmorGitFingerprintHeader: fingerprint,
	})
}
