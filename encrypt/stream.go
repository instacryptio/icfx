// Package encrypt writes .icfx containers. EncryptStream is the single writer:
// it stream-encrypts the plaintext for the recipients, seals the metadata
// inside the ciphertext, and signs a message binding the plaintext, the
// ciphertext and the profile (crypto.SignedMessage) — in constant memory, so
// file size never matters. EncryptFile is the path-based convenience wrapper.
package encrypt

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
)

// EncryptStream writes an .icfx container to dst: it stream-encrypts the
// plaintext read from src for the hybrid PQ `recipients` (one ciphertext any
// one of them can decrypt), seals meta inside the ciphertext ahead of the file
// bytes, and (when meta.IsSigned) signs crypto.SignedMessage — the profile plus
// SHA-512 digests of the plaintext and of the ciphertext — with `signer`. Both
// digests are computed on the way through, so only the small message is ever
// signed and memory stays constant regardless of file size.
//
// profile must be ProfilePrivate or ProfilePublic; the legacy profiles are
// decrypt-only. ProfilePublic additionally writes an advisory copy of meta to
// the plaintext header.
//
// When signing, meta.SenderFingerprint is set from signer if empty and must
// match it if given — the sealed fingerprint is what recipients resolve the
// signer by, so it can never name anyone but the key that signed.
func EncryptStream(dst io.Writer, src io.Reader, recipients []string, signer *identity.Unlocked, meta format.Metadata, profile format.Profile) error {
	switch profile {
	case format.ProfilePrivate, format.ProfilePublic:
	default:
		return fmt.Errorf("EncryptStream: profile %#x is not writable (legacy profiles are decrypt-only)", byte(profile))
	}
	if meta.IsSigned {
		if signer == nil {
			return fmt.Errorf("meta.IsSigned set but no signer provided")
		}
		switch meta.SenderFingerprint {
		case "":
			meta.SenderFingerprint = signer.Fingerprint()
		case signer.Fingerprint():
		default:
			return fmt.Errorf("meta.SenderFingerprint %q does not match the signer %q", meta.SenderFingerprint, signer.Fingerprint())
		}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}
	if len(metaJSON) > 65535 {
		return fmt.Errorf("metadata too large: %d bytes", len(metaJSON))
	}

	// 1. Stream-encrypt src into a temp ciphertext file, hashing the plaintext
	//    on the way in and the ciphertext on the way out.
	tmp, err := os.CreateTemp(config.TempDir(), "icfx-enc-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	ctDigest := crypto.NewContainerDigest()
	ptDigest := crypto.NewContainerDigest()
	ew, err := crypto.EncryptStream(io.MultiWriter(tmp, ctDigest), recipients)
	if err != nil {
		return fmt.Errorf("starting encryption: %w", err)
	}

	// The sealed metadata leads the plaintext: uint16 metaLen || metaJSON ||
	// file bytes. Only the file bytes feed the plaintext digest — the framing
	// is inside the ciphertext, which the ciphertext digest covers.
	var lenbuf [8]byte
	binary.BigEndian.PutUint16(lenbuf[:2], uint16(len(metaJSON)))
	if _, err := ew.Write(lenbuf[:2]); err != nil {
		return fmt.Errorf("writing inner metadata length: %w", err)
	}
	if _, err := ew.Write(metaJSON); err != nil {
		return fmt.Errorf("writing inner metadata: %w", err)
	}
	if _, err := io.Copy(ew, io.TeeReader(src, ptDigest)); err != nil {
		return fmt.Errorf("encrypting payload: %w", err)
	}
	if err := ew.Close(); err != nil { // flushes the age final chunk into the temp file
		return fmt.Errorf("finalizing ciphertext: %w", err)
	}

	fi, err := tmp.Stat()
	if err != nil {
		return fmt.Errorf("sizing ciphertext: %w", err)
	}
	payloadLen := fi.Size()

	// 2. Sign the message binding profile, plaintext and ciphertext.
	var signature []byte
	if meta.IsSigned {
		signature, err = signer.Sign(crypto.SignedMessage(byte(profile), ptDigest.Sum(nil), ctDigest.Sum(nil)))
		if err != nil {
			return fmt.Errorf("signing: %w", err)
		}
	}
	if len(signature) > 65535 {
		return fmt.Errorf("signature too large: %d bytes", len(signature))
	}

	// 3. Assemble the container: magic|profile|headerMetaLen|[headerMeta]|
	//    payloadLen(u64)|payload|sigLen|sig. Only ProfilePublic carries the
	//    advisory header copy.
	var headerMeta []byte
	if profile.Public() {
		headerMeta = metaJSON
	}
	if _, err := dst.Write(format.MagicBytes); err != nil {
		return err
	}
	if _, err := dst.Write([]byte{byte(profile)}); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(lenbuf[:2], uint16(len(headerMeta)))
	if _, err := dst.Write(lenbuf[:2]); err != nil {
		return err
	}
	if len(headerMeta) > 0 {
		if _, err := dst.Write(headerMeta); err != nil {
			return err
		}
	}
	binary.BigEndian.PutUint64(lenbuf[:8], uint64(payloadLen))
	if _, err := dst.Write(lenbuf[:8]); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(dst, tmp); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}
	binary.BigEndian.PutUint16(lenbuf[:2], uint16(len(signature)))
	if _, err := dst.Write(lenbuf[:2]); err != nil {
		return err
	}
	if len(signature) > 0 {
		if _, err := dst.Write(signature); err != nil {
			return err
		}
	}
	return nil
}

// EncryptFile encrypts inPath to an .icfx container at outPath in the given
// profile. It overwrites outPath; callers enforce their own overwrite policy.
// meta.OriginalFilename and the other fields are the caller's to populate.
func EncryptFile(inPath, outPath string, recipients []string, signer *identity.Unlocked, meta format.Metadata, profile format.Profile) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}

	encErr := EncryptStream(out, in, recipients, signer, meta, profile)
	closeErr := out.Close()
	if encErr != nil {
		_ = os.Remove(outPath)
		return encErr
	}
	if closeErr != nil {
		_ = os.Remove(outPath)
		return fmt.Errorf("finalizing output: %w", closeErr)
	}
	return nil
}
