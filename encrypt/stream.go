// Package encrypt produces .icfx containers across all four format profiles
// (see format.Profile). EncryptStream writes the streaming profiles
// (ProfilePrivateStreaming / ProfilePublicStreaming), signing a ciphertext
// digest so encryption runs in constant memory — large files never materialize
// in RAM. EncryptFile is the high-level entry point: it dispatches to the
// streaming path or the buffered path (ProfilePublicBuffered /
// ProfilePrivateBuffered) by profile.
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

// EncryptStream writes a streaming .icfx container to dst: it stream-encrypts
// the plaintext read from src for the hybrid PQ `recipients` (one ciphertext
// any one of them can decrypt), and (when meta.IsSigned) signs a SHA-512 digest
// of the ciphertext with `signer`. The ciphertext is streamed to a temp file and
// hashed on the way, so only the small digest is ever signed — constant memory
// regardless of file size.
//
// profile must be a streaming profile. ProfilePrivateStreaming seals the
// metadata inside the payload (inner framing) and leaves the header empty;
// ProfilePublicStreaming carries the metadata in the plaintext header and writes
// the bare file bytes as the payload (no inner framing).
func EncryptStream(dst io.Writer, src io.Reader, recipients []string, signer *identity.Unlocked, meta format.Metadata, profile format.Profile) error {
	if !profile.Streaming() {
		return fmt.Errorf("EncryptStream requires a streaming profile, got %#x", byte(profile))
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}
	if len(metaJSON) > 65535 {
		return fmt.Errorf("metadata too large: %d bytes", len(metaJSON))
	}
	if meta.IsSigned && signer == nil {
		return fmt.Errorf("meta.IsSigned set but no signer provided")
	}

	// 1. Stream-encrypt src into a temp ciphertext file, hashing the ciphertext.
	tmp, err := os.CreateTemp(config.TempDir(), "icfx-enc-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	digest := crypto.NewV3Digest()
	ew, err := crypto.EncryptStream(io.MultiWriter(tmp, digest), recipients)
	if err != nil {
		return fmt.Errorf("starting encryption: %w", err)
	}

	// Private profiles frame the metadata ahead of the file bytes, inside the
	// encrypted payload: uint16 metaLen || metaJSON || filedata. Public profiles
	// write only the file bytes (metadata rides in the plaintext header).
	var lenbuf [8]byte
	if !profile.Public() {
		binary.BigEndian.PutUint16(lenbuf[:2], uint16(len(metaJSON)))
		if _, err := ew.Write(lenbuf[:2]); err != nil {
			return fmt.Errorf("writing inner metadata length: %w", err)
		}
		if _, err := ew.Write(metaJSON); err != nil {
			return fmt.Errorf("writing inner metadata: %w", err)
		}
	}
	if _, err := io.Copy(ew, src); err != nil {
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

	// 2. Sign the digest (small, fixed-size message).
	var signature []byte
	if meta.IsSigned {
		signature, err = signer.Sign(crypto.V3SignedMessage(digest.Sum(nil)))
		if err != nil {
			return fmt.Errorf("signing: %w", err)
		}
	}
	if len(signature) > 65535 {
		return fmt.Errorf("signature too large: %d bytes", len(signature))
	}

	// 3. Assemble the container: magic|profile|headerMetaLen|[headerMeta]|
	//    payloadLen(u64)|payload|sigLen|sig. Public profiles expose the header
	//    metadata; private profiles leave it empty.
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

// encryptBuffered writes a buffered .icfx container (ProfilePublicBuffered /
// ProfilePrivateBuffered): the whole ciphertext is held in memory and the
// signature covers all of it. Reuses the format/crypto primitives. Suited to
// small data / compatibility; large inputs should use a streaming profile.
func encryptBuffered(dst io.Writer, src io.Reader, recipients []string, signer *identity.Unlocked, meta format.Metadata, profile format.Profile) error {
	if meta.IsSigned && signer == nil {
		return fmt.Errorf("meta.IsSigned set but no signer provided")
	}
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	// Private profiles seal the metadata inside the payload; public profiles
	// carry only the file bytes (metadata rides in the plaintext header).
	payloadPlain := plaintext
	if !profile.Public() {
		payloadPlain, err = format.EncodePayload(meta, plaintext)
		if err != nil {
			return fmt.Errorf("framing inner metadata: %w", err)
		}
	}

	ciphertext, err := crypto.Encrypt(payloadPlain, recipients)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	var signature []byte
	if meta.IsSigned {
		signature, err = signer.Sign(ciphertext) // buffered signs the whole ciphertext
		if err != nil {
			return fmt.Errorf("signing: %w", err)
		}
	}

	c := &format.Container{Profile: profile, Payload: ciphertext, Signature: signature, Private: true}
	if profile.Public() {
		c.Metadata = meta
		c.Private = false
	}
	data, err := c.Serialize()
	if err != nil {
		return fmt.Errorf("serializing container: %w", err)
	}
	if _, err := dst.Write(data); err != nil {
		return err
	}
	return nil
}

// EncryptFile encrypts inPath to a .icfx container at outPath in the given
// profile, dispatching to the streaming or buffered writer. It overwrites
// outPath; callers enforce their own overwrite policy. meta.OriginalFilename and
// the other fields are the caller's to populate.
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

	write := EncryptStream
	if !profile.Streaming() {
		write = encryptBuffered
	}
	encErr := write(out, in, recipients, signer, meta, profile)
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
