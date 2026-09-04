package decrypt

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
)

// DecryptAndVerifyStream streams an .icfx container from src to dst, verifying
// any signature. v3 containers stream in CONSTANT MEMORY (a large file never
// materializes in RAM); v1/v2 containers fall back to the buffered
// DecryptAndVerify (their uint32 payload length caps them at ~4 GiB anyway).
// Verification is advisory, exactly as DecryptAndVerify — the plaintext is
// written to dst regardless of the outcome; callers inspect the VerifyResult.
func DecryptAndVerifyStream(src io.ReadSeeker, dst io.Writer, u *identity.Unlocked, contactList []contacts.Contact) (VerifyResult, error) {
	// Peek the version, then rewind.
	head := make([]byte, format.HeaderPrefixLen)
	if _, err := io.ReadFull(src, head); err != nil {
		return VerifyResult{}, fmt.Errorf("reading ICFX header: %w", err)
	}
	profile, _, err := format.ParseHeaderPrefix(head)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("parsing ICFX header: %w", err)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return VerifyResult{}, err
	}

	// Buffered profiles (ProfilePublicBuffered / ProfilePrivateBuffered): their
	// uint32 length caps size, so buffering is the pre-existing model.
	if !profile.Streaming() {
		data, err := io.ReadAll(src)
		if err != nil {
			return VerifyResult{}, err
		}
		res, err := DecryptAndVerify(data, u, contactList)
		if err != nil {
			return VerifyResult{}, err
		}
		if _, err := dst.Write(res.Plaintext); err != nil {
			return VerifyResult{}, err
		}
		return res.Verify, nil
	}

	// --- Streaming profiles: two passes over the ciphertext, constant memory ---
	sh, err := format.ParseStreamHeader(src)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("parsing streaming container: %w", err)
	}

	// PASS 1: streaming SHA-512 over the ciphertext payload → digest.
	if _, err := src.Seek(sh.PayloadStart, io.SeekStart); err != nil {
		return VerifyResult{}, err
	}
	h := crypto.NewV3Digest()
	if _, err := io.CopyN(h, src, sh.PayloadLen); err != nil {
		return VerifyResult{}, fmt.Errorf("hashing payload: %w", err)
	}
	digest := h.Sum(nil)

	// Public profile (ProfilePublicStreaming): the signer fingerprint is in the
	// plaintext header, so we can verify BEFORE decrypting; the payload is the
	// bare file bytes (no inner metadata), streamed straight to dst.
	if sh.Profile.Public() {
		verify := VerifyResult{Status: VerifyUnsigned}
		if sh.HeaderMeta.IsSigned && len(sh.Signature) > 0 {
			verify = verifySignature(crypto.V3SignedMessage(digest), sh.Signature, sh.HeaderMeta.SenderFingerprint, u, contactList)
		}
		if _, err := src.Seek(sh.PayloadStart, io.SeekStart); err != nil {
			return VerifyResult{}, err
		}
		pr, err := u.DecryptStream(io.LimitReader(src, sh.PayloadLen))
		if err != nil {
			return VerifyResult{}, fmt.Errorf("decrypting payload: %w", err)
		}
		if _, err := io.Copy(dst, pr); err != nil {
			return VerifyResult{}, fmt.Errorf("writing plaintext: %w", err)
		}
		return verify, nil
	}

	// Private profile (ProfilePrivateStreaming). PASS 2: decrypt the payload.
	// Read the inner metadata (signer fingerprint) off the front, verify the
	// signature (before any file bytes reach dst), then stream the file bytes out.
	if _, err := src.Seek(sh.PayloadStart, io.SeekStart); err != nil {
		return VerifyResult{}, err
	}
	pr, err := u.DecryptStream(io.LimitReader(src, sh.PayloadLen))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("decrypting payload: %w", err)
	}
	meta, err := readInnerMeta(pr)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("reading inner metadata: %w", err)
	}

	verify := VerifyResult{Status: VerifyUnsigned}
	if meta.IsSigned && len(sh.Signature) > 0 {
		// Reuse the shared verify policy (contact→revoked→self); the message is
		// the domain-separated digest instead of the whole ciphertext.
		verify = verifySignature(crypto.V3SignedMessage(digest), sh.Signature, meta.SenderFingerprint, u, contactList)
	}

	if _, err := io.Copy(dst, pr); err != nil {
		return VerifyResult{}, fmt.Errorf("writing plaintext: %w", err)
	}
	return verify, nil
}

// readInnerMeta reads the uint16-length-prefixed inner metadata off the front of
// a decrypted v2/v3 payload stream, leaving r positioned at the file bytes.
func readInnerMeta(r io.Reader) (format.Metadata, error) {
	var lenbuf [2]byte
	if _, err := io.ReadFull(r, lenbuf[:]); err != nil {
		return format.Metadata{}, err
	}
	mbuf := make([]byte, int(binary.BigEndian.Uint16(lenbuf[:])))
	if _, err := io.ReadFull(r, mbuf); err != nil {
		return format.Metadata{}, err
	}
	var meta format.Metadata
	if err := json.Unmarshal(mbuf, &meta); err != nil {
		return format.Metadata{}, err
	}
	return meta, nil
}

// decryptToWriter dispatches a container (ICFX magic) vs a bare-age file, both
// streaming to dst.
func decryptToWriter(isContainer bool, src io.ReadSeeker, dst io.Writer, u *identity.Unlocked, contactList []contacts.Contact) (VerifyResult, error) {
	if isContainer {
		return DecryptAndVerifyStream(src, dst, u, contactList)
	}
	// Bare age file: no container, no signature.
	r, err := u.DecryptStream(src)
	if err != nil {
		return VerifyResult{}, err
	}
	if _, err := io.Copy(dst, r); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Status: VerifyUnsigned}, nil
}

// DecryptFile streams the .icfx (or bare-age) file at inPath to outPath. v3
// containers decrypt in constant memory. It overwrites outPath; callers enforce
// their own overwrite/force policy and atomic-rename if needed. Returns the
// verification outcome (VerifyUnsigned for bare-age input).
func DecryptFile(inPath, outPath string, u *identity.Unlocked, contactList []contacts.Contact) (VerifyResult, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return VerifyResult{}, err
	}
	defer in.Close()

	magic := make([]byte, len(format.MagicBytes))
	if _, err := io.ReadFull(in, magic); err != nil {
		return VerifyResult{}, fmt.Errorf("reading input: %w", err)
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return VerifyResult{}, err
	}

	// 0600: decrypted plaintext may be sensitive; don't leave it world-readable
	// (os.Create would use 0666 & umask, typically 0644).
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return VerifyResult{}, err
	}

	verify, decErr := decryptToWriter(string(magic) == string(format.MagicBytes), in, out, u, contactList)
	closeErr := out.Close()
	if decErr != nil {
		_ = os.Remove(outPath)
		return VerifyResult{}, decErr
	}
	if closeErr != nil {
		_ = os.Remove(outPath)
		return VerifyResult{}, fmt.Errorf("finalizing output: %w", closeErr)
	}
	return verify, nil
}
