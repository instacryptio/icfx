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

// DecryptAndVerifyStream decrypts the .icfx container in src to dst in constant
// memory and verifies its signature. The plaintext is written regardless of
// the outcome and the verdict is returned afterwards — for the current
// profiles it cannot be known sooner, because the signature binds the
// plaintext digest and that completes only with the last byte. Callers that
// must not expose unverified plaintext therefore write dst to a temporary
// location and promote it only once the VerifyResult is acceptable.
//
// Legacy profiles decrypt as they always did; if they claim a signature the
// result is VerifyFailed without any check, since their scheme never bound the
// plaintext and is no longer honoured.
func DecryptAndVerifyStream(src io.ReadSeeker, dst io.Writer, u *identity.Unlocked, contactList []contacts.Contact) (VerifyResult, error) {
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
	switch {
	case !profile.Streaming():
		return decryptLegacyBuffered(src, dst, u)
	case profile.Legacy():
		return decryptLegacyStreaming(src, dst, u)
	}
	return decryptContainer(src, dst, u, contactList)
}

// decryptContainer handles ProfilePrivate / ProfilePublic: one pass over the
// payload that hashes the ciphertext going into age and the plaintext coming
// out, then verifies crypto.SignedMessage against the signer named by the
// sealed metadata.
func decryptContainer(src io.ReadSeeker, dst io.Writer, u *identity.Unlocked, contactList []contacts.Contact) (VerifyResult, error) {
	sh, err := format.ParseStreamHeader(src)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("parsing container: %w", err)
	}
	if sh.Profile == format.ProfilePrivate && !sh.Private {
		return VerifyResult{}, fmt.Errorf("parsing container: private profile carries a header: %w", format.ErrInvalidFormat)
	}
	if _, err := src.Seek(sh.PayloadStart, io.SeekStart); err != nil {
		return VerifyResult{}, err
	}

	ctDigest := crypto.NewContainerDigest()
	ptDigest := crypto.NewContainerDigest()
	payload := io.LimitReader(src, sh.PayloadLen)
	pr, err := u.DecryptStream(io.TeeReader(payload, ctDigest))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("decrypting payload: %w", err)
	}
	meta, err := readInnerMeta(pr)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("reading inner metadata: %w", err)
	}
	if _, err := io.Copy(dst, io.TeeReader(pr, ptDigest)); err != nil {
		return VerifyResult{}, fmt.Errorf("writing plaintext: %w", err)
	}
	// age stops reading at its final chunk; hash whatever payload bytes it
	// left unread so the digest covers the payload exactly as written.
	if _, err := io.Copy(ctDigest, payload); err != nil {
		return VerifyResult{}, fmt.Errorf("hashing payload: %w", err)
	}
	return verdict(sh, meta, ptDigest.Sum(nil), ctDigest.Sum(nil), u, contactList), nil
}

// verdict decides the VerifyResult for a decrypted container. The sealed
// metadata is the only authority on whether the container is signed and by
// whom; every inconsistency between it and what is on the wire is a failure.
func verdict(sh *format.StreamHeader, meta format.Metadata, plaintextDigest, ciphertextDigest []byte, u *identity.Unlocked, contactList []contacts.Contact) VerifyResult {
	if !meta.IsSigned {
		if len(sh.Signature) > 0 {
			// Nobody may bolt a signature onto a file its author left unsigned.
			return VerifyResult{Status: VerifyFailed}
		}
		return VerifyResult{Status: VerifyUnsigned}
	}
	failed := VerifyResult{Status: VerifyFailed, SignerFP: meta.SenderFingerprint}
	switch {
	case meta.SenderFingerprint == "":
		return failed // signed but names no signer: malformed
	case len(sh.Signature) == 0:
		return failed // signature stripped
	case !sh.Private && !sh.HeaderMeta.Equal(meta):
		return failed // advisory header disagrees with the sealed copy
	}
	return verifySignature(crypto.SignedMessage(byte(sh.Profile), plaintextDigest, ciphertextDigest), sh.Signature, meta.SenderFingerprint, u, contactList)
}

// decryptLegacyBuffered decrypts a LegacyProfilePublicBuffered /
// LegacyProfilePrivateBuffered container (uint32 payload length, whole
// ciphertext in memory).
func decryptLegacyBuffered(src io.Reader, dst io.Writer, u *identity.Unlocked) (VerifyResult, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return VerifyResult{}, err
	}
	c, err := format.Deserialize(data)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("parsing ICFX container: %w", err)
	}
	plaintext, err := u.Decrypt(c.Payload)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("decrypting payload: %w", err)
	}
	meta, filedata := c.Metadata, plaintext
	if c.Profile.SealsMetadata() {
		meta, filedata, err = format.DecodePayload(plaintext)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("parsing inner metadata: %w", err)
		}
	}
	if _, err := dst.Write(filedata); err != nil {
		return VerifyResult{}, fmt.Errorf("writing plaintext: %w", err)
	}
	return legacyVerdict(meta, c.Signature), nil
}

// decryptLegacyStreaming decrypts a LegacyProfilePrivateStreaming /
// LegacyProfilePublicStreaming container in constant memory.
func decryptLegacyStreaming(src io.ReadSeeker, dst io.Writer, u *identity.Unlocked) (VerifyResult, error) {
	sh, err := format.ParseStreamHeader(src)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("parsing container: %w", err)
	}
	if _, err := src.Seek(sh.PayloadStart, io.SeekStart); err != nil {
		return VerifyResult{}, err
	}
	pr, err := u.DecryptStream(io.LimitReader(src, sh.PayloadLen))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("decrypting payload: %w", err)
	}
	meta := sh.HeaderMeta
	if sh.Profile.SealsMetadata() {
		meta, err = readInnerMeta(pr)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("reading inner metadata: %w", err)
		}
	}
	if _, err := io.Copy(dst, pr); err != nil {
		return VerifyResult{}, fmt.Errorf("writing plaintext: %w", err)
	}
	return legacyVerdict(meta, sh.Signature), nil
}

// legacyVerdict: legacy signatures bound only the ciphertext and are no longer
// honoured, so anything that claims to be signed fails. The claimed signer
// fingerprint (if the layout carried one) is reported so the caller can say
// who the file said it was from.
func legacyVerdict(meta format.Metadata, signature []byte) VerifyResult {
	if !meta.IsSigned && len(signature) == 0 {
		return VerifyResult{Status: VerifyUnsigned}
	}
	return VerifyResult{Status: VerifyFailed, SignerFP: meta.SenderFingerprint}
}

// readInnerMeta reads the uint16-length-prefixed inner metadata off the front of
// a decrypted payload stream, leaving r positioned at the file bytes.
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

// DecryptFile streams the .icfx (or bare-age) file at inPath to outPath in
// constant memory. It overwrites outPath; callers enforce their own overwrite
// policy. The verdict arrives after the plaintext is on disk (see
// DecryptAndVerifyStream), so callers that gate on it should pass a temporary
// outPath and promote it themselves. Returns VerifyUnsigned for bare-age input.
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
