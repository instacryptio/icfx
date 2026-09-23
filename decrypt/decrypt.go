// Package decrypt is icfx's container-aware decrypt + signature-verification
// path: it parses an .icfx container, decrypts it with the caller's unlocked
// identity, and — when the sealed metadata says the container is signed —
// verifies the signature against the caller's contacts (current keys, then
// rotated-out/previous keys) and finally the unlocked identity itself. It is
// the single implementation shared by every client (local decrypt, file-share
// receive, and signature checks), so verification policy can never drift
// between them.
//
// The signature covers the plaintext, the ciphertext and the profile byte
// (crypto.SignedMessage), and the signer is resolved only from the metadata
// sealed inside the ciphertext — never from a plaintext header. Verification
// is therefore always post-decrypt, and for the streaming path the verdict is
// known only after the last plaintext byte has been written to dst.
//
// The library never withholds plaintext: the bytes are always written and the
// VerifyResult reports what was found. Callers gate on it — a VerifyFailed
// means the file claims a signer it cannot prove, so clients decrypt to a
// temporary location, ask the user, and only then promote or discard.
package decrypt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
)

// VerifyStatus is the outcome of the signature check on a decrypted container.
type VerifyStatus int

const (
	// VerifyUnsigned: the container carries no signature and claims none.
	VerifyUnsigned VerifyStatus = iota
	// VerifyOK: the signature verified against a known signer (see
	// VerifyResult for who) and binds the plaintext that was written.
	VerifyOK
	// VerifyFailed: the container claims a signature that does not hold —
	// a signer key was resolved but the signature or the plaintext does not
	// match it, the signature was stripped or bolted on, an advisory header
	// disagrees with the sealed metadata, or the container is a legacy layout
	// whose signature scheme is no longer honoured. Treat as tampered.
	VerifyFailed
	// VerifyUnknownSigner: the container is signed by a fingerprint that
	// matches no contact and not the unlocked identity, so the signature could
	// not be checked. The sender may simply not be imported yet.
	VerifyUnknownSigner
)

// String names the status for logs and fallthrough display arms.
func (s VerifyStatus) String() string {
	switch s {
	case VerifyUnsigned:
		return "unsigned"
	case VerifyOK:
		return "ok"
	case VerifyFailed:
		return "failed"
	case VerifyUnknownSigner:
		return "unknown-signer"
	}
	return fmt.Sprintf("VerifyStatus(%d)", int(s))
}

// VerifyResult is the structured verification outcome. Clients render it however
// they like (styled terminal lines, a bridge JSON string, an exit code) — the
// library composes no display text.
type VerifyResult struct {
	Status VerifyStatus
	// SignerFP is the sender fingerprint from the SEALED metadata. Set whenever
	// the container names a signer, so callers can show who it claims to be
	// even on VerifyFailed / VerifyUnknownSigner.
	SignerFP string
	// SignerAlias is the matched contact's alias (set on VerifyOK via a contact).
	SignerAlias string
	// SignerIdentity is the local identity name (set on VerifyOK via self-sign).
	SignerIdentity string
	// UsedRevokedKey reports that the match was against a contact's rotated-out
	// (previous) key rather than its current one; RevokedAt is when it was revoked.
	UsedRevokedKey bool
	RevokedAt      time.Time
}

// Result bundles the decrypted file bytes with the verification outcome.
type Result struct {
	Plaintext []byte
	Verify    VerifyResult
}

// DecryptAndVerify is the in-memory form of DecryptAndVerifyStream: the whole
// container is in data and the whole plaintext comes back in Result. See the
// package doc for the verification contract.
func DecryptAndVerify(data []byte, u *identity.Unlocked, contactList []contacts.Contact) (Result, error) {
	var out bytes.Buffer
	verify, err := DecryptAndVerifyStream(bytes.NewReader(data), &out, u, contactList)
	if err != nil {
		return Result{}, err
	}
	return Result{Plaintext: out.Bytes(), Verify: verify}, nil
}

// verifySignature resolves the signer's public key for senderFP and checks
// signature over message. Search order: every contact whose current key
// carries the fingerprint (the store does not enforce uniqueness), then
// contacts' previous/revoked keys, then the unlocked identity itself.
// Fingerprints compare case-insensitively, as contacts.FindByFingerprint does.
// A fingerprint that resolves to a usable key whose signature does not verify
// is VerifyFailed; one that resolves to nothing usable is VerifyUnknownSigner
// (an undecodable stored key says nothing about the file).
func verifySignature(message, signature []byte, senderFP string, u *identity.Unlocked, contactList []contacts.Contact) VerifyResult {
	if senderFP == "" {
		return VerifyResult{Status: VerifyUnknownSigner}
	}
	resolved := false
	verifies := func(encodedKey string) bool {
		pub, err := base64.StdEncoding.DecodeString(encodedKey)
		if err != nil {
			return false
		}
		resolved = true
		ok, verr := crypto.Verify(message, signature, pub)
		return verr == nil && ok
	}

	// (a) current contact keys by fingerprint.
	for _, c := range contactList {
		if strings.EqualFold(c.Fingerprint, senderFP) && verifies(c.SignPubKey) {
			return VerifyResult{Status: VerifyOK, SignerFP: senderFP, SignerAlias: c.Alias}
		}
	}

	// (b) previous/revoked contact keys — a signature made before the contact
	// rotated stays valid, but is flagged.
	for _, c := range contactList {
		for _, prev := range c.PreviousKeys {
			if strings.EqualFold(prev.Fingerprint, senderFP) && verifies(prev.SignPubKey) {
				return VerifyResult{
					Status:         VerifyOK,
					SignerFP:       senderFP,
					SignerAlias:    c.Alias,
					UsedRevokedKey: true,
					RevokedAt:      prev.RevokedAt,
				}
			}
		}
	}

	// (c) self — the file was signed by the identity we're decrypting with.
	if strings.EqualFold(u.Fingerprint(), senderFP) && verifies(u.Info().SignPubKey) {
		return VerifyResult{Status: VerifyOK, SignerFP: senderFP, SignerIdentity: u.Name()}
	}

	if resolved {
		return VerifyResult{Status: VerifyFailed, SignerFP: senderFP}
	}
	return VerifyResult{Status: VerifyUnknownSigner, SignerFP: senderFP}
}
