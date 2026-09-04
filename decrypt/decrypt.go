// Package decrypt is icfx's container-aware decrypt + signature-verification
// path: it parses an .icfx container, decrypts it with the caller's unlocked
// identity, and — when the container is signed — verifies the signature against
// the caller's contacts (current keys, then rotated-out/previous keys) and
// finally the unlocked identity itself. It is the single implementation shared
// by every client (local decrypt, file-share receive, and signature checks), so
// verification policy can never drift between them.
//
// Signature verification is ADVISORY to decryption: an unverifiable signature
// never blocks decryption (the plaintext is still returned). Callers inspect the
// returned VerifyResult and decide how strict to be — a verify command exits
// non-zero, while decrypt/receive surface a warning.
package decrypt

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
)

// VerifyStatus is the outcome of the signature check on a decrypted container.
type VerifyStatus int

const (
	// VerifyUnsigned: the container carried no signature.
	VerifyUnsigned VerifyStatus = iota
	// VerifyOK: the signature matched a known signer (see VerifyResult for who).
	VerifyOK
	// VerifyUnverifiable: the container is signed, but no available key matched
	// (unknown sender, or the signature did not verify).
	VerifyUnverifiable
	// VerifyNoMetadata: the container is signed but carries no recoverable
	// sender metadata to verify against — a header-stripped pre-v2 (v1) file.
	VerifyNoMetadata
)

// VerifyResult is the structured verification outcome. Clients render it however
// they like (styled terminal lines, a bridge JSON string, an exit code) — the
// library composes no display text.
type VerifyResult struct {
	Status VerifyStatus
	// SignerFP is the sender fingerprint taken from the AUTHENTICATED metadata
	// (v2 inner metadata, or the v1 header). Set whenever the container names a
	// signer, so callers can show it even on VerifyUnverifiable.
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

// DecryptAndVerify parses an .icfx container, decrypts its payload with u, and
// verifies any signature. See the package doc for the advisory-verification
// contract. contactList may be nil/empty (verification then falls back to the
// unlocked identity only).
//
// Verification always runs POST-decrypt against the AUTHENTICATED metadata: for
// v2 that is the inner metadata sealed inside the payload (the plaintext header
// is disposable and must never be trusted for signer selection); for v1 the
// header is the only copy. The signer key is resolved in order: the sender's
// current contact key, then that contact's previous/revoked keys, then the
// unlocked identity itself (encrypt-to-self).
func DecryptAndVerify(data []byte, u *identity.Unlocked, contactList []contacts.Contact) (Result, error) {
	container, err := format.Deserialize(data)
	if err != nil {
		return Result{}, fmt.Errorf("parsing ICFX container: %w", err)
	}

	plaintext, err := u.Decrypt(container.Payload)
	if err != nil {
		return Result{}, fmt.Errorf("decrypting payload: %w", err)
	}

	// Recover the authenticated metadata + the original file bytes. A private
	// profile seals a metadata copy inside the payload; a public profile's
	// payload is the bare file bytes, carrying metadata (if any) only in the
	// plaintext header.
	meta := container.Metadata
	filedata := plaintext
	if !container.Profile.Public() {
		meta, filedata, err = format.DecodePayload(plaintext)
		if err != nil {
			return Result{}, fmt.Errorf("parsing inner metadata: %w", err)
		}
	}

	// A header-stripped public container has no metadata anywhere: if it was
	// signed the signature can't be checked; return the bytes with NoMetadata.
	if container.Private && container.Profile.Public() {
		status := VerifyUnsigned
		if len(container.Signature) > 0 {
			status = VerifyNoMetadata
		}
		return Result{Plaintext: filedata, Verify: VerifyResult{Status: status}}, nil
	}

	if !meta.IsSigned {
		return Result{Plaintext: filedata, Verify: VerifyResult{Status: VerifyUnsigned}}, nil
	}
	// The AUTHENTICATED inner metadata says this container is signed, but the
	// container carries no signature bytes — an active attacker stripped the
	// outer signature. Report it as unverifiable (with the named signer), not as
	// a clean "unsigned" file.
	if len(container.Signature) == 0 {
		return Result{Plaintext: filedata, Verify: VerifyResult{Status: VerifyUnverifiable, SignerFP: meta.SenderFingerprint}}, nil
	}

	res := verifySignature(container.Payload, container.Signature, meta.SenderFingerprint, u, contactList)
	return Result{Plaintext: filedata, Verify: res}, nil
}

// verifySignature resolves the signer's public key and checks the signature
// (always taken over the encrypted payload). Search order: contact current key,
// contact previous/revoked keys, then the unlocked identity itself.
func verifySignature(payload, signature []byte, senderFP string, u *identity.Unlocked, contactList []contacts.Contact) VerifyResult {
	// (a) current contact key by fingerprint.
	for _, c := range contactList {
		if c.Fingerprint != senderFP {
			continue
		}
		if pub, err := base64.StdEncoding.DecodeString(c.SignPubKey); err == nil {
			if ok, verr := crypto.Verify(payload, signature, pub); verr == nil && ok {
				return VerifyResult{Status: VerifyOK, SignerFP: senderFP, SignerAlias: c.Alias}
			}
		}
		break // fingerprint is unique; current key didn't verify — fall through to previous keys
	}

	// (b) previous/revoked contact keys — a signature made before the contact
	// rotated stays valid, but is flagged.
	for _, c := range contactList {
		for _, prev := range c.PreviousKeys {
			if prev.Fingerprint != senderFP {
				continue
			}
			if pub, err := base64.StdEncoding.DecodeString(prev.SignPubKey); err == nil {
				if ok, verr := crypto.Verify(payload, signature, pub); verr == nil && ok {
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
	}

	// (c) self — the file was signed by the identity we're decrypting with.
	if u.Fingerprint() == senderFP {
		if pub, err := base64.StdEncoding.DecodeString(u.Info().SignPubKey); err == nil {
			if ok, verr := crypto.Verify(payload, signature, pub); verr == nil && ok {
				return VerifyResult{Status: VerifyOK, SignerFP: senderFP, SignerIdentity: u.Name()}
			}
		}
	}

	return VerifyResult{Status: VerifyUnverifiable, SignerFP: senderFP}
}
