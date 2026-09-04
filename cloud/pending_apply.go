package cloud

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// Pending kinds — the routing labels the server stores verbatim. The payload
// under each kind is encrypted to the recipient's lock; only the recipient can
// read it.
const (
	KindContactRequest = "contact_request"
	KindContactAccept  = "contact_accept"
	KindRotation       = "rotation"
	KindRevocation     = "revocation"
)

// SendToRecipient encrypts payload to the recipient's encryption public key
// (age1pq1... recipient string) and queues it in their pending inbox. The
// server only ever routes opaque ciphertext. toFingerprint optionally hints
// which of the recipient's identity locks the payload is encrypted to. Use
// one of the Kind* constants.
func (c *Client) SendToRecipient(ctx context.Context, recipientID, recipientEncPubKey, toFingerprint, kind string, payload []byte) (PendingPostResult, error) {
	ct, err := crypto.Encrypt(payload, []string{recipientEncPubKey})
	if err != nil {
		return PendingPostResult{}, fmt.Errorf("encrypt to recipient: %w", err)
	}
	return c.PostPending(ctx, recipientID, kind, ct, toFingerprint)
}

// SendToFingerprint encrypts payload to the recipient's encryption public
// key and queues it for whichever account has published the identity with
// the given fingerprint. The fingerprint → account resolution happens
// server-side, so the sender never learns the recipient's account id.
func (c *Client) SendToFingerprint(ctx context.Context, fingerprint, recipientEncPubKey, kind string, payload []byte) (PendingPostResult, error) {
	ct, err := crypto.Encrypt(payload, []string{recipientEncPubKey})
	if err != nil {
		return PendingPostResult{}, fmt.Errorf("encrypt to recipient: %w", err)
	}
	return c.PostPendingToFingerprint(ctx, fingerprint, kind, ct)
}

// contactRequestEnvelope is the plaintext of a contact_request payload: the
// requester's lock bundle plus the account id the acceptance should be sent
// back to. It travels only inside the E2E-encrypted ciphertext — the server
// never sees the requester's account id in readable form.
type contactRequestEnvelope struct {
	ReplyAccountID string `json:"reply_account_id"`
	LockBundle     []byte `json:"lock_bundle"`
}

// MarshalContactRequest builds the plaintext payload for KindContactRequest:
// the requester's own lock bundle plus the account id the recipient should
// address the contact_accept reply to.
func MarshalContactRequest(replyAccountID string, lb qr.LockBundle) ([]byte, error) {
	raw, err := qr.MarshalLockBundle(lb)
	if err != nil {
		return nil, fmt.Errorf("marshal lock bundle: %w", err)
	}
	return json.Marshal(contactRequestEnvelope{ReplyAccountID: replyAccountID, LockBundle: raw})
}

// AppliedUpdate is the decrypted, parsed content of a pending item. Exactly one
// of Lock / Bundle is set, per Kind. The SDK only decrypts and parses — what to
// do with the result (add a contact, apply a rotation, mark a contact revoked)
// is the caller's decision.
type AppliedUpdate struct {
	Kind string
	Lock *qr.LockBundle // set for contact_request / contact_accept
	// ReplyAccountID is set for contact_request only: where to address the
	// contact_accept reply. It arrived inside the encrypted payload.
	ReplyAccountID string
	Bundle         *bundle.ParsedBundle // set for rotation / revocation
}

// ApplyPending decrypts a fetched pending item with the recipient's own key and
// parses it by kind. It is a free function because it does no network I/O and
// holds no client state — decrypt + parse only. The caller Acks (AckPending)
// once it has durably applied the update.
func ApplyPending(u SelfCrypter, item PendingFetch) (AppliedUpdate, error) {
	plain, err := u.Decrypt(item.Ciphertext)
	if err != nil {
		return AppliedUpdate{}, fmt.Errorf("decrypt pending %s: %w", item.ID, err)
	}
	out := AppliedUpdate{Kind: item.Kind}
	switch item.Kind {
	case KindContactRequest:
		var env contactRequestEnvelope
		if err := json.Unmarshal(plain, &env); err != nil {
			return AppliedUpdate{}, fmt.Errorf("parse contact request: %w", err)
		}
		lb, err := qr.ParseLockBundle(env.LockBundle)
		if err != nil {
			return AppliedUpdate{}, fmt.Errorf("parse lock bundle: %w", err)
		}
		out.Lock = &lb
		out.ReplyAccountID = env.ReplyAccountID
	case KindContactAccept:
		lb, err := qr.ParseLockBundle(plain)
		if err != nil {
			return AppliedUpdate{}, fmt.Errorf("parse lock bundle: %w", err)
		}
		out.Lock = &lb
	case KindRotation, KindRevocation:
		pb, err := bundle.Parse(plain)
		if err != nil {
			return AppliedUpdate{}, fmt.Errorf("parse bundle: %w", err)
		}
		out.Bundle = pb
	default:
		return AppliedUpdate{}, fmt.Errorf("unknown pending kind %q", item.Kind)
	}
	return out, nil
}
