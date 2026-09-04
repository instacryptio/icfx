package cloud_test

import (
	"testing"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// unitCrypter is a minimal SelfCrypter over a real hybrid-PQ keypair.
type unitCrypter struct{ pub, priv string }

func (c unitCrypter) EncryptToSelf(plaintext []byte) ([]byte, error) {
	return crypto.Encrypt(plaintext, []string{c.pub})
}

func (c unitCrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	return crypto.Decrypt(ciphertext, c.priv)
}

// TestContactRequestEnvelopeRoundTrip exercises MarshalContactRequest →
// encrypt → ApplyPending without a server: the recipient recovers both the
// requester's lock bundle and the reply account id.
func TestContactRequestEnvelopeRoundTrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	recipient := unitCrypter{pub: kp.EncryptionRecipient, priv: kp.EncryptionIdentity}

	requester := qr.LockBundle{
		Name:        "Bob Smith",
		Alias:       "bobs",
		Email:       "bob@example.com",
		EncPubKey:   "age1pq1exampleexampleexample",
		Fingerprint: "9c14e7b02a5f0000",
	}
	payload, err := cloud.MarshalContactRequest("acct-1234", requester)
	if err != nil {
		t.Fatalf("marshal contact request: %v", err)
	}

	ct, err := crypto.Encrypt(payload, []string{kp.EncryptionRecipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	upd, err := cloud.ApplyPending(recipient, cloud.PendingFetch{
		ID:         "item-1",
		Kind:       cloud.KindContactRequest,
		Ciphertext: ct,
	})
	if err != nil {
		t.Fatalf("apply pending: %v", err)
	}
	if upd.Kind != cloud.KindContactRequest || upd.Lock == nil {
		t.Fatalf("unexpected update: %+v", upd)
	}
	if upd.ReplyAccountID != "acct-1234" {
		t.Fatalf("reply account id: got %q", upd.ReplyAccountID)
	}
	if upd.Lock.Name != requester.Name || upd.Lock.Fingerprint != requester.Fingerprint || upd.Lock.Alias != requester.Alias {
		t.Fatalf("lock bundle mismatch: %+v", upd.Lock)
	}

	// contact_accept stays a raw lock bundle — no envelope, no reply id.
	raw, err := qr.MarshalLockBundle(requester)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := crypto.Encrypt(raw, []string{kp.EncryptionRecipient})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := cloud.ApplyPending(recipient, cloud.PendingFetch{
		ID:         "item-2",
		Kind:       cloud.KindContactAccept,
		Ciphertext: ct2,
	})
	if err != nil {
		t.Fatalf("apply accept: %v", err)
	}
	if acc.Lock == nil || acc.Lock.Name != requester.Name || acc.ReplyAccountID != "" {
		t.Fatalf("unexpected accept update: %+v", acc)
	}
}
