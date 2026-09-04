package cloud

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/contacts"
)

// BroadcastReport summarizes a rotation/revocation broadcast. Aliases are local
// contact aliases. Clients render it; nothing here prints.
type BroadcastReport struct {
	Sent    []string // signed bundle queued to this cloud contact's inbox
	Skipped []string // non-cloud contact — must be told out-of-band (file export)
	Failed  []string // cloud contact whose send errored (transient)
}

// BroadcastRotation posts a signed rotation to every cloud-reachable contact's
// pending inbox, addressed by the contact's published fingerprint (contacts
// hold no account id). rot must already be sealed: NewLock self-signed by the
// new key and the rotation signed by the old key. Non-cloud contacts are
// skipped — the caller directs the user to share the exported bundle
// out-of-band. Sending only to saved contacts means this can't spam strangers.
func BroadcastRotation(ctx context.Context, c *Client, store *contacts.Store, rot bundle.RotationBundle) (BroadcastReport, error) {
	payload, err := json.Marshal(rot)
	if err != nil {
		return BroadcastReport{}, fmt.Errorf("marshaling rotation: %w", err)
	}
	return broadcast(ctx, c, store, KindRotation, payload)
}

// BroadcastRevocation posts a signed revocation to every cloud-reachable
// contact's pending inbox. rev must already be sealed by the revoked key.
func BroadcastRevocation(ctx context.Context, c *Client, store *contacts.Store, rev bundle.RevocationBundle) (BroadcastReport, error) {
	payload, err := json.Marshal(rev)
	if err != nil {
		return BroadcastReport{}, fmt.Errorf("marshaling revocation: %w", err)
	}
	return broadcast(ctx, c, store, KindRevocation, payload)
}

func broadcast(ctx context.Context, c *Client, store *contacts.Store, kind string, payload []byte) (BroadcastReport, error) {
	var rep BroadcastReport
	existing, err := store.Load()
	if err != nil {
		return rep, fmt.Errorf("loading contacts: %w", err)
	}
	for i := range existing {
		ct := existing[i]
		if !ct.Cloud || ct.Fingerprint == "" || ct.EncPubKey == "" {
			rep.Skipped = append(rep.Skipped, ct.Alias)
			continue
		}
		if _, serr := c.SendToFingerprint(ctx, ct.Fingerprint, ct.EncPubKey, kind, payload); serr != nil {
			rep.Failed = append(rep.Failed, ct.Alias)
			continue
		}
		rep.Sent = append(rep.Sent, ct.Alias)
	}
	return rep, nil
}
