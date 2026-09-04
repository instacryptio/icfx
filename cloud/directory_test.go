package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/instacryptio/icfx/qr"
)

func TestPublishIdentityLock_EmailRequired(t *testing.T) {
	lock := qr.LockBundle{
		Name:        "noemail",
		EncPubKey:   "age1pq1xxxx",
		SignPubKey:  "c2lnbg==",
		Fingerprint: "abcd1234abcd1234",
	}

	// A nil client proves validation happens before any network use.
	err := PublishIdentityLock(context.Background(), nil, lock)
	if !errors.Is(err, ErrEmailRequired) {
		t.Fatalf("got %v, want ErrEmailRequired", err)
	}
}
