//go:build integration

package cloud_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/instacryptio/icfx/cloud"
)

// TestNotificationsSyncConvergence proves cross-device convergence of the
// zero-knowledge notifications blob: two "devices" (two stores, one account,
// one self-lock key) converge, and a dismissal on one device propagates to the
// other. Requires the harness (server on CLOUD_TEST_URL, migration 0022).
func TestNotificationsSyncConvergence(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	mustSignUp(t, c, randEmail(), validPW)

	// Same account ⇒ same default-identity self-lock key on every device.
	u, _ := newCrypter(t)

	devA := cloud.NewNotificationStore(filepath.Join(t.TempDir(), "a.json"))
	devB := cloud.NewNotificationStore(filepath.Join(t.TempDir(), "b.json"))

	// Device A creates a self-share notice and syncs it up.
	if err := devA.SeedSelfShare("s1", "secret.txt", 12, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := devA.Sync(ctx, c, u); err != nil {
		t.Fatalf("A sync: %v", err)
	}

	// Device B pulls it.
	if err := devB.Sync(ctx, c, u); err != nil {
		t.Fatalf("B sync: %v", err)
	}
	if got := devB.List(); len(got) != 1 || got[0].ID != "share:s1" {
		t.Fatalf("B should have the share notice, got %+v", got)
	}

	// Device B dismisses it and syncs.
	if err := devB.Dismiss("share:s1"); err != nil {
		t.Fatal(err)
	}
	if err := devB.Sync(ctx, c, u); err != nil {
		t.Fatalf("B sync 2: %v", err)
	}

	// Device A pulls the dismissal — the row is gone there too.
	if err := devA.Sync(ctx, c, u); err != nil {
		t.Fatalf("A sync 2: %v", err)
	}
	if got := devA.List(); len(got) != 0 {
		t.Fatalf("A should see the dismissal, still has %+v", got)
	}
	if devA.UnseenCount() != 0 || devB.UnseenCount() != 0 {
		t.Fatalf("unseen counts should match at 0: A=%d B=%d", devA.UnseenCount(), devB.UnseenCount())
	}

	// The stored blob is opaque ciphertext (zero-knowledge): a raw GetBlob must
	// not contain the plaintext file name.
	raw, err := c.GetBlob(ctx, "notifications")
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if len(raw.Ciphertext) == 0 {
		t.Fatal("expected a stored ciphertext blob")
	}
	if containsBytes(raw.Ciphertext, []byte("secret.txt")) {
		t.Fatal("plaintext file name leaked into the stored blob — not zero-knowledge")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
