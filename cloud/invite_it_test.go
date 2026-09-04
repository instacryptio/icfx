//go:build integration

package cloud_test

import (
	"context"
	"testing"
	"time"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/contacts"
)

// TestInviteBackAfterOfflineExchange covers the field scenario: B obtains
// A's lock OUT OF BAND (QR scan / file import — modeled as SaveFromLock),
// then invites A to connect through the cloud so A can accept and get B's
// lock. Also pins the unreachable case: an unpublished fingerprint bounces
// with IsNotFound.
func TestInviteBackAfterOfflineExchange(t *testing.T) {
	ctx := context.Background()

	// A is a cloud user with a PUBLISHED identity; B is a cloud user whose
	// identity is NOT published (invites still work — only the recipient
	// needs publishing).
	a, _ := cloud.New(baseURL())
	mustSignUp(t, a, randEmail(), validPW)
	annaName := "anna-" + randFingerprint()[:8]
	anna := newITIdentity(t, annaName)
	publishIT(t, a, anna)

	b, _ := cloud.New(baseURL())
	mustSignUp(t, b, randEmail(), validPW)
	ben := newITIdentity(t, "ben-offline")

	// B "scans A's QR": saves the lock locally, no directory involved.
	storeB := contacts.NewStoreWithPath(t.TempDir() + "/contacts-b.json")
	alias, _, err := contacts.SaveFromLock(storeB, anna.lb)
	if err != nil {
		t.Fatalf("save scanned lock: %v", err)
	}
	listB, _ := storeB.Load()
	if listB[0].CloudConnection != "" {
		t.Fatalf("fresh scan must start unconnected: %+v", listB[0])
	}

	// B invites A straight at the scanned lock.
	if err := cloud.InviteContact(ctx, b, ben.lb, anna.lb); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := storeB.SetCloudConnection(alias, contacts.ConnectionInvited, time.Now()); err != nil {
		t.Fatal(err)
	}

	// A reviews + accepts (same machinery as directory friend requests).
	items, err := a.ListPending(ctx)
	if err != nil || len(items) != 1 || items[0].Kind != cloud.KindContactRequest {
		t.Fatalf("A inbox: %+v err=%v", items, err)
	}
	item, err := a.FetchPending(ctx, items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	upd, err := cloud.ApplyPending(anna.crypter(), item)
	if err != nil || upd.Lock == nil || upd.Lock.Fingerprint != ben.lb.Fingerprint {
		t.Fatalf("apply: %+v err=%v", upd, err)
	}
	storeA := contacts.NewStoreWithPath(t.TempDir() + "/contacts-a.json")
	aliasB, _, err := contacts.SaveFromLock(storeA, *upd.Lock)
	if err != nil {
		t.Fatal(err)
	}
	// Accept side is connected the moment it saves + accepts.
	if err := storeA.SetCloudConnection(aliasB, contacts.ConnectionConnected, time.Now()); err != nil {
		t.Fatal(err)
	}
	if notified, err := cloud.AcceptContactRequest(ctx, a, upd, anna.lb, item.ID); err != nil || !notified {
		t.Fatalf("accept: notified=%v err=%v", notified, err)
	}

	// B drains: the accept flips B's contact to connected (hooked inside
	// DrainPending).
	rep, err := cloud.DrainPending(ctx, b, storeB, ben.unlockFor())
	if err != nil {
		t.Fatalf("B drain: %v", err)
	}
	if len(rep.Accepted) != 1 {
		t.Fatalf("B drain: %+v", rep)
	}
	listB, _ = storeB.Load()
	if listB[0].CloudConnection != contacts.ConnectionConnected {
		t.Fatalf("B contact must be connected after accept: %+v", listB[0])
	}

	// Unreachable: inviting B's UNPUBLISHED identity bounces with 404.
	err = cloud.InviteContact(ctx, a, anna.lb, ben.lb)
	if !cloud.IsNotFound(err) {
		t.Fatalf("invite to unpublished fingerprint: want IsNotFound, got %v", err)
	}
}
