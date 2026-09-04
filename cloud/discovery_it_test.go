//go:build integration

package cloud_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// rawSigner signs with a raw ML-DSA-65 private key (test helper for the
// external cloud_test package).
type rawSigner struct{ key []byte }

func (r rawSigner) Sign(data []byte) ([]byte, error) { return crypto.Sign(data, r.key) }

// itIdentity is one simulated user: a real keypair, its lock bundle, and a
// SelfCrypter over it (what an unlocked identity provides).
type itIdentity struct {
	kp *crypto.KeyPair
	lb qr.LockBundle
}

func newITIdentity(t *testing.T, name string) itIdentity {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	lb := qr.LockBundle{
		ID:          "ic-" + name,
		Name:        name,
		EncPubKey:   kp.EncryptionRecipient,
		SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
		Fingerprint: kp.Fingerprint,
	}
	sealed, err := qr.SealLock(rawSigner{kp.SigningPrivateKey}, lb)
	if err != nil {
		t.Fatalf("seal lock: %v", err)
	}
	return itIdentity{kp: kp, lb: sealed}
}

func (i itIdentity) crypter() testCrypter {
	return testCrypter{pub: i.kp.EncryptionRecipient, priv: i.kp.EncryptionIdentity}
}

func (i itIdentity) unlockFor() func(string) (cloud.SelfCrypter, error) {
	return func(string) (cloud.SelfCrypter, error) { return i.crypter(), nil }
}

func publishIT(t *testing.T, c *cloud.Client, id itIdentity) {
	t.Helper()
	if err := cloud.PublishIdentityLock(context.Background(), c, publishableLock(id)); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// publishableLock returns the identity's lock with an email set — the
// directory's publish contract requires one.
func publishableLock(id itIdentity) qr.LockBundle {
	lock := id.lb
	if lock.Email == "" {
		lock.Email = lock.Name + "@example.com"
	}
	return lock
}

// TestPublishLift_FingerprintTaken: the same fingerprint published by a
// DIFFERENT account maps to the ErrFingerprintTaken sentinel.
func TestPublishLift_FingerprintTaken(t *testing.T) {
	ctx := context.Background()

	a, _ := cloud.New(baseURL())
	mustSignUp(t, a, randEmail(), validPW)
	id := newITIdentity(t, "dup-"+randFingerprint()[:8])
	publishIT(t, a, id)

	// Republishing from the SAME account is an idempotent update.
	if err := cloud.PublishIdentityLock(ctx, a, publishableLock(id)); err != nil {
		t.Fatalf("same-account republish must succeed: %v", err)
	}

	b, _ := cloud.New(baseURL())
	mustSignUp(t, b, randEmail(), validPW)
	err := cloud.PublishIdentityLock(ctx, b, publishableLock(id))
	if !errors.Is(err, cloud.ErrFingerprintTaken) {
		t.Fatalf("cross-account republish: got %v, want ErrFingerprintTaken", err)
	}
}

// TestDiscoveryFriendRequestFlow: A publishes → B searches (only published
// identities visible) → B sends a friend request → A's drain counts it
// (never auto-applies) → A accepts → B's drain auto-applies the acceptance.
func TestDiscoveryFriendRequestFlow(t *testing.T) {
	ctx := context.Background()

	// Account A with identity "anna", account B with identity "ben".
	a, _ := cloud.New(baseURL())
	mustSignUp(t, a, randEmail(), validPW)
	// Unique display name so repeated suite runs against the same DB can't
	// produce extra search hits.
	annaName := "anna-" + randFingerprint()[:8]
	anna := newITIdentity(t, annaName)
	publishIT(t, a, anna)

	b, _ := cloud.New(baseURL())
	mustSignUp(t, b, randEmail(), validPW)
	ben := newITIdentity(t, "ben")

	// /directory/mine shows A its own row; B's mine is empty.
	mine, err := a.ListMyDirectory(ctx)
	if err != nil || len(mine) != 1 || mine[0].Fingerprint != anna.lb.Fingerprint {
		t.Fatalf("A mine: %+v err=%v", mine, err)
	}
	if mineB, _ := b.ListMyDirectory(ctx); len(mineB) != 0 {
		t.Fatalf("B mine must be empty, got %+v", mineB)
	}

	// B searches, validates, and sends a friend request as "ben".
	hits, err := b.SearchDirectory(ctx, annaName, 0)
	if err != nil || len(hits) != 1 {
		t.Fatalf("search: %+v err=%v", hits, err)
	}
	target, err := cloud.ParseDirectoryLock(hits[0])
	if err != nil {
		t.Fatalf("parse hit: %v", err)
	}
	if err := cloud.SendFriendRequest(ctx, b, ben.lb, hits[0], target); err != nil {
		t.Fatalf("friend request: %v", err)
	}

	// A's drain: the request is COUNTED, never applied, and stays queued.
	storeA := contacts.NewStoreWithPath(t.TempDir() + "/contacts-a.json")
	rep, err := cloud.DrainPending(ctx, a, storeA, anna.unlockFor())
	if err != nil {
		t.Fatalf("A drain: %v", err)
	}
	if rep.RequestsWaiting != 1 || len(rep.Accepted) != 0 {
		t.Fatalf("A drain: want 1 waiting request, got %+v", rep)
	}
	listA, _ := storeA.Load()
	if len(listA) != 0 {
		t.Fatal("a friend request must NEVER auto-add a contact")
	}

	// A reviews + accepts: save ben, send accept-back, ack.
	items, err := a.ListPending(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("A inbox: %+v err=%v", items, err)
	}
	item, err := a.FetchPending(ctx, items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	upd, err := cloud.ApplyPending(anna.crypter(), item)
	if err != nil || upd.Kind != cloud.KindContactRequest {
		t.Fatalf("apply: %+v err=%v", upd, err)
	}
	if _, _, err := contacts.SaveFromLock(storeA, *upd.Lock); err != nil {
		t.Fatal(err)
	}
	notified, err := cloud.AcceptContactRequest(ctx, a, upd, anna.lb, item.ID)
	if err != nil || !notified {
		t.Fatalf("accept: notified=%v err=%v", notified, err)
	}

	// B's drain auto-applies the acceptance: anna appears as a contact.
	storeB := contacts.NewStoreWithPath(t.TempDir() + "/contacts-b.json")
	repB, err := cloud.DrainPending(ctx, b, storeB, ben.unlockFor())
	if err != nil {
		t.Fatalf("B drain: %v", err)
	}
	if len(repB.Accepted) != 1 || repB.Accepted[0] != annaName {
		t.Fatalf("B drain: want anna accepted, got %+v", repB)
	}
	listB, _ := storeB.Load()
	if len(listB) != 1 || listB[0].Fingerprint != anna.lb.Fingerprint {
		t.Fatalf("B contacts: %+v", listB)
	}

	// Both inboxes are now empty (acks landed).
	if left, _ := a.ListPending(ctx); len(left) != 0 {
		t.Fatalf("A inbox not drained: %+v", left)
	}
	if left, _ := b.ListPending(ctx); len(left) != 0 {
		t.Fatalf("B inbox not drained: %+v", left)
	}
}

// TestDrainAppliesRotationAndRevocation: rotation/revocation pending items
// auto-apply to the matching contact and ALWAYS record the old key in
// PreviousKeys (the user's "record revoked keys" requirement). Unknown
// senders are acked and ignored.
func TestDrainAppliesRotationAndRevocation(t *testing.T) {
	ctx := context.Background()

	a, _ := cloud.New(baseURL())
	mustSignUp(t, a, randEmail(), validPW)
	anna := newITIdentity(t, "anna")

	// A knows "carol" (newITIdentity already yields ID "ic-carol" and a
	// sealed, self-signed lock).
	carolOld := newITIdentity(t, "carol")
	storeA := contacts.NewStoreWithPath(t.TempDir() + "/contacts.json")
	if _, _, err := contacts.SaveFromLock(storeA, carolOld.lb); err != nil {
		t.Fatal(err)
	}

	// Carol rotates: new lock self-signed by the new key; the rotation itself
	// signed by the OLD key (continuity). Same IC-ID ties them to the contact.
	carolNew := newITIdentity(t, "carol")
	rotBundle := bundle.RotationBundle{
		NewLock:    carolNew.lb,
		Revocation: bundle.NewRevocation("ic-carol", carolOld.lb.Fingerprint),
	}
	rotBundle, err := bundle.SealRotation(rawSigner{carolOld.kp.SigningPrivateKey}, rotBundle)
	if err != nil {
		t.Fatalf("seal rotation: %v", err)
	}
	rotRaw, err := bundle.MarshalRotation(rotBundle)
	if err != nil {
		t.Fatalf("marshal rotation: %v", err)
	}
	info, err := a.AccountInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// A forged rotation (signed by an attacker key, not carol's stored key)
	// must be rejected — the core of the fix. Sent and drained first so the
	// contact is provably unchanged before the legitimate rotation lands.
	forged := bundle.RotationBundle{
		NewLock:    newITIdentity(t, "carol").lb,
		Revocation: bundle.NewRevocation("ic-carol", carolOld.lb.Fingerprint),
	}
	forged, _ = bundle.SealRotation(rawSigner{newITIdentity(t, "mallory").kp.SigningPrivateKey}, forged)
	forgedRaw, _ := bundle.MarshalRotation(forged)
	if _, err := a.SendToRecipient(ctx, info.AccountID, anna.lb.EncPubKey, anna.lb.Fingerprint, cloud.KindRotation, forgedRaw); err != nil {
		t.Fatalf("send forged rotation: %v", err)
	}
	frep, err := cloud.DrainPending(ctx, a, storeA, anna.unlockFor())
	if err != nil || frep.Rejected != 1 || len(frep.Rotated) != 0 {
		t.Fatalf("forged rotation must be rejected: %+v err=%v", frep, err)
	}
	if fl, _ := storeA.Load(); fl[0].Fingerprint != carolOld.lb.Fingerprint {
		t.Fatal("forged rotation must not change the contact's key")
	}

	if _, err := a.SendToRecipient(ctx, info.AccountID, anna.lb.EncPubKey, anna.lb.Fingerprint, cloud.KindRotation, rotRaw); err != nil {
		t.Fatalf("send rotation: %v", err)
	}

	rep, err := cloud.DrainPending(ctx, a, storeA, anna.unlockFor())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(rep.Rotated) != 1 {
		t.Fatalf("want 1 rotation applied, got %+v", rep)
	}
	list, _ := storeA.Load()
	if len(list) != 1 {
		t.Fatalf("contacts: %+v", list)
	}
	ct := list[0]
	if ct.Fingerprint != carolNew.lb.Fingerprint {
		t.Fatalf("rotation must install the new key, got %s", ct.Fingerprint)
	}
	if len(ct.PreviousKeys) != 1 || ct.PreviousKeys[0].Fingerprint != carolOld.lb.Fingerprint || ct.PreviousKeys[0].RevokedAt.IsZero() {
		t.Fatalf("old key must be recorded in PreviousKeys: %+v", ct.PreviousKeys)
	}

	// Carol revokes outright: signed by the key being revoked (now carolNew,
	// the current stored key). Key cleared, ALSO recorded in history.
	rev := bundle.NewRevocation("ic-carol", carolNew.lb.Fingerprint)
	rev, err = bundle.SealRevocation(rawSigner{carolNew.kp.SigningPrivateKey}, rev)
	if err != nil {
		t.Fatal(err)
	}
	revRaw, err := bundle.MarshalRevocation(rev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SendToRecipient(ctx, info.AccountID, anna.lb.EncPubKey, anna.lb.Fingerprint, cloud.KindRevocation, revRaw); err != nil {
		t.Fatalf("send revocation: %v", err)
	}
	rep, err = cloud.DrainPending(ctx, a, storeA, anna.unlockFor())
	if err != nil || len(rep.Revoked) != 1 {
		t.Fatalf("revocation drain: %+v err=%v", rep, err)
	}
	list, _ = storeA.Load()
	ct = list[0]
	if ct.EncPubKey != "" || len(ct.PreviousKeys) != 2 {
		t.Fatalf("revocation must clear the key and keep history: enc=%q prev=%d", ct.EncPubKey, len(ct.PreviousKeys))
	}

	// Rotation for an UNKNOWN contact: acked + ignored, store untouched.
	strangerNew := newITIdentity(t, "stranger")
	strangerNew.lb.ID = "ic-stranger"
	strRaw, _ := bundle.MarshalRotation(bundle.RotationBundle{NewLock: strangerNew.lb, Revocation: bundle.NewRevocation("ic-stranger", "deadbeefdeadbeef")})
	if _, err := a.SendToRecipient(ctx, info.AccountID, anna.lb.EncPubKey, anna.lb.Fingerprint, cloud.KindRotation, strRaw); err != nil {
		t.Fatal(err)
	}
	rep, err = cloud.DrainPending(ctx, a, storeA, anna.unlockFor())
	if err != nil || rep.Ignored != 1 || len(rep.Rotated) != 0 {
		t.Fatalf("unknown-sender rotation: %+v err=%v", rep, err)
	}
	if left, _ := a.ListPending(ctx); len(left) != 0 {
		t.Fatalf("ignored items must still be acked: %+v", left)
	}
}

// TestBroadcastRotationTwoClient: B rotates and auto-broadcasts a signed
// rotation to its cloud contacts; A (a cloud contact) receives it, verifies
// continuity against B's stored key, and applies the new key. End-to-end proof
// of the signed cloud-send path.
func TestBroadcastRotationTwoClient(t *testing.T) {
	ctx := context.Background()

	a, _ := cloud.New(baseURL())
	mustSignUp(t, a, randEmail(), validPW)
	b, _ := cloud.New(baseURL())
	mustSignUp(t, b, randEmail(), validPW)

	// A publishes anna so B can address A by fingerprint when broadcasting.
	anna := newITIdentity(t, "anna-"+randFingerprint()[:8])
	publishIT(t, a, anna)

	bobOld := newITIdentity(t, "bob")

	// B holds anna as a cloud contact (broadcast target); A holds bob as a
	// cloud contact (whose rotation A will receive and verify).
	storeB := contacts.NewStoreWithPath(t.TempDir() + "/contactsB.json")
	if _, _, err := contacts.SaveFromLock(storeB, anna.lb); err != nil {
		t.Fatal(err)
	}
	storeA := contacts.NewStoreWithPath(t.TempDir() + "/contactsA.json")
	if _, _, err := contacts.SaveFromLock(storeA, bobOld.lb); err != nil {
		t.Fatal(err)
	}

	// B rotates bob (new lock self-signed by new key; rotation signed by old
	// key) and broadcasts to its cloud contacts.
	bobNew := newITIdentity(t, "bob")
	rot := bundle.RotationBundle{
		NewLock:    bobNew.lb,
		Revocation: bundle.NewRevocation("ic-bob", bobOld.lb.Fingerprint),
	}
	rot, err := bundle.SealRotation(rawSigner{bobOld.kp.SigningPrivateKey}, rot)
	if err != nil {
		t.Fatalf("seal rotation: %v", err)
	}
	brep, err := cloud.BroadcastRotation(ctx, b, storeB, rot)
	if err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	if len(brep.Sent) != 1 || len(brep.Failed) != 0 {
		t.Fatalf("want 1 sent, 0 failed, got %+v", brep)
	}

	rep, err := cloud.DrainPending(ctx, a, storeA, anna.unlockFor())
	if err != nil || len(rep.Rotated) != 1 {
		t.Fatalf("drain: %+v err=%v", rep, err)
	}
	list, _ := storeA.Load()
	if list[0].Fingerprint != bobNew.lb.Fingerprint {
		t.Fatal("bob's key must be rotated on A's side after broadcast")
	}
}
