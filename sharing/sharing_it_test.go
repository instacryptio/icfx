//go:build integration

package sharing_test

// End-to-end share round-trip against a live ic-cloud server WITH object
// storage configured (MinIO locally). Set CLOUD_TEST_URL (default
// http://localhost:8080); the server needs IC_CLOUD_DEV=true and the
// IC_CLOUD_STORJ_* env pointing at the test bucket.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/sharing"
)

func baseURL() string {
	if v := os.Getenv("CLOUD_TEST_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

func randEmail() string { return "share-" + uuid.NewString() + "@example.com" }

func randFingerprint() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mustSignUp(t *testing.T, c *cloud.Client, email string) string {
	t.Helper()
	pending, err := c.SignUp(context.Background(), email, "correcthorsebatterystaple", true)
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if pending.DevCode == "" {
		t.Fatal("no dev_code — run the test server with IC_CLOUD_DEV=true")
	}
	res, err := c.ConfirmSignUp(context.Background(), email, pending.DevCode)
	if err != nil {
		t.Fatalf("confirm signup: %v", err)
	}
	return res.AccountID
}

// upgradeToBasic flips the account to the basic tier via the dev-mode fake
// billing webhook (the server runs the FakeProcessor when Stripe is not
// configured; production refuses to start that way).
func upgradeToBasic(t *testing.T, accountID string) {
	t.Helper()
	body := fmt.Sprintf(`{"account_id":%q,"external_ref":"it-%s","tier":"basic","status":"active"}`,
		accountID, accountID)
	resp, err := http.Post(baseURL()+"/v1/billing/webhook/stripe", "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("fake webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fake webhook status %d", resp.StatusCode)
	}
}

// buildContainer produces a v2 ICFX container encrypted to lock, mirroring
// what the icc/ic-app encrypt flows produce locally: metadata encrypted
// inside the payload, plus a plaintext header copy (as icc --public-meta
// would) so the test can prove SendEncrypted strips it before upload.
func buildContainer(t *testing.T, plain []byte, lock, senderFp, origName string) []byte {
	t.Helper()
	meta := format.Metadata{
		SenderFingerprint: senderFp,
		Timestamp:         time.Now().UTC(),
		OriginalFilename:  origName,
		IsSigned:          false,
	}
	inner, err := format.EncodePayload(meta, plain)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	payload, err := crypto.Encrypt(inner, []string{lock})
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	c := &format.Container{
		Profile:  format.ProfilePrivateBuffered,
		Metadata: meta,
		Payload:  payload,
	}
	data, err := c.Serialize()
	if err != nil {
		t.Fatalf("serialize container: %v", err)
	}
	return data
}

func TestShareContainerRoundTrip(t *testing.T) {
	ctx := context.Background()
	aliceC, _ := cloud.New(baseURL())
	bobC, _ := cloud.New(baseURL())
	aliceID := mustSignUp(t, aliceC, randEmail())
	mustSignUp(t, bobC, randEmail())
	upgradeToBasic(t, aliceID)

	kpBob, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	bobFp := randFingerprint()
	if err := bobC.PublishDirectory(ctx, cloud.DirectoryPublishInput{
		DisplayName: "Bob",
		Email:       randEmail(),
		Fingerprint: bobFp,
		LockArmored: "-----BEGIN LOCK-----\n" + kpBob.EncryptionRecipient + "\n-----END LOCK-----",
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Alice uploads an ICFX container (the icc/ic-app wire format), no
	// email (NoNotify), never-expiring.
	plain := make([]byte, 128*1024)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	container := buildContainer(t, plain, kpBob.EncryptionRecipient, randFingerprint(), "roundtrip.bin")
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "roundtrip.bin.icfx")
	if err := os.WriteFile(srcPath, container, 0600); err != nil {
		t.Fatal(err)
	}

	sent, err := sharing.SendEncrypted(ctx, aliceC, []sharing.Recipient{{
		Lock:        kpBob.EncryptionRecipient,
		Fingerprint: bobFp,
	}}, srcPath, sharing.SendOptions{TTL: 0, NoNotify: true})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	// The uploaded object is the STRIPPED container: same payload, empty
	// header (the plaintext metadata block is removed before upload).
	strippedLocal, err := format.StripHeader(container)
	if err != nil {
		t.Fatalf("strip reference: %v", err)
	}
	if sent.ShareID == "" || sent.CiphertextBytes != int64(len(strippedLocal)) {
		t.Fatalf("send result mismatch: %+v (stripped container %d bytes)", sent, len(strippedLocal))
	}

	// Bob's inbox lists it; download the ciphertext and verify it is the
	// container byte-for-byte, then decrypt like a client would.
	inbox, err := bobC.ShareInbox(ctx, 10)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	var found *cloud.ShareInboxItem
	for i := range inbox {
		if inbox[i].ShareID == sent.ShareID {
			found = &inbox[i]
		}
	}
	if found == nil {
		t.Fatalf("share %s not in inbox: %+v", sent.ShareID, inbox)
	}
	if !found.TTLExpiresAt.IsZero() {
		t.Fatalf("never-expire share reports TTL %v", found.TTLExpiresAt)
	}
	if found.FileName != "roundtrip.bin.icfx" {
		t.Fatalf("inbox file name: %s", found.FileName)
	}

	var buf bytes.Buffer
	dl, err := sharing.DownloadCiphertext(ctx, bobC, sent.ShareID, &buf)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if dl.FileName != "roundtrip.bin.icfx" || int64(buf.Len()) != sent.CiphertextBytes {
		t.Fatalf("download mismatch: %+v (%d bytes)", dl, buf.Len())
	}
	if !bytes.Equal(buf.Bytes(), strippedLocal) {
		t.Fatal("downloaded ciphertext differs from the stripped container")
	}
	// PRIVACY PIN: the stored object must not leak the metadata plaintext.
	if bytes.Contains(buf.Bytes(), []byte("roundtrip.bin")) {
		t.Fatal("stored object leaks the original filename")
	}

	if format.Detect(buf.Bytes()) != format.FormatICFX {
		t.Fatal("downloaded payload is not an ICFX container")
	}
	parsed, err := format.Deserialize(buf.Bytes())
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !parsed.Private || parsed.Metadata.OriginalFilename != "" {
		t.Fatalf("stored container should be private: %+v", parsed.Metadata)
	}
	inner, err := crypto.Decrypt(parsed.Payload, kpBob.EncryptionIdentity)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	// The encrypted inner metadata copy survives the strip.
	meta, got, err := format.DecodePayload(inner)
	if err != nil {
		t.Fatalf("decode inner payload: %v", err)
	}
	if meta.OriginalFilename != "roundtrip.bin" {
		t.Fatalf("inner metadata: %+v", meta)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round-tripped plaintext differs from original")
	}
	if sharing.ReceiveName(dl.FileName, sent.ShareID) != "roundtrip.bin" {
		t.Fatalf("receive name: %s", sharing.ReceiveName(dl.FileName, sent.ShareID))
	}

	// Wrong key fails cleanly.
	kpEve, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(parsed.Payload, kpEve.EncryptionIdentity); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}

	// Sender cancels → gone from the inbox, further download refused.
	if err := aliceC.CancelShare(ctx, sent.ShareID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	inbox, err = bobC.ShareInbox(ctx, 10)
	if err != nil {
		t.Fatalf("inbox after cancel: %v", err)
	}
	for _, it := range inbox {
		if it.ShareID == sent.ShareID {
			t.Fatal("cancelled share still in inbox")
		}
	}
	if _, err := sharing.DownloadCiphertext(ctx, bobC, sent.ShareID, &bytes.Buffer{}); err == nil {
		t.Fatal("download after cancel should fail")
	}
}
