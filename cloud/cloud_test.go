//go:build integration

package cloud_test

// These tests talk to a live ic-cloud server. Set CLOUD_TEST_URL to point at
// it (default: http://localhost:8080). The server must have been migrated.
// Tests create unique accounts per run so they don't need DB cleanup, but
// they do create directory entries — re-running with the same
// fingerprint will hit a unique constraint, so each test generates random
// fingerprints.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// testCrypter is a minimal SelfCrypter backed by a real hybrid-PQ keypair, so
// the envelope helpers are exercised with genuine icfx encryption (not a stub).
type testCrypter struct{ pub, priv string }

func (t testCrypter) EncryptToSelf(plaintext []byte) ([]byte, error) {
	return crypto.Encrypt(plaintext, []string{t.pub})
}

func (t testCrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	return crypto.Decrypt(ciphertext, t.priv)
}

func newCrypter(t *testing.T) (testCrypter, *crypto.KeyPair) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return testCrypter{pub: kp.EncryptionRecipient, priv: kp.EncryptionIdentity}, kp
}

func baseURL() string {
	if v := os.Getenv("CLOUD_TEST_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

func randEmail() string { return "test-" + uuid.NewString() + "@example.com" }
func randFingerprint() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + hex.EncodeToString(b)
}

const validPW = "correcthorsebatterystaple"

func TestBlobEnvelopeAndPendingApply(t *testing.T) {
	ctx := context.Background()
	aliceC, _ := cloud.New(baseURL())
	bobC, _ := cloud.New(baseURL())

	aliceID := mustSignUp(t, aliceC, randEmail(), validPW)
	bobID := mustSignUp(t, bobC, randEmail(), validPW)

	alice, kpA := newCrypter(t)
	bob, kpB := newCrypter(t)

	// SealBlob / OpenBlob round-trip a contacts blob.
	contacts := []byte(`[{"name":"Bob","fp":"abc"}]`)
	r, err := aliceC.SealBlob(ctx, alice, "contacts", contacts, 0)
	if err != nil {
		t.Fatalf("seal contacts: %v", err)
	}
	if r.Version != 1 {
		t.Fatalf("want version 1, got %d", r.Version)
	}
	got, ver, err := aliceC.OpenBlob(ctx, alice, "contacts")
	if err != nil {
		t.Fatalf("open contacts: %v", err)
	}
	if !bytes.Equal(got, contacts) || ver != 1 {
		t.Fatalf("round-trip mismatch: %q v%d", got, ver)
	}

	// Settings uses the same generic helpers.
	if _, err := aliceC.SealBlob(ctx, alice, "settings", []byte(`{"theme":"dark"}`), 0); err != nil {
		t.Fatalf("seal settings: %v", err)
	}

	// A stale prevVersion surfaces as a conflict.
	if _, err := aliceC.SealBlob(ctx, alice, "contacts", contacts, 0); !cloud.IsConflict(err) {
		t.Fatalf("want conflict, got %v", err)
	}

	// The server holds only ciphertext — the plaintext must never appear.
	blob, err := aliceC.GetBlob(ctx, "contacts")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob.Ciphertext, []byte("Bob")) {
		t.Fatal("plaintext leaked into the stored blob")
	}

	// Pending: Alice sends a contact_request (her lock + reply account id,
	// as the envelope) encrypted to Bob.
	reqPayload, err := cloud.MarshalContactRequest(aliceID, qr.LockBundle{
		Name:        "Alice",
		EncPubKey:   kpA.EncryptionRecipient,
		Fingerprint: kpA.Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aliceC.SendToRecipient(ctx, bobID, kpB.EncryptionRecipient, "", cloud.KindContactRequest, reqPayload); err != nil {
		t.Fatalf("send to recipient: %v", err)
	}

	// Bob picks it up, decrypts + parses via ApplyPending.
	items, err := bobC.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 pending item, got %d", len(items))
	}
	item, err := bobC.FetchPending(ctx, items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	upd, err := cloud.ApplyPending(bob, item)
	if err != nil {
		t.Fatalf("apply pending: %v", err)
	}
	if upd.Kind != cloud.KindContactRequest || upd.Lock == nil {
		t.Fatalf("unexpected applied update: %+v", upd)
	}
	if upd.Lock.Name != "Alice" || upd.Lock.Fingerprint != kpA.Fingerprint {
		t.Fatalf("lock mismatch: %+v", upd.Lock)
	}
	if upd.ReplyAccountID != aliceID {
		t.Fatalf("reply account id: want %s, got %s", aliceID, upd.ReplyAccountID)
	}
}

func TestSignUpLoginRefreshLogout(t *testing.T) {
	c, _ := cloud.New(baseURL())
	ctx := context.Background()

	if _, err := c.SignUp(ctx, randEmail(), "short", true); err == nil {
		t.Fatal("weak password should fail")
	}

	email := randEmail()
	pending, err := c.SignUp(ctx, email, validPW, true)
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if pending.DevCode == "" {
		t.Fatal("no dev_code — run the test server with IC_CLOUD_DEV=true")
	}

	// No account exists until the code is confirmed.
	if _, err := c.LogIn(ctx, email, validPW); err == nil {
		t.Fatal("login before confirm should fail")
	}
	// Wrong code → invalid_code, still no account.
	if _, err := c.ConfirmSignUp(ctx, email, "000000"); err == nil {
		t.Fatal("wrong code should fail")
	}
	res, err := c.ConfirmSignUp(ctx, email, pending.DevCode)
	if err != nil {
		t.Fatalf("confirm signup: %v", err)
	}
	if res.AccountID == "" {
		t.Fatal("expected account id from confirm")
	}
	// Confirm returns a signed-in session directly.
	if !c.IsAuthenticated() {
		t.Fatal("expected to be authenticated after confirm")
	}

	// Signup for an existing account → conflict upfront.
	if _, err := c.SignUp(ctx, email, validPW, true); err == nil {
		t.Fatal("duplicate signup should fail")
	}

	// Wrong password
	c2, _ := cloud.New(baseURL())
	if _, err := c2.LogIn(ctx, email, "wrong-password-here"); err == nil {
		t.Fatal("wrong password should fail")
	}
	if c2.IsAuthenticated() {
		t.Fatal("should not be authenticated after failed login")
	}

	// Successful login (no TOTP)
	challenge, err := c.LogIn(ctx, email, validPW)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if challenge != nil {
		t.Fatal("did not expect TOTP challenge")
	}
	if !c.IsAuthenticated() {
		t.Fatal("expected to be authenticated")
	}

	// Refresh with a still-valid access token coalesces (single-flight
	// guard) — no server round trip, tokens unchanged.
	old := c.Tokens().AccessToken
	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("coalesced refresh: %v", err)
	}
	if c.Tokens().AccessToken != old {
		t.Fatal("refresh of a valid token should be a no-op")
	}

	// Simulate access-token expiry → Refresh rotates for real.
	expired := *c.Tokens()
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	c.SetTokens(&expired)
	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if c.Tokens().AccessToken == old {
		t.Fatal("expected new access token after refresh")
	}

	// Plan returns Free
	plan, err := c.GetPlan(ctx)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Tier != "free" {
		t.Fatalf("expected free tier, got %s", plan.Tier)
	}

	// LogOut invalidates token
	if err := c.LogOut(ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if c.IsAuthenticated() {
		t.Fatal("expected unauthenticated after logout")
	}
}

func TestTOTPFlow(t *testing.T) {
	c, _ := cloud.New(baseURL())
	ctx := context.Background()
	email := randEmail()
	mustSignUp(t, c, email, validPW)

	setup, err := c.SetupTOTP(ctx)
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	if setup.OTPAuthURL == "" {
		t.Fatal("expected otpauth url")
	}
	secret := extractSecret(t, setup.OTPAuthURL)

	code, _ := totp.GenerateCode(secret, time.Now())
	conf, err := c.ConfirmTOTP(ctx, code)
	if err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	if len(conf.RecoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(conf.RecoveryCodes))
	}

	// Fresh client; login should now demand TOTP
	c2, _ := cloud.New(baseURL())
	challenge, err := c2.LogIn(ctx, email, validPW)
	if !errors.Is(err, cloud.ErrTOTPRequired) {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}
	if challenge == nil || challenge.TempToken == "" {
		t.Fatal("expected challenge with temp token")
	}
	code2, _ := totp.GenerateCode(secret, time.Now())
	if err := c2.LogInTOTP(ctx, challenge.TempToken, code2); err != nil {
		t.Fatalf("login totp: %v", err)
	}
	if !c2.IsAuthenticated() {
		t.Fatal("expected c2 to be authenticated after TOTP")
	}
}

func TestBlobRoundtripAndConflict(t *testing.T) {
	c, _ := cloud.New(baseURL())
	ctx := context.Background()
	email := randEmail()
	mustSignUp(t, c, email, validPW)

	// First GET → 404
	if _, err := c.GetBlob(ctx, "settings"); !cloud.IsNotFound(err) {
		t.Fatalf("want NotFound, got %v", err)
	}

	// Initial PUT with prevVersion=0 → version=1
	r, err := c.PutBlob(ctx, "settings", []byte("encrypted-v1"), 0)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if r.Version != 1 {
		t.Fatalf("want v1, got %d", r.Version)
	}

	// Round-trip GET
	b, err := c.GetBlob(ctx, "settings")
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Ciphertext) != "encrypted-v1" || b.Version != 1 {
		t.Fatalf("round-trip mismatch")
	}

	// Stale prevVersion → conflict; CurrentVersionFromConflict returns 1
	_, err = c.PutBlob(ctx, "settings", []byte("encrypted-v2"), 0)
	if !cloud.IsConflict(err) {
		t.Fatalf("want conflict, got %v", err)
	}
	cur, ok := cloud.CurrentVersionFromConflict(err)
	if !ok || cur != 1 {
		t.Fatalf("expected current=1, got cur=%d ok=%v", cur, ok)
	}

	// Correct prevVersion → version=2
	r, err = c.PutBlob(ctx, "settings", []byte("encrypted-v2"), 1)
	if err != nil || r.Version != 2 {
		t.Fatalf("want v2, got %d err=%v", r.Version, err)
	}

	// Delete
	if err := c.DeleteBlob(ctx, "settings"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetBlob(ctx, "settings"); !cloud.IsNotFound(err) {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}

func TestDirectoryAndPending(t *testing.T) {
	ctx := context.Background()
	aliceC, _ := cloud.New(baseURL())
	bobC, _ := cloud.New(baseURL())

	aliceEmail, bobEmail := randEmail(), randEmail()
	aliceFp, bobFp := randFingerprint(), randFingerprint()

	// Sign up + log in
	aliceID := mustSignUp(t, aliceC, aliceEmail, validPW)
	bobID := mustSignUp(t, bobC, bobEmail, validPW)

	// Both publish to directory
	if err := aliceC.PublishDirectory(ctx, cloud.DirectoryPublishInput{
		DisplayName: "Alice", Email: aliceEmail, Fingerprint: aliceFp,
		LockArmored: "-----BEGIN LOCK-----\nalice\n-----END LOCK-----",
	}); err != nil {
		t.Fatalf("alice publish: %v", err)
	}
	if err := bobC.PublishDirectory(ctx, cloud.DirectoryPublishInput{
		DisplayName: "Bob", Email: bobEmail, Fingerprint: bobFp,
		LockArmored: "-----BEGIN LOCK-----\nbob\n-----END LOCK-----",
	}); err != nil {
		t.Fatalf("bob publish: %v", err)
	}

	// Alice searches for Bob by fingerprint prefix
	res, err := aliceC.SearchDirectory(ctx, bobFp[:8], 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 || res[0].Fingerprint != bobFp {
		t.Fatalf("search miss: %+v", res)
	}

	// Alice posts an encrypted contact_request to Bob by account id
	if _, err := aliceC.PostPending(ctx, bobID, "contact_request", []byte("encrypted-contact-req"), ""); err != nil {
		t.Fatalf("post pending: %v", err)
	}

	// ...and a second one addressed by Bob's published fingerprint — the
	// server resolves it to Bob's account without exposing the account id,
	// and records the fingerprint as a routing hint.
	if _, err := aliceC.PostPendingToFingerprint(ctx, bobFp, "contact_request", []byte("encrypted-by-fp")); err != nil {
		t.Fatalf("post pending by fingerprint: %v", err)
	}

	// An unpublished fingerprint is unaddressable.
	if _, err := aliceC.PostPendingToFingerprint(ctx, randFingerprint(), "contact_request", []byte("x")); !cloud.IsNotFound(err) {
		t.Fatalf("expected not found for unpublished fingerprint, got %v", err)
	}

	// Bob lists his inbox — should see both, hint only on the fp-addressed one
	items, err := bobC.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Kind != "contact_request" {
		t.Fatalf("bob inbox: %+v", items)
	}
	if items[0].ToFingerprint != "" || items[1].ToFingerprint != bobFp {
		t.Fatalf("to_fingerprint hints: %+v", items)
	}
	if err := bobC.AckPending(ctx, items[1].ID); err != nil {
		t.Fatal(err)
	}

	// Bob fetches and acks
	item, err := bobC.FetchPending(ctx, items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(item.Ciphertext) != "encrypted-contact-req" {
		t.Fatalf("ciphertext mismatch")
	}
	if err := bobC.AckPending(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	items, _ = bobC.ListPending(ctx)
	if len(items) != 0 {
		t.Fatalf("expected empty inbox after ack, got %d", len(items))
	}

	// Alice unpublishes her directory entry
	if err := aliceC.UnpublishDirectory(ctx, aliceFp); err != nil {
		t.Fatal(err)
	}

	_ = aliceID // keep referenced
	_ = bobID
}

// --- helpers --------------------------------------------------------------

// mustSignUp completes the pending-signup flow via the dev_code echo — the
// test server MUST run with IC_CLOUD_DEV=true. ConfirmSignUp returns a
// signed-in session directly, so no LogIn is needed.
func mustSignUp(t *testing.T, c *cloud.Client, email, pw string) string {
	t.Helper()
	pending, err := c.SignUp(context.Background(), email, pw, true)
	if err != nil {
		t.Fatalf("signup %s: %v", email, err)
	}
	if pending.DevCode == "" {
		t.Fatal("no dev_code in signup response — run the test server with IC_CLOUD_DEV=true")
	}
	res, err := c.ConfirmSignUp(context.Background(), email, pending.DevCode)
	if err != nil {
		t.Fatalf("confirm signup %s: %v", email, err)
	}
	return res.AccountID
}

// extractSecret pulls the secret= query parameter out of an otpauth URL.
func extractSecret(t *testing.T, url string) string {
	t.Helper()
	const key = "secret="
	i := indexAfter(url, key)
	if i < 0 {
		t.Fatalf("no secret in %s", url)
	}
	end := i
	for end < len(url) && url[end] != '&' {
		end++
	}
	return url[i:end]
}

func indexAfter(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i + len(sub)
		}
	}
	return -1
}

// TestChangePasswordFlow exercises the SDK method the CLI change-password command
// calls: after a change, the new password logs in and the old one no longer does.
// openFn is nil (no identities blob for a fresh account → no re-key), and no TOTP
// is enrolled so the returned challenge must be nil.
func TestChangePasswordFlow(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	email := randEmail()
	mustSignUp(t, c, email, validPW)

	const newPW = "another-strong-passphrase"
	challenge, err := c.ChangePassword(ctx, validPW, newPW, nil)
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	if challenge != nil {
		t.Fatal("did not expect a TOTP challenge for a non-TOTP account")
	}
	if !c.IsAuthenticated() {
		t.Fatal("expected to remain authenticated after change (re-login)")
	}

	// A fresh client: old password fails, new password works.
	c2, _ := cloud.New(baseURL())
	if _, err := c2.LogIn(ctx, email, validPW); err == nil {
		t.Fatal("old password should no longer log in")
	}
	if _, err := c2.LogIn(ctx, email, newPW); err != nil {
		t.Fatalf("new password login failed: %v", err)
	}
}

// enrollTOTP is a test helper: signs up + logs in a fresh account, enrolls TOTP,
// and returns the authed client, email, base32 secret, and recovery codes.
func enrollTOTP(t *testing.T) (*cloud.Client, string, string, []string) {
	t.Helper()
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	email := randEmail()
	mustSignUp(t, c, email, validPW)
	setup, err := c.SetupTOTP(ctx)
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	secret := extractSecret(t, setup.OTPAuthURL)
	code, _ := totp.GenerateCode(secret, time.Now())
	conf, err := c.ConfirmTOTP(ctx, code)
	if err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	if len(conf.RecoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(conf.RecoveryCodes))
	}
	return c, email, secret, conf.RecoveryCodes
}

// TestRecoveryLogin verifies a recovery code completes a TOTP-gated login and is
// consumed (single-use).
func TestRecoveryLogin(t *testing.T) {
	ctx := context.Background()
	_, email, _, recovery := enrollTOTP(t)
	rc := recovery[0]

	// Fresh client → login demands a second factor → satisfy with a recovery code.
	c2, _ := cloud.New(baseURL())
	challenge, err := c2.LogIn(ctx, email, validPW)
	if !errors.Is(err, cloud.ErrTOTPRequired) {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}
	if err := c2.LogInRecovery(ctx, challenge.TempToken, rc); err != nil {
		t.Fatalf("recovery login: %v", err)
	}
	if !c2.IsAuthenticated() {
		t.Fatal("expected authentication after recovery login")
	}

	// The same code must not work again (consumed).
	c3, _ := cloud.New(baseURL())
	challenge2, err := c3.LogIn(ctx, email, validPW)
	if !errors.Is(err, cloud.ErrTOTPRequired) {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}
	if err := c3.LogInRecovery(ctx, challenge2.TempToken, rc); err == nil {
		t.Fatal("reused recovery code should fail")
	}
}

// TestDisableTOTP verifies disable needs password + a second factor, and clears
// TOTP so subsequent logins don't require it.
func TestDisableTOTP(t *testing.T) {
	ctx := context.Background()
	c, email, secret, recovery := enrollTOTP(t)

	// Wrong password fails even with a valid code.
	badCode, _ := totp.GenerateCode(secret, time.Now())
	if err := c.DisableTOTP(ctx, email, "wrong-password-here", badCode); err == nil {
		t.Fatal("disable with wrong password should fail")
	}
	// Wrong second factor fails.
	if err := c.DisableTOTP(ctx, email, validPW, "000000"); err == nil {
		t.Fatal("disable with wrong code should fail")
	}
	// Password + live TOTP code succeeds.
	code, _ := totp.GenerateCode(secret, time.Now())
	if err := c.DisableTOTP(ctx, email, validPW, code); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// Login no longer requires a second factor.
	c2, _ := cloud.New(baseURL())
	ch, err := c2.LogIn(ctx, email, validPW)
	if err != nil {
		t.Fatalf("login after disable: %v", err)
	}
	if ch != nil {
		t.Fatal("TOTP should be disabled after disable")
	}
	_ = recovery
}

// TestDisableTOTPWithRecovery verifies a recovery code is an accepted second
// factor for disable (the lost-authenticator path).
func TestDisableTOTPWithRecovery(t *testing.T) {
	ctx := context.Background()
	c, email, _, recovery := enrollTOTP(t)

	if err := c.DisableTOTP(ctx, email, validPW, recovery[0]); err != nil {
		t.Fatalf("disable with recovery code: %v", err)
	}
	c2, _ := cloud.New(baseURL())
	ch, err := c2.LogIn(ctx, email, validPW)
	if err != nil {
		t.Fatalf("login after disable: %v", err)
	}
	if ch != nil {
		t.Fatal("TOTP should be disabled")
	}
}

// TestAccountInfo verifies the account-info endpoint reports TOTP state.
func TestAccountInfo(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())
	email := randEmail()
	mustSignUp(t, c, email, validPW)

	info, err := c.AccountInfo(ctx)
	if err != nil {
		t.Fatalf("account info: %v", err)
	}
	if info.Tier != "free" {
		t.Fatalf("expected free tier, got %q", info.Tier)
	}
	if info.TOTPEnabled {
		t.Fatal("TOTP should be disabled on a fresh account")
	}
	if info.ActiveFactor != "none" {
		t.Fatalf("fresh unverified account should have no active factor, got %q", info.ActiveFactor)
	}

	setup, err := c.SetupTOTP(ctx)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	code, _ := totp.GenerateCode(extractSecret(t, setup.OTPAuthURL), time.Now())
	if _, err := c.ConfirmTOTP(ctx, code); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	info2, err := c.AccountInfo(ctx)
	if err != nil {
		t.Fatalf("account info 2: %v", err)
	}
	if !info2.TOTPEnabled {
		t.Fatal("TOTP should be enabled after confirm")
	}
	if info2.ActiveFactor != "totp" {
		t.Fatalf("expected active factor totp after enroll, got %q", info2.ActiveFactor)
	}
}

// upgradeAccount flips the account's tier via the dev-mode fake billing
// webhook (the server runs the FakeProcessor when Stripe isn't configured;
// production refuses to start that way). Contacts-sync tests need a paid
// tier since the free plan caps cloud-synced contacts at 2.
func upgradeAccount(t *testing.T, accountID, tier string) {
	t.Helper()
	body := fmt.Sprintf(`{"account_id":%q,"external_ref":"it-%s","tier":%q,"status":"active"}`,
		accountID, accountID, tier)
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
