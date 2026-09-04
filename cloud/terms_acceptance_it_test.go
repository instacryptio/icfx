//go:build integration

package cloud_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/instacryptio/icfx/cloud"
)

// TestSignupRequiresTermsAcceptance proves the server rejects a sign-up without
// consent and records terms_accepted_at + terms_version on the account when the
// user accepts. Throwaway; requires the harness (server on CLOUD_TEST_URL with
// the default IC_CLOUD_TERMS_VERSION, migration 0023).
func TestSignupRequiresTermsAcceptance(t *testing.T) {
	ctx := context.Background()
	c, _ := cloud.New(baseURL())

	// (a) Declining consent is rejected — no account/pending is created.
	declined := randEmail()
	if _, err := c.SignUp(ctx, declined, validPW, false); err == nil {
		t.Fatal("sign-up without accepting the terms must be rejected")
	}

	// (b) Accepting consent works and lands a fully verified account.
	accepted := randEmail()
	pending, err := c.SignUp(ctx, accepted, validPW, true)
	if err != nil {
		t.Fatalf("sign-up with consent: %v", err)
	}
	if pending.DevCode == "" {
		t.Fatal("no dev_code — run the server with IC_CLOUD_DEV=true")
	}
	if _, err := c.ConfirmSignUp(ctx, accepted, pending.DevCode); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// Best-effort DB assertions (need the throwaway harness's Postgres
	// container): the account row records the acceptance timestamp + the
	// server's version, and the declined address left no pending row behind.
	got, ok := psql(t, "SELECT terms_version, (terms_accepted_at IS NOT NULL) FROM accounts WHERE email='"+accepted+"'")
	if !ok {
		t.Skip("skipping DB-record assertions (harness Postgres not reachable via podman)")
	}
	if !strings.Contains(got, "2026-08-26") || !strings.Contains(got, "t") {
		t.Fatalf("account should record terms_version + terms_accepted_at, got: %q", got)
	}
	pend, _ := psql(t, "SELECT count(*) FROM signup_pending WHERE email='"+declined+"'")
	if strings.TrimSpace(pend) != "0" {
		t.Fatalf("declined sign-up must not create a signup_pending row, count=%q", pend)
	}
}

// psql runs a query against the throwaway harness Postgres; ok is false when
// podman/psql isn't available (so callers can skip DB-level assertions).
func psql(t *testing.T, sql string) (string, bool) {
	t.Helper()
	out, err := exec.Command("podman", "exec", "icfx-it-pg", "psql", "-U", "postgres",
		"-d", "iccloud_it", "-tAc", sql).CombinedOutput()
	if err != nil {
		return "", false
	}
	return string(out), true
}
