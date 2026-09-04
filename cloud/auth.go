package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/instacryptio/icfx/profile"
)

// getSalt fetches the per-account KDF salt used to derive the auth verifier and
// encryption key. For unknown emails the server returns a stable decoy, so this
// can't be used to enumerate accounts.
func (c *Client) getSalt(ctx context.Context, email string) ([]byte, error) {
	var res struct {
		ClientSalt string `json:"client_salt"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/salt",
		map[string]string{"email": email}, &res, false); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(res.ClientSalt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	return salt, nil
}

// SignUp begins account creation under the pending-signup model. The password
// is processed on-device (Argon2id → HKDF); only the auth verifier + salt
// reach the server, never the password. NO account exists yet — the server
// emails a 6-digit code and the caller completes with ConfirmSignUp. The
// derived encryption key is retained in memory so ConfirmSignUp lands in a
// fully-keyed, signed-in session without a second derivation or email.
//
// acceptedTerms asserts that the user accepted the current Terms of Service and
// Privacy Policy at sign-up; the server rejects the request (and records
// nothing) when it is false.
func (c *Client) SignUp(ctx context.Context, email, password string, acceptedTerms bool) (SignUpPending, error) {
	salt, err := newSalt()
	if err != nil {
		return SignUpPending{}, err
	}
	verifier, encKey, err := deriveAuth(password, salt)
	if err != nil {
		return SignUpPending{}, err
	}
	var res SignUpPending
	if err := c.doJSON(ctx, "POST", "/v1/auth/signup",
		map[string]any{
			"email":          email,
			"auth_verifier":  verifier,
			"client_salt":    base64.StdEncoding.EncodeToString(salt),
			"accepted_terms": acceptedTerms,
		}, &res, false); err != nil {
		return SignUpPending{}, err
	}
	c.setAuthState(email, encKey)
	// Signup consumed the server's verification-purpose email throttle;
	// mirror it client-side so an immediate resend is gated locally too.
	c.recordEmailAction(EmailActionVerify, email)
	return res, nil
}

// ConfirmSignUp exchanges the pending signup + the emailed 6-digit code for
// the real account (born verified) and a signed-in session. The encryption
// key from the SignUp call is already held, so the client is fully keyed.
func (c *Client) ConfirmSignUp(ctx context.Context, email, code string) (SignUpResult, error) {
	var raw struct {
		AccountID string `json:"account_id"`
		Tokens
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/signup/confirm",
		map[string]string{"email": email, "code": code},
		&raw, false); err != nil {
		return SignUpResult{}, err
	}
	c.SetTokens(&raw.Tokens)
	c.persistEncKey() // account now exists; keep the key for future syncs
	return SignUpResult{AccountID: raw.AccountID}, nil
}

// LogIn derives the verifier + encryption key on-device (fetching the account's
// salt first), then authenticates with the verifier. If the account has TOTP it
// returns ErrTOTPRequired + a challenge; the derived encryption key is retained
// either way, so LogInTOTP completes into a fully-keyed session.
func (c *Client) LogIn(ctx context.Context, email, password string) (*LoginTOTPChallenge, error) {
	salt, err := c.getSalt(ctx, email)
	if err != nil {
		return nil, err
	}
	verifier, encKey, err := deriveAuth(password, salt)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Tokens
		SecondFactor string          `json:"second_factor"`
		TempToken    string          `json:"temp_token"`
		WebAuthn     json.RawMessage `json:"webauthn"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/login",
		map[string]string{"email": email, "auth_verifier": verifier},
		&raw, false); err != nil {
		return nil, err
	}
	c.setAuthState(email, encKey) // held even across the second-factor step
	// The verifier was accepted, so the derived key is correct — persist it
	// (best-effort) so later identities syncs don't re-prompt the password.
	c.persistEncKey()
	switch raw.SecondFactor {
	case "totp":
		return &LoginTOTPChallenge{TempToken: raw.TempToken, Factor: "totp"}, ErrTOTPRequired
	case "email":
		return &LoginTOTPChallenge{TempToken: raw.TempToken, Factor: "email"}, ErrEmailCodeRequired
	case "webauthn":
		return &LoginTOTPChallenge{TempToken: raw.TempToken, Factor: "webauthn", WebAuthnOptions: raw.WebAuthn}, ErrWebAuthnRequired
	}
	c.SetTokens(&raw.Tokens)
	return nil, nil
}

// LogInTOTP completes the login after the user enters their TOTP code. The
// encryption key derived during LogIn is already held on the client.
func (c *Client) LogInTOTP(ctx context.Context, tempToken, code string) error {
	var t Tokens
	if err := c.doJSON(ctx, "POST", "/v1/auth/login/totp",
		map[string]string{"temp_token": tempToken, "code": code},
		&t, false); err != nil {
		return err
	}
	c.SetTokens(&t)
	return nil
}

// LogInRecovery completes a TOTP-gated login using a one-time recovery code
// instead of a live TOTP code (the lost-authenticator path). The encryption key
// derived during LogIn is already held on the client. The code is consumed
// server-side.
func (c *Client) LogInRecovery(ctx context.Context, tempToken, code string) error {
	var t Tokens
	if err := c.doJSON(ctx, "POST", "/v1/auth/login/recovery",
		map[string]string{"temp_token": tempToken, "code": code},
		&t, false); err != nil {
		return err
	}
	c.SetTokens(&t)
	return nil
}

// LogInEmail completes an email-gated login using the one-time code the server
// emailed during LogIn. The encryption key derived during LogIn is already held.
func (c *Client) LogInEmail(ctx context.Context, tempToken, code string) error {
	var t Tokens
	if err := c.doJSON(ctx, "POST", "/v1/auth/login/email",
		map[string]string{"temp_token": tempToken, "code": code},
		&t, false); err != nil {
		return err
	}
	c.SetTokens(&t)
	return nil
}

// ChangePassword re-derives keys for the new password, re-keys the cloud
// identities blob (by re-exporting from the local keystore under the new key —
// a byte re-wrap won't do, since each identity bundle is itself keyed to the old
// password), updates the server verifier+salt, then re-logs in (the server
// invalidates sessions on change). Must be logged in.
//
// Like LogIn, it returns a non-nil *LoginTOTPChallenge with ErrTOTPRequired when
// the account has TOTP enabled — the password change has already committed at
// that point; the caller must complete the re-login with LogInTOTP.
//
// exportFn packs local identities' at-rest forms for the re-wrap; pass the
// client's own roaming export. It may be nil when identities roaming isn't in
// use — the re-wrap is then skipped (and only happens if a blob exists anyway).
func (c *Client) ChangePassword(ctx context.Context, oldPassword, newPassword string, exportFn profile.IdentityExportFn) (*LoginTOTPChallenge, error) {
	email := c.accountEmail()
	if email == "" {
		return nil, &Error{Code: "not_logged_in", Message: "log in before changing the password"}
	}
	oldSalt, err := c.getSalt(ctx, email)
	if err != nil {
		return nil, err
	}
	oldVerifier, _, err := deriveAuth(oldPassword, oldSalt)
	if err != nil {
		return nil, err
	}
	newSaltB, err := newSalt()
	if err != nil {
		return nil, err
	}
	newVerifier, newEnc, err := deriveAuth(newPassword, newSaltB)
	if err != nil {
		return nil, err
	}

	// Re-wrap the identities blob's outer layer under the new encryption key, but
	// only if the user actually has one uploaded (don't create one here). File/HW
	// entries inside are unchanged (not encKey-protected); this just re-exports.
	if exportFn != nil {
		has, err := c.hasIdentitiesBlob(ctx)
		if err != nil {
			return nil, err
		}
		if has {
			if _, err := c.pushIdentitiesWithKey(ctx, newEnc, exportFn); err != nil {
				return nil, err
			}
		}
	}

	if err := c.doJSON(ctx, "POST", "/v1/auth/password/change",
		map[string]string{
			"old_verifier":    oldVerifier,
			"new_verifier":    newVerifier,
			"new_client_salt": base64.StdEncoding.EncodeToString(newSaltB),
		}, nil, true); err != nil {
		return nil, err
	}
	return c.LogIn(ctx, email, newPassword) // sessions were invalidated; propagate any TOTP challenge
}

// ResendSignupCode asks the server to re-send the 6-digit signup code for a
// pending signup. Never reveals whether such a signup exists. If a
// CooldownStore is set and the address was requested within
// EmailActionCooldown, it returns a *CooldownError without a round trip; the
// server enforces its own throttle too.
func (c *Client) ResendSignupCode(ctx context.Context, email string) error {
	if err := c.gateEmailAction(EmailActionVerify, email); err != nil {
		return err
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/verify/request",
		map[string]string{"email": email}, nil, false); err != nil {
		return err
	}
	c.recordEmailAction(EmailActionVerify, email)
	return nil
}

// SetEmailTwoFactor enables or disables the email-code second factor for the
// authenticated account. Enabling needs no extra proof (the address is verified
// at signup). DISABLING requires password re-auth (email is needed to fetch the
// KDF salt; the raw password never leaves the client) so a stolen session token
// alone can't downgrade 2FA — consistent with DisableTOTP. Must be logged in.
func (c *Client) SetEmailTwoFactor(ctx context.Context, enable bool, email, password string) error {
	body := map[string]any{"enable": enable}
	if !enable {
		salt, err := c.getSalt(ctx, email)
		if err != nil {
			return err
		}
		verifier, _, err := deriveAuth(password, salt)
		if err != nil {
			return err
		}
		body["auth_verifier"] = verifier
	}
	return c.doJSON(ctx, "POST", "/v1/account/2fa/email", body, nil, true)
}

// ForgotPassword requests a password-reset email. Never reveals whether the
// address is registered. If a CooldownStore is set and the address was requested
// within EmailActionCooldown, it returns a *CooldownError without a round trip;
// the server enforces its own throttle too.
func (c *Client) ForgotPassword(ctx context.Context, email string) error {
	if err := c.gateEmailAction(EmailActionReset, email); err != nil {
		return err
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/password/forgot",
		map[string]string{"email": email}, nil, false); err != nil {
		return err
	}
	c.recordEmailAction(EmailActionReset, email)
	return nil
}

// ResetPassword sets a new password using the emailed token. A fresh salt +
// verifier are derived on-device. Note: reset restores account access, not the
// cloud identities blob (that was keyed to the old password).
func (c *Client) ResetPassword(ctx context.Context, token, newPassword string) error {
	salt, err := newSalt()
	if err != nil {
		return err
	}
	verifier, _, err := deriveAuth(newPassword, salt)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, "POST", "/v1/auth/password/reset",
		map[string]string{
			"token":           token,
			"new_verifier":    verifier,
			"new_client_salt": base64.StdEncoding.EncodeToString(salt),
		}, nil, false)
}

// refreshCoalesceWindow is the validity margin under which a Refresh call
// that lost the single-flight race treats the other caller's rotation as its
// own success.
const refreshCoalesceWindow = 30 * time.Second

// Refresh exchanges the stored refresh token for a new access/refresh pair.
// Single-flight: concurrent callers serialize, and a caller that acquires
// the lock after another just rotated returns nil without contacting the
// server — re-POSTing the consumed token would trip the server's reuse
// detection and revoke every session in the family.
func (c *Client) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if c.TokenValidFor(refreshCoalesceWindow) {
		return nil
	}
	tokens := c.Tokens()
	if tokens == nil || tokens.RefreshToken == "" {
		return &Error{Code: "no_refresh_token", Message: "client has no refresh token"}
	}
	var fresh Tokens
	if err := c.doJSON(ctx, "POST", "/v1/auth/refresh",
		map[string]string{"refresh_token": tokens.RefreshToken},
		&fresh, false); err != nil {
		return err
	}
	c.SetTokens(&fresh)
	return nil
}

// LogOut invalidates the current access token on the server and clears local
// credentials (tokens + the in-memory encryption key).
func (c *Client) LogOut(ctx context.Context) error {
	err := c.doJSON(ctx, "POST", "/v1/auth/logout", nil, nil, true)
	c.clearStoredEncKey()  // before the email is wiped below
	c.clearStoredSession() // ditto — keyed by email
	c.SetTokens(nil)
	c.setAuthState("", nil)
	return err
}

// SetupTOTP starts TOTP enrollment. Returns the otpauth URL for QR rendering.
func (c *Client) SetupTOTP(ctx context.Context) (TOTPSetup, error) {
	var res TOTPSetup
	err := c.doJSON(ctx, "POST", "/v1/account/2fa/setup", nil, &res, true)
	return res, err
}

// ConfirmTOTP finalizes TOTP enrollment and returns the one-time recovery codes.
func (c *Client) ConfirmTOTP(ctx context.Context, code string) (TOTPConfirm, error) {
	var res TOTPConfirm
	err := c.doJSON(ctx, "POST", "/v1/account/2fa/confirm",
		map[string]string{"code": code}, &res, true)
	return res, err
}

// DisableTOTP turns off TOTP for the account. It re-authenticates with the
// account password (processed on-device into a verifier — the raw password never
// leaves the client) AND a second factor: a live TOTP code or an unused recovery
// code. Must be logged in; email is needed to fetch the KDF salt.
func (c *Client) DisableTOTP(ctx context.Context, email, password, code string) error {
	salt, err := c.getSalt(ctx, email)
	if err != nil {
		return err
	}
	verifier, _, err := deriveAuth(password, salt)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, "POST", "/v1/account/2fa/disable",
		map[string]string{"auth_verifier": verifier, "code": code}, nil, true)
}

// AccountInfo returns account metadata: email, tier, whether TOTP is enabled,
// and whether the email is verified. Must be logged in.
func (c *Client) AccountInfo(ctx context.Context) (AccountInfo, error) {
	var res AccountInfo
	err := c.doJSON(ctx, "GET", "/v1/account", nil, &res, true)
	return res, err
}

// RequestAccountDeletion schedules the account for deletion after a server-side
// grace window (default 30 days) and signs every device out. It is NOT an
// immediate wipe: logging back in on any device before the deadline cancels
// it. Re-authenticates with the account password (processed on-device into a
// verifier — the raw password never leaves the client) so a stolen token
// alone can't schedule deletion. Must be logged in; email is needed to fetch
// the KDF salt. revokeKeys is forwarded; pushing revocation bundles is the
// caller's job and must happen BEFORE this call.
//
// On success the local tokens are cleared to match the server-side sign-out.
func (c *Client) RequestAccountDeletion(ctx context.Context, email, password string, revokeKeys bool) error {
	salt, err := c.getSalt(ctx, email)
	if err != nil {
		return err
	}
	verifier, _, err := deriveAuth(password, salt)
	if err != nil {
		return err
	}
	err = c.doJSON(ctx, "DELETE", "/v1/account",
		map[string]any{"auth_verifier": verifier, "revoke_keys": revokeKeys}, nil, true)
	if err == nil {
		c.clearStoredEncKey()
		c.clearStoredSession()
		c.SetTokens(nil)
		c.setAuthState("", nil)
	}
	return err
}
