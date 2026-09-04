package cloud

import "time"

type Tokens struct {
	AccessToken      string    `json:"token"`
	RefreshToken     string    `json:"refresh_token"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type LoginTOTPChallenge struct {
	TempToken   string    `json:"temp_token"`
	TempExpires time.Time `json:"temp_expires"`
	// Factor is the second factor the server is asking for: "totp", "email", or
	// "webauthn". Set by LogIn; not part of the wire payload of this struct.
	Factor string `json:"-"`
	// WebAuthnOptions carries the assertion options when Factor == "webauthn".
	WebAuthnOptions []byte `json:"-"`
}

// WebAuthnKey describes one registered hardware key.
type WebAuthnKey struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

type SignUpResult struct {
	AccountID string `json:"account_id"`
}

// SignUpPending is the state after SignUp under the pending-signup model: a
// 6-digit code was emailed; no account exists until ConfirmSignUp. DevCode is
// populated ONLY by dev-mode servers (local dev / integration tests).
type SignUpPending struct {
	Status  string `json:"status"`
	DevCode string `json:"dev_code"`
}

type TOTPSetup struct {
	OTPAuthURL string `json:"otpauth_url"`
}

type TOTPConfirm struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

type AccountInfo struct {
	// AccountID is the caller's own account id. Needed to route
	// contact-accept replies; only ever returned to its owner.
	AccountID string `json:"account_id"`
	Email     string `json:"email"`
	Tier      string `json:"tier"`
	// Vip is admin-granted: limits are Ultimate regardless of Tier, which
	// stays the real billing tier (display as e.g. "free (VIP)").
	Vip           bool   `json:"vip"`
	TOTPEnabled   bool   `json:"totp_enabled"`
	EmailVerified bool   `json:"email_verified"`
	ActiveFactor  string `json:"active_factor"` // "none", "email", "totp"
}

// --- blob ---

type PutBlobResult struct {
	Version int64 `json:"version"`
}

type Blob struct {
	Ciphertext []byte    `json:"-"`
	Version    int64     `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// --- pending ---

type PendingItem struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// ToFingerprint hints which of the recipient's identity locks the
	// ciphertext is encrypted to (set when the sender addressed the item
	// by published fingerprint). Empty for account-addressed items.
	ToFingerprint string    `json:"to_fingerprint"`
	CreatedAt     time.Time `json:"created_at"`
}

type PendingFetch struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	Ciphertext    []byte    `json:"-"`
	ToFingerprint string    `json:"to_fingerprint"`
	CreatedAt     time.Time `json:"created_at"`
}

type PendingPostResult struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// --- directory ---

type DirectoryPublishInput struct {
	DisplayName string `json:"display_name"`
	Alias       string `json:"alias"`
	Email       string `json:"email"`
	Fingerprint string `json:"fingerprint"`
	LockArmored string `json:"lock_armored"`
}

// DirectoryEntry is one published identity. It deliberately carries no
// account id: search results must never reveal that two identities belong
// to the same account. Messages to an entry are addressed by fingerprint
// (SendToFingerprint) and resolved to the owning account server-side.
type DirectoryEntry struct {
	DisplayName string    `json:"display_name"`
	Alias       string    `json:"alias"`
	Email       string    `json:"email"`
	Fingerprint string    `json:"fingerprint"`
	LockArmored string    `json:"lock_armored"`
	IndexedAt   time.Time `json:"indexed_at"`
}

// --- share ---

type ShareCreateInput struct {
	// RecipientFingerprints are the contact recipients' published fingerprints —
	// one uploaded blob authorized for all of them.
	RecipientFingerprints []string `json:"recipient_fingerprints"`
	// ToSelf additionally shares to the account's own devices (may coexist with
	// RecipientFingerprints). The server never learns the identity, sends no
	// email, and needs no directory publication for the self target.
	ToSelf    bool          `json:"to_self"`
	TTL       time.Duration `json:"-"`
	SingleUse bool          `json:"single_use"`
	FileName  string        `json:"file_name"`
	FileSize  int64         `json:"file_size"`
}

type ShareCreateResult struct {
	ShareID         string    `json:"share_id"`
	UploadURL       string    `json:"upload_url"`
	UploadExpiresAt time.Time `json:"upload_expires_at"`
	CreatedAt       time.Time `json:"created_at"`
	// UnreachableFingerprints: recipients not currently published in the
	// directory — their share rows exist but they can't receive it until they
	// publish. The client warns the sender.
	UnreachableFingerprints []string `json:"unreachable_fingerprints"`
}

type ShareFinalizeResult struct {
	ShareID string `json:"share_id"`
}

type ShareDownload struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	FileName  string    `json:"file_name"`
	FileSize  int64     `json:"file_size"`
}

type ShareSummary struct {
	ID                    string    `json:"id"`
	RecipientFingerprints []string  `json:"recipient_fingerprints"` // the contact recipients
	ToSelf                bool      `json:"to_self"`                // also shared to own devices
	RecipientCount        int64     `json:"recipient_count"`
	DownloadedCount       int64     `json:"downloaded_count"` // recipients who completed
	TTLExpiresAt          time.Time `json:"ttl_expires_at"`   // zero = never expires
	SingleUse             bool      `json:"single_use"`
	FileName              string    `json:"file_name"`
	FileSize              int64     `json:"file_size"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
}

// ShareInboxItem is a downloadable share addressed to one of the account's
// published fingerprints. Sender name/email are present only when the
// sender has a published directory entry.
type ShareInboxItem struct {
	ShareID              string    `json:"share_id"`
	FileName             string    `json:"file_name"`
	FileSize             int64     `json:"file_size"`
	SingleUse            bool      `json:"single_use"`
	TTLExpiresAt         time.Time `json:"ttl_expires_at"` // zero = never expires
	CreatedAt            time.Time `json:"created_at"`
	RecipientFingerprint string    `json:"recipient_fingerprint"` // empty for self-shares
	ToSelf               bool      `json:"to_self"`               // sent by this account to its own devices
	SenderName           string    `json:"sender_name"`
	SenderEmail          string    `json:"sender_email"`
}

// --- billing ---

type Subscription struct {
	Tier             string     `json:"tier"`
	Status           string     `json:"status"`
	Provider         string     `json:"provider"`
	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
	// CancelAtPeriodEnd: active but will not renew — show "cancels on
	// DATE" and offer resume instead of "renews DATE".
	CancelAtPeriodEnd bool `json:"cancel_at_period_end"`
}

// --- plan ---

type Plan struct {
	Tier string `json:"tier"`
	// Vip is admin-granted: limits are Ultimate regardless of Tier, which
	// stays the real billing tier (display as e.g. "free (VIP)").
	Vip    bool       `json:"vip"`
	Limits PlanLimits `json:"limits"`
}

type PlanLimits struct {
	MaxContacts      int   `json:"max_contacts"`
	MaxStorageBytes  int64 `json:"max_storage_bytes"`
	MaxFileSizeBytes int64 `json:"max_file_size_bytes"`
	MaxActiveShares  int   `json:"max_active_shares"`
	BackupAllowed    bool  `json:"backup_allowed"`
}
