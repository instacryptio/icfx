package bundle

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/qr"
)

// validEncPub returns a real, parseable age1pq1 recipient so a test lock passes
// ValidateLockBundle (which ProcessImport now enforces).
func validEncPub(t *testing.T) string {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp.EncryptionRecipient
}

func mustProcessImport(t *testing.T, parsed *ParsedBundle, existing []contacts.Contact) *ImportResult {
	t.Helper()
	r, err := ProcessImport(parsed, existing)
	if err != nil {
		t.Fatalf("ProcessImport: %v", err)
	}
	return r
}

// TestProcessImportNilGuards: a hand-built ParsedBundle missing the pointer its
// type requires returns an error instead of panicking.
func TestProcessImportNilGuards(t *testing.T) {
	cases := map[string]*ParsedBundle{
		"nil parsed":            nil,
		"lock type, nil lock":   {Type: BundleLock},
		"revoke type, nil rev":  {Type: BundleRevoke},
		"rotate type, nil both": {Type: BundleRotate},
		"unknown type":          {Type: BundleType(99)},
	}
	for name, pb := range cases {
		if _, err := ProcessImport(pb, nil); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// --- Parse tests ---

func TestParse_ArmoredLock(t *testing.T) {
	lock := qr.LockBundle{
		ID: "IC-test", Name: "alice", EncPubKey: "age1pq1abc", SignPubKey: "sig123", Fingerprint: "fp1",
	}
	data, _ := json.Marshal(lock)
	armored := format.ArmorEncode(data, format.ArmorLockLabel)

	result, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleLock {
		t.Errorf("Type = %d, want BundleLock", result.Type)
	}
	if result.Lock == nil {
		t.Fatal("Lock is nil")
	}
	if result.Lock.EncPubKey != "age1pq1abc" {
		t.Errorf("EncPubKey = %q, want %q", result.Lock.EncPubKey, "age1pq1abc")
	}
}

func TestParse_ArmoredRevocation(t *testing.T) {
	rev := RevocationBundle{ID: "IC-test", RevokedFingerprint: "fp1", RevokedAt: "2026-01-01T00:00:00Z"}
	data, _ := json.Marshal(rev)
	armored := format.ArmorEncode(data, format.ArmorRevokeLabel)

	result, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleRevoke {
		t.Errorf("Type = %d, want BundleRevoke", result.Type)
	}
	if result.Revocation == nil {
		t.Fatal("Revocation is nil")
	}
	if result.Revocation.RevokedFingerprint != "fp1" {
		t.Errorf("RevokedFingerprint = %q, want %q", result.Revocation.RevokedFingerprint, "fp1")
	}
}

func TestParse_ArmoredRotation(t *testing.T) {
	rot := RotationBundle{
		Revocation: RevocationBundle{ID: "IC-test", RevokedFingerprint: "fp-old", RevokedAt: "2026-01-01T00:00:00Z"},
		NewLock:    qr.LockBundle{ID: "IC-test", Name: "alice", EncPubKey: "age1pq1new", Fingerprint: "fp-new"},
	}
	data, _ := json.Marshal(rot)
	armored := format.ArmorEncode(data, format.ArmorRotateLabel)

	result, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleRotate {
		t.Errorf("Type = %d, want BundleRotate", result.Type)
	}
	if result.Lock == nil || result.Revocation == nil {
		t.Fatal("Lock or Revocation is nil")
	}
	if result.Lock.EncPubKey != "age1pq1new" {
		t.Errorf("Lock.EncPubKey = %q, want %q", result.Lock.EncPubKey, "age1pq1new")
	}
	if result.Revocation.RevokedFingerprint != "fp-old" {
		t.Errorf("Revocation.RevokedFingerprint = %q, want %q", result.Revocation.RevokedFingerprint, "fp-old")
	}
}

func TestParse_RawJSONLock(t *testing.T) {
	data := []byte(`{"id":"IC-1","name":"bob","enc_pub_key":"age1pq1xyz","fingerprint":"fp2"}`)
	result, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleLock {
		t.Errorf("Type = %d, want BundleLock", result.Type)
	}
	if result.Lock.Name != "bob" {
		t.Errorf("Name = %q, want %q", result.Lock.Name, "bob")
	}
}

func TestParse_RawJSONRevocation(t *testing.T) {
	data := []byte(`{"id":"IC-1","revoked_fingerprint":"fp-revoked","revoked_at":"2026-01-01T00:00:00Z"}`)
	result, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleRevoke {
		t.Errorf("Type = %d, want BundleRevoke", result.Type)
	}
	if result.Revocation.ID != "IC-1" {
		t.Errorf("ID = %q, want %q", result.Revocation.ID, "IC-1")
	}
}

func TestParse_RawJSONRotation(t *testing.T) {
	data := []byte(`{
		"revocation":{"id":"IC-1","revoked_fingerprint":"fp-old","revoked_at":"2026-01-01T00:00:00Z"},
		"new_lock":{"id":"IC-1","name":"alice","enc_pub_key":"age1pq1new","fingerprint":"fp-new"}
	}`)
	result, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleRotate {
		t.Errorf("Type = %d, want BundleRotate", result.Type)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	_, err := Parse([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	_, err := Parse([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestParse_UnrecognizedFormat(t *testing.T) {
	_, err := Parse([]byte(`{"foo":"bar"}`))
	if err == nil {
		t.Error("expected error for unrecognized format")
	}
	if !strings.Contains(err.Error(), "unrecognized bundle format") {
		t.Errorf("error = %q, want 'unrecognized bundle format'", err.Error())
	}
}

func TestParse_LockWithoutEncPubKey_Unrecognized(t *testing.T) {
	// A lock bundle with empty enc_pub_key should not be recognized
	data := []byte(`{"id":"IC-1","name":"bob","fingerprint":"fp2"}`)
	_, err := Parse(data)
	if err == nil {
		t.Error("expected error for lock without enc_pub_key")
	}
}

// --- Marshal round-trip tests ---

func TestMarshalRevocation_RoundTrip(t *testing.T) {
	rev := NewRevocation("IC-test", "fp-revoked")
	armored, err := MarshalRevocation(rev)
	if err != nil {
		t.Fatalf("MarshalRevocation: %v", err)
	}

	result, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleRevoke {
		t.Errorf("Type = %d, want BundleRevoke", result.Type)
	}
	if result.Revocation.ID != "IC-test" {
		t.Errorf("ID = %q, want %q", result.Revocation.ID, "IC-test")
	}
	if result.Revocation.RevokedFingerprint != "fp-revoked" {
		t.Errorf("Fingerprint = %q, want %q", result.Revocation.RevokedFingerprint, "fp-revoked")
	}
}

func TestMarshalRotation_RoundTrip(t *testing.T) {
	rot := RotationBundle{
		Revocation: NewRevocation("IC-rot", "fp-old"),
		NewLock:    qr.LockBundle{ID: "IC-rot", Name: "alice", EncPubKey: "age1pq1rotated", Fingerprint: "fp-new"},
	}
	armored, err := MarshalRotation(rot)
	if err != nil {
		t.Fatalf("MarshalRotation: %v", err)
	}

	result, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.Type != BundleRotate {
		t.Errorf("Type = %d, want BundleRotate", result.Type)
	}
	if result.Lock.EncPubKey != "age1pq1rotated" {
		t.Errorf("EncPubKey = %q, want %q", result.Lock.EncPubKey, "age1pq1rotated")
	}
}

// --- NewRevocation tests ---

func TestNewRevocation(t *testing.T) {
	before := time.Now().Add(-time.Second)
	rev := NewRevocation("IC-new", "fp-new")
	after := time.Now().Add(time.Second)

	if rev.ID != "IC-new" {
		t.Errorf("ID = %q, want %q", rev.ID, "IC-new")
	}
	if rev.RevokedFingerprint != "fp-new" {
		t.Errorf("RevokedFingerprint = %q, want %q", rev.RevokedFingerprint, "fp-new")
	}

	ts, err := time.Parse(time.RFC3339, rev.RevokedAt)
	if err != nil {
		t.Fatalf("RevokedAt not RFC3339: %v", err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("RevokedAt = %v, not within expected range", ts)
	}
}

// --- ProcessImport tests ---

func TestProcessImport_LockNewContact(t *testing.T) {
	lock := &qr.LockBundle{ID: "IC-new", Name: "alice", EncPubKey: validEncPub(t)}
	parsed := &ParsedBundle{Type: BundleLock, Lock: lock}

	result := mustProcessImport(t, parsed, []contacts.Contact{})
	if result.Action != ActionAdd {
		t.Errorf("Action = %d, want ActionAdd", result.Action)
	}
	if result.NewKeys.Name != "alice" {
		t.Errorf("NewKeys.Name = %q, want %q", result.NewKeys.Name, "alice")
	}
	if result.Contact != nil {
		t.Error("Contact should be nil for new add")
	}
}

func TestProcessImport_LockMatchByID(t *testing.T) {
	existing := []contacts.Contact{
		{ID: "IC-existing", Alias: "bob", EncPubKey: "old-key"},
	}
	lock := &qr.LockBundle{ID: "IC-existing", Name: "bob", EncPubKey: validEncPub(t)}
	parsed := &ParsedBundle{Type: BundleLock, Lock: lock}

	result := mustProcessImport(t, parsed, existing)
	if result.Action != ActionUpdate {
		t.Errorf("Action = %d, want ActionUpdate", result.Action)
	}
	if result.Contact == nil {
		t.Fatal("Contact should not be nil for update")
	}
	if result.Contact.Alias != "bob" {
		t.Errorf("Contact.Alias = %q, want %q", result.Contact.Alias, "bob")
	}
}

func TestProcessImport_LockMatchByEmail(t *testing.T) {
	existing := []contacts.Contact{
		{ID: "IC-other", Alias: "carol", Email: "carol@test.com", EncPubKey: "old-key"},
	}
	lock := &qr.LockBundle{ID: "IC-different", Name: "carol", Email: "carol@test.com", EncPubKey: validEncPub(t)}
	parsed := &ParsedBundle{Type: BundleLock, Lock: lock}

	result := mustProcessImport(t, parsed, existing)
	if result.Action != ActionUpdate {
		t.Errorf("Action = %d, want ActionUpdate (match by email)", result.Action)
	}
}

func TestProcessImport_RevokeKnownContact(t *testing.T) {
	existing := []contacts.Contact{
		{ID: "IC-known", Alias: "dave", EncPubKey: "key1"},
	}
	rev := &RevocationBundle{ID: "IC-known", RevokedFingerprint: "fp1"}
	parsed := &ParsedBundle{Type: BundleRevoke, Revocation: rev}

	result := mustProcessImport(t, parsed, existing)
	if result.Action != ActionRevoke {
		t.Errorf("Action = %d, want ActionRevoke", result.Action)
	}
	if result.Contact == nil {
		t.Fatal("Contact should not be nil for known revocation")
	}
}

func TestProcessImport_RevokeUnknownContact(t *testing.T) {
	rev := &RevocationBundle{ID: "IC-unknown", RevokedFingerprint: "fp1"}
	parsed := &ParsedBundle{Type: BundleRevoke, Revocation: rev}

	result := mustProcessImport(t, parsed, []contacts.Contact{})
	if result.Action != ActionRevoke {
		t.Errorf("Action = %d, want ActionRevoke", result.Action)
	}
	if result.Contact != nil {
		t.Error("Contact should be nil for unknown revocation")
	}
	if !strings.Contains(result.Message, "unknown") {
		t.Errorf("Message should mention 'unknown', got %q", result.Message)
	}
}

func TestProcessImport_RotateExisting(t *testing.T) {
	existing := []contacts.Contact{
		{ID: "IC-rot", Alias: "eve", EncPubKey: "old-key"},
	}
	lock := &qr.LockBundle{ID: "IC-rot", Name: "eve", EncPubKey: validEncPub(t)}
	rev := &RevocationBundle{ID: "IC-rot", RevokedFingerprint: "fp-old"}
	parsed := &ParsedBundle{Type: BundleRotate, Lock: lock, Revocation: rev}

	result := mustProcessImport(t, parsed, existing)
	if result.Action != ActionUpdate {
		t.Errorf("Action = %d, want ActionUpdate", result.Action)
	}
	if result.NewKeys == nil || result.Revocation == nil {
		t.Error("both NewKeys and Revocation should be set for rotation")
	}
}

func TestProcessImport_RotateNewContact(t *testing.T) {
	lock := &qr.LockBundle{ID: "IC-new", Name: "frank", EncPubKey: validEncPub(t)}
	rev := &RevocationBundle{ID: "IC-new", RevokedFingerprint: "fp-old"}
	parsed := &ParsedBundle{Type: BundleRotate, Lock: lock, Revocation: rev}

	result := mustProcessImport(t, parsed, []contacts.Contact{})
	if result.Action != ActionAdd {
		t.Errorf("Action = %d, want ActionAdd for rotation with no existing contact", result.Action)
	}
}

// --- ApplyUpdate tests ---

func TestApplyUpdate(t *testing.T) {
	// Alias = their published handle (refreshed from the lock on rotation);
	// Nickname = the user's local shortcut (preserved across a lock refresh).
	c := &contacts.Contact{
		ID: "IC-1", Alias: "alice", Nickname: "ally",
		EncPubKey: "old-enc", SignPubKey: "old-sign", Fingerprint: "old-fp",
		Email: "alice@old.com",
	}
	lock := &qr.LockBundle{
		EncPubKey: "new-enc", SignPubKey: "new-sign", Fingerprint: "new-fp",
		Alias: "alicia", Email: "alice@new.com",
	}

	ApplyUpdate(c, lock)

	if c.EncPubKey != "new-enc" {
		t.Errorf("EncPubKey = %q, want %q", c.EncPubKey, "new-enc")
	}
	if c.SignPubKey != "new-sign" {
		t.Errorf("SignPubKey = %q, want %q", c.SignPubKey, "new-sign")
	}
	if c.Fingerprint != "new-fp" {
		t.Errorf("Fingerprint = %q, want %q", c.Fingerprint, "new-fp")
	}
	if c.Alias != "alicia" {
		t.Errorf("Alias = %q, want %q (refreshed from lock)", c.Alias, "alicia")
	}
	if c.Nickname != "ally" {
		t.Errorf("Nickname = %q, want %q (local shortcut preserved)", c.Nickname, "ally")
	}
	if c.Email != "alice@new.com" {
		t.Errorf("Email = %q, want %q", c.Email, "alice@new.com")
	}
	if c.ID != "IC-1" {
		t.Errorf("ID changed to %q, should be preserved", c.ID)
	}

	// Old keys archived
	if len(c.PreviousKeys) != 1 {
		t.Fatalf("PreviousKeys length = %d, want 1", len(c.PreviousKeys))
	}
	if c.PreviousKeys[0].EncPubKey != "old-enc" {
		t.Errorf("PreviousKeys[0].EncPubKey = %q, want %q", c.PreviousKeys[0].EncPubKey, "old-enc")
	}
}

func TestApplyUpdate_PreservesEmptyOptionalFields(t *testing.T) {
	c := &contacts.Contact{
		ID: "IC-1", Alias: "bob", Nickname: "bobby",
		EncPubKey: "old-enc", SignPubKey: "old-sign", Fingerprint: "old-fp",
		Email: "bob@test.com",
	}
	lock := &qr.LockBundle{
		EncPubKey: "new-enc", SignPubKey: "new-sign", Fingerprint: "new-fp",
		// Alias/Name and Email empty — should preserve existing values
	}

	ApplyUpdate(c, lock)

	if c.Alias != "bob" {
		t.Errorf("Alias changed to %q, should be preserved when lock has empty alias/name", c.Alias)
	}
	if c.Nickname != "bobby" {
		t.Errorf("Nickname changed to %q, should be preserved (local shortcut)", c.Nickname)
	}
	if c.Email != "bob@test.com" {
		t.Errorf("Email changed to %q, should be preserved when lock has empty email", c.Email)
	}
}

// --- ApplyRevoke tests ---

func TestApplyRevoke(t *testing.T) {
	c := &contacts.Contact{
		ID: "IC-1", Alias: "charlie",
		EncPubKey: "enc-key", SignPubKey: "sign-key", Fingerprint: "fp1",
	}

	ApplyRevoke(c)

	if c.EncPubKey != "" {
		t.Errorf("EncPubKey = %q, should be empty after revoke", c.EncPubKey)
	}
	if c.SignPubKey != "" {
		t.Errorf("SignPubKey = %q, should be empty after revoke", c.SignPubKey)
	}
	if c.Fingerprint != "" {
		t.Errorf("Fingerprint = %q, should be empty after revoke", c.Fingerprint)
	}

	// Old keys archived
	if len(c.PreviousKeys) != 1 {
		t.Fatalf("PreviousKeys length = %d, want 1", len(c.PreviousKeys))
	}
	if c.PreviousKeys[0].EncPubKey != "enc-key" {
		t.Errorf("PreviousKeys[0].EncPubKey = %q, want %q", c.PreviousKeys[0].EncPubKey, "enc-key")
	}
}

func TestApplyRevoke_AppendsToExistingHistory(t *testing.T) {
	c := &contacts.Contact{
		ID: "IC-1", Alias: "dave",
		EncPubKey: "enc-v2", SignPubKey: "sign-v2", Fingerprint: "fp-v2",
		PreviousKeys: []contacts.PreviousKey{
			{EncPubKey: "enc-v1", SignPubKey: "sign-v1", Fingerprint: "fp-v1", RevokedAt: time.Now().Add(-24 * time.Hour)},
		},
	}

	ApplyRevoke(c)

	if len(c.PreviousKeys) != 2 {
		t.Fatalf("PreviousKeys length = %d, want 2", len(c.PreviousKeys))
	}
	if c.PreviousKeys[0].EncPubKey != "enc-v1" {
		t.Errorf("PreviousKeys[0] should be the original v1 key")
	}
	if c.PreviousKeys[1].EncPubKey != "enc-v2" {
		t.Errorf("PreviousKeys[1] should be the revoked v2 key")
	}
}
