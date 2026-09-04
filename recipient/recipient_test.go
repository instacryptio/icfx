package recipient

import (
	"errors"
	"strings"
	"testing"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
)

func sampleContacts() []contacts.Contact {
	return []contacts.Contact{
		{Alias: "alice", Email: "alice@example.com", Nickname: "al", EncPubKey: "age1pq1alice", Fingerprint: "fp-alice"},
		{Alias: "bob", Email: "bob@example.com", EncPubKey: "", Fingerprint: "fp-bob"},           // revoked (no lock)
		{Alias: "carol", Email: "carol@example.com", EncPubKey: "age1pq1carol", Fingerprint: ""}, // no fingerprint
	}
}

func noOpen(idx identity.IdentityIndex) (string, error) {
	return "", errors.New("open should not be called")
}

func TestForEncrypt_RawLock(t *testing.T) {
	got, err := ForEncrypt("age1pq1rawrecipient", nil, nil, noOpen)
	if err != nil || got != "age1pq1rawrecipient" {
		t.Fatalf("raw lock should pass through: got %q err %v", got, err)
	}
}

func TestForEncrypt_ContactAlias(t *testing.T) {
	got, err := ForEncrypt("alice", sampleContacts(), nil, noOpen)
	if err != nil || got != "age1pq1alice" {
		t.Fatalf("want alice lock, got %q err %v", got, err)
	}
}

func TestForEncrypt_EmailNickname(t *testing.T) {
	got, err := ForEncrypt("al", sampleContacts(), nil, noOpen) // nickname
	if err != nil || got != "age1pq1alice" {
		t.Fatalf("want alice by nickname, got %q err %v", got, err)
	}
	got, err = ForEncrypt("bob@example.com", sampleContacts(), nil, noOpen)
	if err != nil || got != "" { // bob's lock is empty but resolution still matched
		t.Fatalf("want bob by email, got %q err %v", got, err)
	}
}

func TestForEncrypt_OwnIdentity(t *testing.T) {
	entries := []identity.IdentityIndex{{Name: "work"}, {Name: "personal"}}
	called := ""
	open := func(idx identity.IdentityIndex) (string, error) {
		called = idx.Name
		return "age1pq1myown", nil
	}
	got, err := ForEncrypt("personal", nil, entries, open)
	if err != nil || got != "age1pq1myown" {
		t.Fatalf("want own-identity lock, got %q err %v", got, err)
	}
	if called != "personal" {
		t.Fatalf("open called for %q, want personal", called)
	}
}

func TestForEncrypt_NotFound(t *testing.T) {
	if _, err := ForEncrypt("nobody", sampleContacts(), []identity.IdentityIndex{{Name: "x"}}, noOpen); err == nil {
		t.Fatal("want error for unknown recipient")
	}
}

func TestForEncrypt_OwnIdentityUnlockFails(t *testing.T) {
	entries := []identity.IdentityIndex{{Name: "work"}}
	open := func(idx identity.IdentityIndex) (string, error) { return "", errors.New("hw tap declined") }
	if _, err := ForEncrypt("work", nil, entries, open); err == nil {
		t.Fatal("want error when the only matching identity fails to unlock")
	}
}

func TestExpandGroups(t *testing.T) {
	cs := []contacts.Contact{
		{ID: "id-a", Alias: "alice", EncPubKey: "age1pq1alice"},
		{ID: "id-b", Alias: "bob", EncPubKey: "age1pq1bob"},
		{ID: "id-c", Alias: "carol", EncPubKey: ""}, // revoked (no lock) → skipped
	}
	gl := []groups.Group{{ID: "g1", Name: "Team", MemberIDs: []string{"id-a", "id-b", "id-c", "id-missing"}}}

	eq := func(got, want []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	expand := func(tos []string, groupList []groups.Group, cl []contacts.Contact) []string {
		r, _ := ExpandGroups(tos, groupList, cl)
		return r
	}

	// A group expands to its members' locks; lockless + dangling members skipped.
	eq(expand([]string{"Team"}, gl, cs), []string{"age1pq1alice", "age1pq1bob"})

	// Contact precedence: a contact whose alias equals a group name stays a contact.
	withCollision := append(append([]contacts.Contact{}, cs...),
		contacts.Contact{ID: "id-t", Alias: "Team", EncPubKey: "age1pq1team"})
	eq(expand([]string{"Team"}, gl, withCollision), []string{"Team"})

	// Non-group, non-contact refs pass through for ForEncrypt to handle.
	eq(expand([]string{"age1pq1raw", "nobody"}, gl, cs), []string{"age1pq1raw", "nobody"})

	// Mixed: a contact ref stays; a group ref expands.
	eq(expand([]string{"alice", "Team"}, gl, cs), []string{"alice", "age1pq1alice", "age1pq1bob"})
}

func TestExpandGroups_Warnings(t *testing.T) {
	cs := []contacts.Contact{
		{ID: "id-a", Alias: "alice", EncPubKey: "age1pq1alice"},
		{ID: "id-c", Alias: "carol", EncPubKey: ""}, // no active lock → warn + skip
	}
	// id-missing is a dangling member (contact deleted) → warn + skip.
	gl := []groups.Group{{ID: "g1", Name: "Team", MemberIDs: []string{"id-a", "id-c", "id-missing"}}}

	recips, warnings := ExpandGroups([]string{"Team"}, gl, cs)
	if len(recips) != 1 || recips[0] != "age1pq1alice" {
		t.Fatalf("recipients = %v, want just alice's lock", recips)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v, want 2 (lockless carol + dangling member)", warnings)
	}
	var sawCarol, sawMissing bool
	for _, w := range warnings {
		if strings.Contains(w, "carol") {
			sawCarol = true
		}
		if strings.Contains(w, "Team") {
			sawMissing = true
		}
	}
	if !sawCarol || !sawMissing {
		t.Fatalf("warnings = %v, want one mentioning carol and one mentioning the group", warnings)
	}

	// An all-unreachable group yields an empty-group warning and no recipients.
	only := []contacts.Contact{{ID: "id-c", Alias: "carol", EncPubKey: ""}}
	gl2 := []groups.Group{{ID: "g2", Name: "Ghosts", MemberIDs: []string{"id-c"}}}
	recips2, warnings2 := ExpandGroups([]string{"Ghosts"}, gl2, only)
	if len(recips2) != 0 {
		t.Fatalf("recipients = %v, want none", recips2)
	}
	if len(warnings2) == 0 {
		t.Fatal("want at least one warning for an all-unreachable group")
	}
}

func TestForEncryptMany_MultipleAndDedupe(t *testing.T) {
	// Resolve alice by alias, carol by alias, alice again by nickname, and a
	// raw lock. alice appears twice via different handles → deduped to one.
	got, err := ForEncryptMany(
		[]string{"alice", "carol", "al", "age1pq1raw"},
		sampleContacts(), nil, noOpen,
	)
	if err != nil {
		t.Fatalf("ForEncryptMany error: %v", err)
	}
	want := []string{"age1pq1alice", "age1pq1carol", "age1pq1raw"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (order preserved, first occurrence)", got, want)
		}
	}
}

func TestForEncryptMany_SkipsEmptyRefs(t *testing.T) {
	got, err := ForEncryptMany([]string{"", "alice", ""}, sampleContacts(), nil, noOpen)
	if err != nil {
		t.Fatalf("ForEncryptMany error: %v", err)
	}
	if len(got) != 1 || got[0] != "age1pq1alice" {
		t.Fatalf("got %v, want [age1pq1alice]", got)
	}
}

func TestForEncryptMany_UnresolvedErrors(t *testing.T) {
	if _, err := ForEncryptMany([]string{"alice", "nobody"}, sampleContacts(), nil, noOpen); err == nil {
		t.Fatal("want error when a ref does not resolve")
	}
}

func TestForEncryptMany_EmptySet(t *testing.T) {
	if _, err := ForEncryptMany(nil, sampleContacts(), nil, noOpen); err == nil {
		t.Fatal("want error for empty recipient set")
	}
	if _, err := ForEncryptMany([]string{""}, sampleContacts(), nil, noOpen); err == nil {
		t.Fatal("want error when all refs are empty")
	}
}

func TestForShareMany(t *testing.T) {
	cs := []contacts.Contact{
		{ID: "id-a", Alias: "alice", EncPubKey: "age1pq1alice", Fingerprint: "fp-alice"},
		{ID: "id-b", Alias: "bob", EncPubKey: "age1pq1bob", Fingerprint: "fp-bob"},
		{ID: "id-c", Alias: "carol", EncPubKey: "age1pq1carol", Fingerprint: ""}, // unpublished → skip
	}
	gl := []groups.Group{{ID: "g1", Name: "Team", MemberIDs: []string{"id-a", "id-c", "id-missing"}}}

	t.Run("group expands to shareable members, skips fingerprint-less", func(t *testing.T) {
		targets, warnings, err := ForShareMany(cs, gl, []string{"Team"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(targets) != 1 || targets[0].Fingerprint != "fp-alice" || targets[0].Alias != "alice" {
			t.Fatalf("targets = %+v, want just alice", targets)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "carol") {
			t.Fatalf("warnings = %v, want one mentioning carol", warnings)
		}
	})

	t.Run("mixed contact + group, dedupe by fingerprint", func(t *testing.T) {
		targets, _, err := ForShareMany(cs, gl, []string{"bob", "Team", "alice"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		// bob + (Team→alice) + alice(dupe) = bob, alice
		if len(targets) != 2 {
			t.Fatalf("targets = %+v, want 2 (bob, alice deduped)", targets)
		}
	})

	t.Run("unknown ref is a hard error", func(t *testing.T) {
		if _, _, err := ForShareMany(cs, gl, []string{"nobody"}); err == nil {
			t.Fatal("want error for an unknown recipient")
		}
	})

	t.Run("all unreachable → error", func(t *testing.T) {
		if _, _, err := ForShareMany(cs, gl, []string{"carol"}); err == nil {
			t.Fatal("want error when no recipient is reachable")
		}
	})
}

// NOTE: the singular ForShare was removed (unused — ForShareMany resolves
// recipients inline); its contact-resolution behavior is covered by
// TestForShareMany above.
