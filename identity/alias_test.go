package identity

import (
	"errors"
	"testing"
)

func idxSet() []IdentityIndex {
	return []IdentityIndex{
		{Name: "Test Tester - Instacrypt", Alias: "ictest"},
		{Name: "Work Account", Alias: "work"},
		{Name: "No Alias"},
	}
}

func TestFindIndexByNameOrAlias(t *testing.T) {
	entries := idxSet()

	// Exact name match.
	got, err := FindIndexByNameOrAlias(entries, "Work Account")
	if err != nil || got.Alias != "work" {
		t.Fatalf("by name: got %+v err %v", got, err)
	}

	// Alias match, case-insensitive.
	got, err = FindIndexByNameOrAlias(entries, "ICTEST")
	if err != nil || got.Name != "Test Tester - Instacrypt" {
		t.Fatalf("by alias: got %+v err %v", got, err)
	}

	// Name wins over a same-string alias would (name checked first) — n/a here,
	// just confirm a miss returns ErrNotFound.
	if _, err := FindIndexByNameOrAlias(entries, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("miss: want ErrNotFound, got %v", err)
	}

	// Empty ref must not match the aliasless entry.
	if _, err := FindIndexByNameOrAlias(entries, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty ref: want ErrNotFound, got %v", err)
	}
}

func TestCheckAliasUnique(t *testing.T) {
	entries := idxSet()

	// Duplicate (case-insensitive) against a different identity → taken.
	if err := CheckAliasUnique(entries, "WORK", ""); !errors.Is(err, ErrAliasTaken) {
		t.Fatalf("dup: want ErrAliasTaken, got %v", err)
	}

	// Editing the same identity to keep its own alias is allowed.
	if err := CheckAliasUnique(entries, "work", "Work Account"); err != nil {
		t.Fatalf("self-keep: want nil, got %v", err)
	}

	// A fresh alias is fine.
	if err := CheckAliasUnique(entries, "brandnew", ""); err != nil {
		t.Fatalf("fresh: want nil, got %v", err)
	}

	// Empty alias is always allowed.
	if err := CheckAliasUnique(entries, "", ""); err != nil {
		t.Fatalf("empty: want nil, got %v", err)
	}

	// An alias equal to a DIFFERENT identity's NAME is rejected (confused-deputy),
	// case-insensitively.
	nameOnly := []IdentityIndex{{Name: "solo"}}
	if err := CheckAliasUnique(nameOnly, "solo", ""); !errors.Is(err, ErrAliasTaken) {
		t.Fatalf("alias==other name: want ErrAliasTaken, got %v", err)
	}
	if err := CheckAliasUnique([]IdentityIndex{{Name: "Solo"}}, "solo", ""); !errors.Is(err, ErrAliasTaken) {
		t.Fatalf("alias==other name (case): want ErrAliasTaken, got %v", err)
	}
}

func TestResolveDefaultIndex(t *testing.T) {
	entries := []IdentityIndex{{Name: "alice"}, {Name: "bob"}}
	if idx := ResolveDefaultIndex(entries, "bob"); idx == nil || idx.Name != "bob" {
		t.Fatalf("named default: %+v", idx)
	}
	if idx := ResolveDefaultIndex(entries, "ghost"); idx == nil || idx.Name != "alice" {
		t.Fatalf("missing default → first: %+v", idx)
	}
	if idx := ResolveDefaultIndex(entries, ""); idx == nil || idx.Name != "alice" {
		t.Fatalf("empty default → first: %+v", idx)
	}
	if idx := ResolveDefaultIndex(nil, "x"); idx != nil {
		t.Fatalf("empty index → nil, got %+v", idx)
	}
}

func TestCheckNameAvailable(t *testing.T) {
	entries := []IdentityIndex{{Name: "Work Account", Alias: "work"}}
	if err := CheckNameAvailable(entries, "Work Account"); !errors.Is(err, ErrAliasTaken) {
		t.Fatalf("name==existing name: want ErrAliasTaken, got %v", err)
	}
	if err := CheckNameAvailable(entries, "work"); !errors.Is(err, ErrAliasTaken) {
		t.Fatalf("name==existing alias: want ErrAliasTaken, got %v", err)
	}
	if err := CheckNameAvailable(entries, "fresh"); err != nil {
		t.Fatalf("fresh name: want nil, got %v", err)
	}
}

func TestBackupFilename(t *testing.T) {
	// Alias present → alias-based name.
	if got := BackupFilename(Identity{Name: "Test Tester - Instacrypt", Alias: "ictest"}); got != "ictest.icid" {
		t.Errorf("alias: got %q", got)
	}
	// No alias → sanitized name fallback (spaces → underscores).
	if got := BackupFilename(Identity{Name: "No Alias"}); got != "No_Alias.icid" {
		t.Errorf("name fallback: got %q", got)
	}
	// Index counterpart matches.
	if got := IndexBackupFilename(IdentityIndex{Name: "Work Account", Alias: "work"}); got != "work.icid" {
		t.Errorf("index: got %q", got)
	}
}
