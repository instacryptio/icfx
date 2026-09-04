package contacts

import (
	"errors"
	"testing"
	"time"
)

func TestFindByAlias(t *testing.T) {
	cs := []Contact{
		{Alias: "alice", Email: "alice@test.com", AddedAt: time.Now()},
		{Alias: "bob", Email: "bob@test.com", AddedAt: time.Now()},
	}

	c, err := FindByAlias(cs, "bob")
	if err != nil {
		t.Fatalf("FindByAlias(bob) error: %v", err)
	}
	if c.Alias != "bob" {
		t.Errorf("FindByAlias(bob) = %q", c.Alias)
	}

	_, err = FindByAlias(cs, "nobody")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByAlias(nobody) = %v, want ErrNotFound", err)
	}
}

func TestFindByEmailOrNickname(t *testing.T) {
	cs := []Contact{
		{Alias: "alice", Nickname: "ally", Email: "alice@test.com", AddedAt: time.Now()},
		{Alias: "bob", Nickname: "bobby", Email: "bob@test.com", AddedAt: time.Now()},
	}

	// Find by email
	c, err := FindByEmailOrNickname(cs, "bob@test.com")
	if err != nil {
		t.Fatalf("FindByEmailOrNickname(bob@test.com) error: %v", err)
	}
	if c.Alias != "bob" {
		t.Errorf("FindByEmailOrNickname(bob@test.com) = %q, want bob", c.Alias)
	}

	// Find by nickname
	c, err = FindByEmailOrNickname(cs, "ally")
	if err != nil {
		t.Fatalf("FindByEmailOrNickname(ally) error: %v", err)
	}
	if c.Alias != "alice" {
		t.Errorf("FindByEmailOrNickname(ally) = %q, want alice", c.Alias)
	}

	// Not found
	_, err = FindByEmailOrNickname(cs, "nobody")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByEmailOrNickname(nobody) = %v, want ErrNotFound", err)
	}
}
