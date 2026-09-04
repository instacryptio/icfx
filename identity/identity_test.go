package identity

import (
	"errors"
	"testing"
	"time"
)

func TestFindByName(t *testing.T) {
	ids := []Identity{
		{Name: "alice", Email: "alice@test.com", IsPrimary: true, CreatedAt: time.Now()},
		{Name: "bob", Email: "bob@test.com", IsPrimary: false, CreatedAt: time.Now()},
	}

	id, err := FindByName(ids, "alice")
	if err != nil {
		t.Fatalf("FindByName(alice) error: %v", err)
	}
	if id.Name != "alice" {
		t.Errorf("FindByName(alice) = %q", id.Name)
	}

	_, err = FindByName(ids, "nobody")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByName(nobody) = %v, want ErrNotFound", err)
	}
}

func TestFindPrimary(t *testing.T) {
	ids := []Identity{
		{Name: "secondary", IsPrimary: false},
		{Name: "primary", IsPrimary: true},
	}

	id, err := FindPrimary(ids)
	if err != nil {
		t.Fatalf("FindPrimary() error: %v", err)
	}
	if id.Name != "primary" {
		t.Errorf("FindPrimary() = %q, want primary", id.Name)
	}

	_, err = FindPrimary([]Identity{{Name: "none", IsPrimary: false}})
	if !errors.Is(err, ErrNoPrimary) {
		t.Errorf("FindPrimary() = %v, want ErrNoPrimary", err)
	}
}
