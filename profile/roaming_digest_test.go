package profile_test

import (
	"testing"

	"github.com/instacryptio/icfx/profile"
)

// TestRoamingDigest: deterministic for an unchanged set, sensitive to
// additions — the two properties the stateful sync engine leans on.
func TestRoamingDigest(t *testing.T) {
	ks := useEnv(t, t.TempDir())
	createLocalIdentity(t, ks, "main")

	d1, err := profile.RoamingDigest(fileExportFn(t))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d2, err := profile.RoamingDigest(fileExportFn(t))
	if err != nil {
		t.Fatalf("digest again: %v", err)
	}
	if d1 != d2 || d1 == "" {
		t.Fatalf("digest must be deterministic and non-empty: %q vs %q", d1, d2)
	}

	// Adding an identity changes the digest.
	createLocalIdentity(t, ks, "work")
	d3, err := profile.RoamingDigest(fileExportFn(t))
	if err != nil {
		t.Fatalf("digest after add: %v", err)
	}
	if d3 == d1 {
		t.Fatal("digest must change when the identity set changes")
	}
}
