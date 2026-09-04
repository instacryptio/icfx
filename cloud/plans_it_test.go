//go:build integration

package cloud_test

import (
	"context"
	"testing"

	"github.com/instacryptio/icfx/cloud"
)

// TestPlanCatalogPublic pins the public catalog contract clients render
// pricing tables from: no auth, four tiers in upgrade order, Free at $0
// with no sharing.
func TestPlanCatalogPublic(t *testing.T) {
	c, _ := cloud.New(baseURL()) // no login — the endpoint is public
	entries, err := c.ListPlans(context.Background())
	if err != nil {
		t.Fatalf("ListPlans: %v", err)
	}
	want := []string{"free", "basic", "pro", "ultimate"}
	if len(entries) != len(want) {
		t.Fatalf("want %d tiers, got %d: %+v", len(want), len(entries), entries)
	}
	for i, tier := range want {
		if entries[i].Tier != tier {
			t.Fatalf("order: want %s at %d, got %s", tier, i, entries[i].Tier)
		}
	}
	if entries[0].PriceMonthlyCents != 0 || entries[0].MaxActiveShares != 0 {
		t.Fatalf("free tier must be $0 with no shares: %+v", entries[0])
	}
	for _, e := range entries[1:] {
		if e.PriceMonthlyCents <= 0 || !e.BackupAllowed {
			t.Fatalf("paid tier %s must have a price and backup: %+v", e.Tier, e)
		}
	}
}
