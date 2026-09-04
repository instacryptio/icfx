package cloud

import "context"

func (c *Client) GetPlan(ctx context.Context) (Plan, error) {
	var p Plan
	err := c.doJSON(ctx, "GET", "/v1/plan", nil, &p, true)
	return p, err
}

// DisplayTier renders an account tier for humans, appending the admin-granted
// VIP marker (e.g. "free (VIP)"). VIP keeps the real billing tier and grants
// Ultimate limits, so it decorates the tier rather than replacing it. Shared by
// every tier/plan status line so the convention can't drift between surfaces.
func DisplayTier(tier string, vip bool) string {
	if vip {
		return tier + " (VIP)"
	}
	return tier
}

// PlanCatalogEntry is one tier in the server's public plan catalog, in
// upgrade order. Prices are advertised display values; billing truth lives
// at the payment provider.
type PlanCatalogEntry struct {
	Tier              string `json:"tier"`
	PriceMonthlyCents int    `json:"price_monthly_cents"`
	MaxContacts       int    `json:"max_contacts"`
	BackupAllowed     bool   `json:"backup_allowed"`
	MaxActiveShares   int    `json:"max_active_shares"`
	MaxFileSizeBytes  int64  `json:"max_file_size_bytes"`
}

// ListPlans returns the public plan catalog. No authentication required —
// clients render pricing tables from it before signup.
func (c *Client) ListPlans(ctx context.Context) ([]PlanCatalogEntry, error) {
	var out []PlanCatalogEntry
	err := c.doJSON(ctx, "GET", "/v1/plans", nil, &out, false)
	return out, err
}
