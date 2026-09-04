package cloud

import "context"

// Checkout starts a subscription checkout for a paid tier ("basic", "pro", or
// "ultimate") and returns the provider URL to send the user to. The account's
// email must be verified first (the server returns 403 otherwise).
func (c *Client) Checkout(ctx context.Context, tier string) (string, error) {
	var res struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/billing/checkout",
		map[string]string{"tier": tier}, &res, true); err != nil {
		return "", err
	}
	return res.RedirectURL, nil
}

// ChangeSubscription swaps the account's existing subscription to another
// paid tier in place — immediate, with the prorated difference credited or
// charged by the provider. The new tier lands asynchronously once the
// provider confirms via webhook. Returns IsNotFound when there is no
// subscription to change (use Checkout instead).
func (c *Client) ChangeSubscription(ctx context.Context, tier string) error {
	return c.doJSON(ctx, "POST", "/v1/billing/change",
		map[string]string{"tier": tier}, nil, true)
}

// CancelSubscription schedules the subscription to end at the period
// boundary (the account keeps the paid tier until then). The pending state
// — and eventually the downgrade — lands via the provider webhook.
func (c *Client) CancelSubscription(ctx context.Context) error {
	return c.doJSON(ctx, "POST", "/v1/billing/cancel", nil, nil, true)
}

// ResumeSubscription clears a pending at-period-end cancellation.
func (c *Client) ResumeSubscription(ctx context.Context) error {
	return c.doJSON(ctx, "POST", "/v1/billing/resume", nil, nil, true)
}

// GetSubscription returns the account's current subscription, or IsNotFound
// when there is none (the account is on the Free tier).
func (c *Client) GetSubscription(ctx context.Context) (Subscription, error) {
	var s Subscription
	err := c.doJSON(ctx, "GET", "/v1/billing/subscription", nil, &s, true)
	return s, err
}
