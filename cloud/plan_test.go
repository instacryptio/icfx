package cloud

import "testing"

func TestDisplayTier(t *testing.T) {
	cases := []struct {
		tier string
		vip  bool
		want string
	}{
		{"free", false, "free"},
		{"free", true, "free (VIP)"},
		{"ultimate", false, "ultimate"},
		{"pro", true, "pro (VIP)"},
		{"", true, " (VIP)"},
	}
	for _, c := range cases {
		if got := DisplayTier(c.tier, c.vip); got != c.want {
			t.Errorf("DisplayTier(%q, %v) = %q, want %q", c.tier, c.vip, got, c.want)
		}
	}
}
