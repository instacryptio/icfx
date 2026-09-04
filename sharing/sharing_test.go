package sharing

import "testing"

func TestReceiveName(t *testing.T) {
	cases := []struct {
		declared string
		want     string
	}{
		{"report.pdf.icfx", "report.pdf"},
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd.icfx", "passwd"},
		{"/abs/path/x.icfx", "x"},
		{"", "share-abc"},
		{".", "share-abc"},
		{"..", "share-abc"},
		{"  spaced.icfx ", "spaced"},
	}
	for _, c := range cases {
		if got := ReceiveName(c.declared, "abc"); got != c.want {
			t.Errorf("ReceiveName(%q) = %q, want %q", c.declared, got, c.want)
		}
	}
}

func TestShareIDFromLink(t *testing.T) {
	const id = "0e6f3b8a-6f0f-4b3a-9a4e-2a1b3c4d5e6f"
	cases := []string{
		id,
		"https://cloud.example.com/v1/share/" + id,
		"https://cloud.example.com/v1/share/" + id + "/",
		" " + id + " ",
	}
	for _, c := range cases {
		if got := ShareIDFromLink(c); got != id {
			t.Errorf("ShareIDFromLink(%q) = %q, want %q", c, got, id)
		}
	}
}
