package contacts

import "testing"

func TestFindByFingerprint(t *testing.T) {
	list := []Contact{
		{Alias: "alice", Fingerprint: "aaaa1111bbbb2222"},
		{Alias: "bob", Fingerprint: "cccc3333dddd4444", PreviousKeys: []PreviousKey{
			{Fingerprint: "0000oldoldold0000"},
		}},
		{Alias: "revoked", Fingerprint: ""}, // revoked contact — empty fp
	}

	t.Run("empty fingerprint never matches", func(t *testing.T) {
		if _, ok := FindByFingerprint(list, ""); ok {
			t.Fatal("empty fingerprint must not match (even the revoked empty-fp contact)")
		}
	})
	t.Run("current fingerprint", func(t *testing.T) {
		c, ok := FindByFingerprint(list, "aaaa1111bbbb2222")
		if !ok || c.Alias != "alice" {
			t.Fatalf("want alice, got %+v ok=%v", c, ok)
		}
	})
	t.Run("case-insensitive", func(t *testing.T) {
		c, ok := FindByFingerprint(list, "AAAA1111BBBB2222")
		if !ok || c.Alias != "alice" {
			t.Fatalf("want alice (case-insensitive), got %+v ok=%v", c, ok)
		}
	})
	t.Run("rotated-away previous key still matches", func(t *testing.T) {
		c, ok := FindByFingerprint(list, "0000oldoldold0000")
		if !ok || c.Alias != "bob" {
			t.Fatalf("want bob via previous key, got %+v ok=%v", c, ok)
		}
	})
	t.Run("unknown fingerprint", func(t *testing.T) {
		if _, ok := FindByFingerprint(list, "ffffffffffffffff"); ok {
			t.Fatal("unknown fingerprint must not match")
		}
	})
}
