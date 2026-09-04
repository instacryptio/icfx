package groups

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	s := NewStoreWithPath(filepath.Join(t.TempDir(), "groups.json"))

	g, err := s.Add("Team", []string{"id-a", "id-b"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if g.ID == "" || g.Name != "Team" || len(g.MemberIDs) != 2 {
		t.Fatalf("bad group: %+v", g)
	}

	if _, err := s.Add("Team", nil); err != ErrAlreadyExists {
		t.Fatalf("duplicate name should error, got %v", err)
	}

	if err := s.Edit(g.ID, "Team A", []string{"id-a"}); err != nil {
		t.Fatalf("Edit: %v", err)
	}
	list, _ := s.List()
	if len(list) != 1 || list[0].Name != "Team A" || len(list[0].MemberIDs) != 1 {
		t.Fatalf("edit not applied: %+v", list)
	}

	if err := s.Remove(g.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	list, _ = s.List()
	if len(list) != 0 {
		t.Fatalf("group should be gone, got %+v", list)
	}
	// The delete must be recorded as a tombstone for sync.
	view, _ := s.SyncBytes()
	var d groupData
	_ = json.Unmarshal(view, &d)
	if len(d.Deleted) != 1 || d.Deleted[0] != g.ID {
		t.Fatalf("expected tombstone for %s, got %+v", g.ID, d.Deleted)
	}

	if err := s.Edit("nonexistent", "x", nil); err != ErrNotFound {
		t.Fatalf("edit unknown should ErrNotFound, got %v", err)
	}
}

func view(t *testing.T, groups []Group, deleted []string) []byte {
	t.Helper()
	b, err := json.Marshal(groupData{Version: storeVersion, Groups: groups, Deleted: deleted})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMergeGroups_LWWAndTombstone(t *testing.T) {
	t0 := time.Now().UTC()
	older := Group{ID: "g1", Name: "Team", MemberIDs: []string{"a"}, UpdatedAt: t0}
	newer := Group{ID: "g1", Name: "Team", MemberIDs: []string{"a", "b", "c"}, UpdatedAt: t0.Add(time.Minute)}

	// Later UpdatedAt wins regardless of side/order.
	local := view(t, []Group{older}, nil)
	remote := view(t, []Group{newer}, nil)
	m1, err := MergeGroups(local, remote)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	m2, _ := MergeGroups(remote, local)
	if !bytes.Equal(m1, m2) {
		t.Fatal("merge is not commutative")
	}
	var d groupData
	_ = json.Unmarshal(m1, &d)
	if len(d.Groups) != 1 || len(d.Groups[0].MemberIDs) != 3 {
		t.Fatalf("LWW should keep the newer 3-member group: %+v", d.Groups)
	}

	// A tombstone on either side drops the group and wins.
	withTomb := view(t, nil, []string{"g1"})
	m3, _ := MergeGroups(remote, withTomb)
	var d3 groupData
	_ = json.Unmarshal(m3, &d3)
	if len(d3.Groups) != 0 || len(d3.Deleted) != 1 {
		t.Fatalf("tombstone must drop the group: %+v", d3)
	}

	// Idempotent: merging a result with itself is a no-op.
	m4, _ := MergeGroups(m1, m1)
	if !bytes.Equal(m1, m4) {
		t.Fatal("merge is not idempotent")
	}
}
