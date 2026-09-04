package groups

import (
	"encoding/json"
	"sort"
	"strings"
)

// MergeGroups converges two group sync views (local + remote) into one. It is
// commutative and idempotent, as required by the cloud whole-blob CRDT sync:
//   - groups union by ID; the copy with the later UpdatedAt wins (last-writer-
//     wins), ties broken deterministically by canonical content so the result
//     is order-independent;
//   - Deleted tombstone sets union and WIN — a tombstoned group ID is dropped
//     from the output and can never be resurrected by a stale copy.
func MergeGroups(localBytes, remoteBytes []byte) ([]byte, error) {
	var a, b groupData
	if len(localBytes) > 0 {
		if err := json.Unmarshal(localBytes, &a); err != nil {
			return nil, err
		}
	}
	if len(remoteBytes) > 0 {
		if err := json.Unmarshal(remoteBytes, &b); err != nil {
			return nil, err
		}
	}

	deleted := map[string]struct{}{}
	for _, id := range a.Deleted {
		deleted[id] = struct{}{}
	}
	for _, id := range b.Deleted {
		deleted[id] = struct{}{}
	}

	byID := map[string]Group{}
	take := func(groups []Group) {
		for _, g := range groups {
			if _, gone := deleted[g.ID]; gone {
				continue
			}
			cur, ok := byID[g.ID]
			if !ok || winsOver(g, cur) {
				byID[g.ID] = g
			}
		}
	}
	take(a.Groups)
	take(b.Groups)

	out := make([]Group, 0, len(byID))
	for _, g := range byID {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})

	tomb := make([]string, 0, len(deleted))
	for id := range deleted {
		tomb = append(tomb, id)
	}
	sort.Strings(tomb)

	return json.Marshal(groupData{Version: storeVersion, Groups: out, Deleted: tomb})
}

// winsOver reports whether g should replace cur: later UpdatedAt wins; on an
// exact tie, the lexicographically greater canonical content wins (a stable,
// order-independent tiebreak).
func winsOver(g, cur Group) bool {
	if g.UpdatedAt.After(cur.UpdatedAt) {
		return true
	}
	if g.UpdatedAt.Before(cur.UpdatedAt) {
		return false
	}
	return canonical(g) > canonical(cur)
}

func canonical(g Group) string {
	members := append([]string(nil), g.MemberIDs...)
	sort.Strings(members)
	return g.Name + "\x00" + strings.Join(members, ",")
}
