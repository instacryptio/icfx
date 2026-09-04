package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// This file is the op-log client: contacts sync ships per-contact encrypted
// ops instead of the whole blob. Ops are OPAQUE to the server — each one is
// self-lock ciphertext of a tiny JSON envelope (see ContactOp). The blobs
// table still holds a full snapshot, but only as a bootstrap/compaction
// artifact; routine sync transfers ops only.

// ContactOp is the plaintext op envelope for the contacts resource.
// Op is "put" (upsert the whole contact) or "del" (tombstone). ID is the
// contact's alias — the contact store's uniqueness key on every client.
type ContactOp struct {
	Op      string          `json:"op"` // "put" | "del"
	ID      string          `json:"id"`
	Contact json.RawMessage `json:"contact,omitempty"` // the full contacts.Contact on put
}

// AppendedOps reports the server-assigned sequence range of an append batch.
type AppendedOps struct {
	FirstSeq int64 `json:"first_seq"`
	LastSeq  int64 `json:"last_seq"`
}

// AppendOps appends a batch of already-encrypted ops to the account's op log
// for resource, returning the assigned seq range.
func (c *Client) AppendOps(ctx context.Context, resource string, ops [][]byte) (AppendedOps, error) {
	encoded := make([]string, len(ops))
	for i, op := range ops {
		encoded[i] = base64.StdEncoding.EncodeToString(op)
	}
	var out AppendedOps
	err := c.doJSON(ctx, "POST", "/v1/ops/"+url.PathEscape(resource), map[string]any{"ops_b64": encoded}, &out, true)
	if err != nil {
		return AppendedOps{}, err
	}
	return out, nil
}

// Op is one fetched op-log entry: server-assigned seq + opaque ciphertext.
type Op struct {
	Seq        int64
	Ciphertext []byte
}

// FetchOpsSince returns every op after seq for resource, following server
// paging until exhausted.
func (c *Client) FetchOpsSince(ctx context.Context, resource string, seq int64) ([]Op, error) {
	var all []Op
	since := seq
	for {
		var out struct {
			Items []struct {
				Seq        int64  `json:"seq"`
				Ciphertext string `json:"ciphertext_b64"`
			} `json:"items"`
			HasMore bool `json:"has_more"`
		}
		path := "/v1/ops/" + url.PathEscape(resource) + "?since=" + strconv.FormatInt(since, 10)
		if err := c.doJSON(ctx, "GET", path, nil, &out, true); err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			raw, err := base64.StdEncoding.DecodeString(it.Ciphertext)
			if err != nil {
				return nil, fmt.Errorf("op %d: bad ciphertext encoding: %w", it.Seq, err)
			}
			all = append(all, Op{Seq: it.Seq, Ciphertext: raw})
			since = it.Seq
		}
		if !out.HasMore {
			return all, nil
		}
	}
}

// CompactOps uploads a full snapshot (already encrypted) and atomically
// truncates the op log through throughSeq. prevVersion is the snapshot blob
// version this client last saw (0 if none) — a mismatch surfaces via
// IsConflict, meaning another device compacted first; just skip and resync.
// Returns the new snapshot version.
func (c *Client) CompactOps(ctx context.Context, resource string, snapshot []byte, throughSeq, prevVersion int64) (int64, error) {
	body := map[string]any{
		"snapshot_b64": base64.StdEncoding.EncodeToString(snapshot),
		"through_seq":  throughSeq,
		"prev_version": prevVersion,
	}
	var out struct {
		Version int64 `json:"version"`
	}
	err := c.doJSON(ctx, "POST", "/v1/ops/"+url.PathEscape(resource)+"/compact", body, &out, true)
	if err != nil {
		return 0, err
	}
	return out.Version, nil
}

// ServerSyncState is the tiny idle-check summary: per-blob versions and
// per-resource op-log high-water marks in one round trip. No content, no
// crypto — this is what auto-sync polls instead of downloading blobs.
type ServerSyncState struct {
	Blobs []ServerBlobMeta `json:"blobs"`
	Ops   []ServerOpsMeta  `json:"ops"`
}

type ServerBlobMeta struct {
	Name       string `json:"name"`
	Version    int64  `json:"version"`
	ThroughSeq int64  `json:"through_seq"`
}

type ServerOpsMeta struct {
	Resource string `json:"resource"`
	MaxSeq   int64  `json:"max_seq"`
}

// Blob returns the metadata for the named blob (zero value if absent).
func (s ServerSyncState) Blob(name string) ServerBlobMeta {
	for _, b := range s.Blobs {
		if b.Name == name {
			return b
		}
	}
	return ServerBlobMeta{}
}

// MaxSeq returns the op-log high-water mark for resource (0 if no ops).
func (s ServerSyncState) MaxSeq(resource string) int64 {
	for _, o := range s.Ops {
		if o.Resource == resource {
			return o.MaxSeq
		}
	}
	return 0
}

// FetchSyncState retrieves the account's sync state summary.
func (c *Client) FetchSyncState(ctx context.Context) (ServerSyncState, error) {
	var out ServerSyncState
	if err := c.doJSON(ctx, "GET", "/v1/sync/state", nil, &out, true); err != nil {
		return ServerSyncState{}, err
	}
	return out, nil
}
