package groups

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/instacryptio/icfx/config"
)

// storeVersion is the on-disk schema version for groups.json.
const storeVersion = 1

// Store manages contact-group persistence as a plaintext JSON file (mode 0600).
// A per-Store mutex serializes the load-modify-save mutators so a background
// cloud sync and a UI action can't race and lose one another's writes; save
// itself is atomic (temp file + rename).
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore creates a group store using the default path (groups.json).
func NewStore() (*Store, error) {
	path, err := config.GroupsFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving groups file path: %w", err)
	}
	return &Store{path: path}, nil
}

// NewStoreWithPath creates a store with a custom file path.
func NewStoreWithPath(path string) *Store {
	return &Store{path: path}
}

// newID returns a random 128-bit hex identifier for a new group.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating group id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// load reads the full group data (groups + tombstones). Empty on missing file.
func (s *Store) load() (groupData, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return groupData{Version: storeVersion}, nil
	}
	if err != nil {
		return groupData{}, fmt.Errorf("reading groups file: %w", err)
	}
	var data groupData
	if err := json.Unmarshal(raw, &data); err != nil {
		return groupData{}, fmt.Errorf("parsing groups: %w", err)
	}
	return data, nil
}

// save writes the full group data to disk as plaintext JSON (mode 0600),
// atomically via a same-dir temp file + rename.
func (s *Store) save(data groupData) error {
	data.Version = storeVersion
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling groups: %w", err)
	}
	return config.WriteFileAtomic(s.path, jsonBytes)
}

// List returns the live (non-deleted) groups.
func (s *Store) List() ([]Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	return data.Groups, nil
}

// Add creates a group, returning ErrAlreadyExists if the name is taken.
func (s *Store) Add(name string, memberIDs []string) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Group{}, err
	}
	for _, g := range data.Groups {
		if g.Name == name {
			return Group{}, ErrAlreadyExists
		}
	}
	id, err := newID()
	if err != nil {
		return Group{}, err
	}
	g := Group{ID: id, Name: name, MemberIDs: memberIDs, UpdatedAt: time.Now().UTC()}
	data.Groups = append(data.Groups, g)
	data.Deleted = removeString(data.Deleted, id) // never tombstoned for a fresh id, but keep clean
	if err := s.save(data); err != nil {
		return Group{}, err
	}
	return g, nil
}

// Edit updates a group's name and members. ErrNotFound if the id is unknown.
func (s *Store) Edit(id, name string, memberIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return err
	}
	for i := range data.Groups {
		if data.Groups[i].ID != id {
			continue
		}
		data.Groups[i].Name = name
		data.Groups[i].MemberIDs = memberIDs
		data.Groups[i].UpdatedAt = time.Now().UTC()
		return s.save(data)
	}
	return ErrNotFound
}

// Remove deletes a group, recording a tombstone so the delete converges across
// devices on sync. ErrNotFound if the id is unknown.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return err
	}
	filtered := make([]Group, 0, len(data.Groups))
	found := false
	for _, g := range data.Groups {
		if g.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, g)
	}
	if !found {
		return ErrNotFound
	}
	data.Groups = filtered
	if !containsString(data.Deleted, id) {
		data.Deleted = append(data.Deleted, id)
	}
	return s.save(data)
}

// SyncBytes returns the local group view (groups + tombstones) as JSON, for the
// cloud whole-blob CRDT sync (see MergeGroups).
func (s *Store) SyncBytes() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// ApplyMerged overwrites the local store with a merged sync view.
func (s *Store) ApplyMerged(merged []byte) error {
	var data groupData
	if err := json.Unmarshal(merged, &data); err != nil {
		return fmt.Errorf("parsing merged groups: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(data)
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func removeString(s []string, v string) []string {
	// Allocate a fresh slice rather than reusing s[:0], which would mutate the
	// caller's backing array in place.
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
