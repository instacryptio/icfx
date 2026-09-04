package contacts

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/instacryptio/icfx/config"
)

// Store manages contact persistence as a plaintext JSON file (mode 0600).
// Contacts hold only public-key metadata + identifying labels (alias,
// email, nickname) needed for message addressing; no field holds secrets.
//
// A per-Store mutex serializes the load-modify-save mutators so a background
// cloud sync and a UI action can't race and lose one of their writes; Save
// itself is atomic (temp file + rename) so a crash mid-write can't truncate
// the file. Callers that load, mutate the returned slice, then Save (e.g.
// Add/Remove which take a pre-loaded slice) still own that transaction — the
// mutex protects the persistence step, not caller-side read-modify-write.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore creates a new contact store using the default path.
func NewStore() (*Store, error) {
	path, err := config.ContactsFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving contacts file path: %w", err)
	}
	return &Store{path: path}, nil
}

// NewStoreWithPath creates a store with a custom file path.
func NewStoreWithPath(path string) *Store {
	return &Store{path: path}
}

// Load reads all contacts from disk. Empty slice if the file doesn't exist.
func (s *Store) Load() ([]Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() ([]Contact, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return []Contact{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading contacts file: %w", err)
	}
	var data contactData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parsing contacts: %w", err)
	}
	return data.Contacts, nil
}

// Save writes contacts to disk as plaintext JSON, mode 0600.
func (s *Store) Save(contacts []Contact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(contacts)
}

// saveLocked persists the contact list atomically: it writes to a temp file in
// the destination directory and renames it over the target, so a crash or full
// disk mid-write leaves the previous file intact rather than a truncated one.
func (s *Store) saveLocked(contacts []Contact) error {
	data := contactData{Version: 2, Contacts: contacts}
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling contacts: %w", err)
	}
	return config.WriteFileAtomic(s.path, jsonBytes)
}

// Add adds a contact, returning ErrAlreadyExists if the alias is taken.
func (s *Store) Add(contact Contact, existing []Contact) ([]Contact, error) {
	for _, c := range existing {
		if c.Alias == contact.Alias {
			return nil, ErrAlreadyExists
		}
	}
	updated := append(existing, contact)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveLocked(updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// SetCloudConnection updates a contact's connect-handshake state by alias.
// Loads and saves in place; returns ErrNotFound for an unknown alias.
func (s *Store) SetCloudConnection(alias, state string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Alias != alias {
			continue
		}
		list[i].CloudConnection = state
		if state == ConnectionInvited {
			list[i].InvitedAt = at
		}
		return s.saveLocked(list)
	}
	return ErrNotFound
}

// MarkConnectedByFingerprint flips the contact holding fingerprint (current
// keys) to ConnectionConnected — called when a contact_accept arrives, i.e.
// the mutual exchange handshake completed. Unknown fingerprints are a no-op
// (the accept may predate a local delete).
func (s *Store) MarkConnectedByFingerprint(fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Fingerprint != fingerprint {
			continue
		}
		if list[i].CloudConnection == ConnectionConnected {
			return nil
		}
		list[i].CloudConnection = ConnectionConnected
		return s.saveLocked(list)
	}
	return nil
}

// Remove removes a contact by alias.
func (s *Store) Remove(alias string, existing []Contact) ([]Contact, error) {
	filtered := make([]Contact, 0, len(existing))
	found := false
	for _, c := range existing {
		if c.Alias == alias {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}
	if !found {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveLocked(filtered); err != nil {
		return nil, err
	}
	return filtered, nil
}
