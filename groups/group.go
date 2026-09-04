// Package groups manages contact groups: a named bundle of contacts (referenced
// by their stable contact IDs) used as a shortcut to encrypt or share to several
// people at once. Stored as plaintext JSON (mode 0600) alongside contacts — a
// group holds no secrets, only a name and a list of member contact IDs.
//
// The on-disk shape doubles as the cloud-sync view: it carries a Deleted
// tombstone set so a group removed on one device propagates as a delete (and
// can't be resurrected by a stale copy) when synced. See MergeGroups.
package groups

import (
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("group not found")
	ErrAlreadyExists = errors.New("group already exists")
)

// Group is a named set of member contact IDs. UpdatedAt drives last-writer-wins
// convergence during cloud sync.
type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MemberIDs []string  `json:"member_ids"`
	UpdatedAt time.Time `json:"updated_at"`
}

// groupData is the versioned on-disk / sync wrapper. Deleted holds tombstone
// group IDs so deletions converge across devices.
type groupData struct {
	Version int      `json:"version"`
	Groups  []Group  `json:"groups"`
	Deleted []string `json:"deleted,omitempty"`
}

// FindByID returns the group with the given ID, or ErrNotFound.
func FindByID(list []Group, id string) (*Group, error) {
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, ErrNotFound
}

// FindByName returns the group with the given exact name, or ErrNotFound.
func FindByName(list []Group, name string) (*Group, error) {
	for i := range list {
		if list[i].Name == name {
			return &list[i], nil
		}
	}
	return nil, ErrNotFound
}
