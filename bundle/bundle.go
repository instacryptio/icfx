// Package bundle provides unified parsing and creation of lock, revocation,
// and rotation bundles. Clients call Parse() and get back a typed result —
// no detection logic needed in ic-cli or ic-app.
package bundle

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/qr"
)

// BundleType identifies the kind of bundle.
type BundleType int

const (
	BundleLock   BundleType = iota // Lock bundle (public keys)
	BundleRevoke                   // Revocation bundle
	BundleRotate                   // Combined revocation + new lock
)

// RevocationBundle contains data for revoking a key. Sig is a base64
// ML-DSA-65 signature by the key being revoked over CanonicalRevocationBytes,
// proving the revocation was authorized by that key's holder.
type RevocationBundle struct {
	ID                 string `json:"id"`
	RevokedFingerprint string `json:"revoked_fingerprint"`
	RevokedAt          string `json:"revoked_at"`
	Sig                string `json:"sig,omitempty"`
}

// RotationBundle combines a revocation with a new lock. Sig is a base64
// ML-DSA-65 continuity signature by the OLD (revoked) key over
// CanonicalRotationBytes, proving the transition to NewLock was authorized by
// the holder of the previous key. NewLock additionally carries its own
// self-signature.
type RotationBundle struct {
	Revocation RevocationBundle `json:"revocation"`
	NewLock    qr.LockBundle    `json:"new_lock"`
	Sig        string           `json:"sig,omitempty"`
}

// ParsedBundle is the result of parsing any bundle type. Sig carries the
// top-level authenticity signature (the rotation continuity sig for
// BundleRotate, the revocation sig for BundleRevoke) so verify-before-apply
// can check it; without this it would be dropped during parsing.
type ParsedBundle struct {
	Type       BundleType
	Lock       *qr.LockBundle    // non-nil for BundleLock and BundleRotate
	Revocation *RevocationBundle // non-nil for BundleRevoke and BundleRotate
	Sig        string            // continuity/revocation signature (base64)
}

// Parse auto-detects the bundle type from armor-encoded or raw JSON data and parses it.
func Parse(data []byte) (*ParsedBundle, error) {
	// Try armor-encoded data first
	if format.IsArmored(data) {
		return parseArmored(data)
	}
	// Try raw JSON
	return parseJSON(data)
}

func parseArmored(data []byte) (*ParsedBundle, error) {
	payload, label, err := format.ArmorDecode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding armor: %w", err)
	}

	switch label {
	case format.ArmorLockLabel:
		lock, err := qr.ParseLockBundle(payload)
		if err != nil {
			return nil, fmt.Errorf("parsing lock bundle: %w", err)
		}
		return &ParsedBundle{Type: BundleLock, Lock: &lock}, nil

	case format.ArmorRevokeLabel:
		var rev RevocationBundle
		if err := json.Unmarshal(payload, &rev); err != nil {
			return nil, fmt.Errorf("parsing revocation bundle: %w", err)
		}
		return &ParsedBundle{Type: BundleRevoke, Revocation: &rev, Sig: rev.Sig}, nil

	case format.ArmorRotateLabel:
		var rot RotationBundle
		if err := json.Unmarshal(payload, &rot); err != nil {
			return nil, fmt.Errorf("parsing rotation bundle: %w", err)
		}
		return &ParsedBundle{Type: BundleRotate, Lock: &rot.NewLock, Revocation: &rot.Revocation, Sig: rot.Sig}, nil

	default:
		return nil, fmt.Errorf("unknown armor label: %s", label)
	}
}

func parseJSON(data []byte) (*ParsedBundle, error) {
	// Try rotation bundle (has both "revocation" and "new_lock" keys)
	var rot RotationBundle
	if err := json.Unmarshal(data, &rot); err == nil && rot.Revocation.ID != "" && rot.NewLock.ID != "" {
		return &ParsedBundle{Type: BundleRotate, Lock: &rot.NewLock, Revocation: &rot.Revocation, Sig: rot.Sig}, nil
	}

	// Try revocation bundle (has "revoked_fingerprint")
	var rev RevocationBundle
	if err := json.Unmarshal(data, &rev); err == nil && rev.RevokedFingerprint != "" {
		return &ParsedBundle{Type: BundleRevoke, Revocation: &rev, Sig: rev.Sig}, nil
	}

	// Try lock bundle (has "enc_pub_key")
	lock, err := qr.ParseLockBundle(data)
	if err == nil && lock.EncPubKey != "" {
		return &ParsedBundle{Type: BundleLock, Lock: &lock}, nil
	}

	return nil, fmt.Errorf("unrecognized bundle format")
}

// MarshalRevocation creates an armor-encoded revocation bundle.
func MarshalRevocation(rev RevocationBundle) ([]byte, error) {
	data, err := json.MarshalIndent(rev, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling revocation: %w", err)
	}
	return format.ArmorEncode(data, format.ArmorRevokeLabel), nil
}

// MarshalRotation creates an armor-encoded rotation bundle.
func MarshalRotation(rot RotationBundle) ([]byte, error) {
	data, err := json.MarshalIndent(rot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling rotation: %w", err)
	}
	return format.ArmorEncode(data, format.ArmorRotateLabel), nil
}

// NewRevocation creates a RevocationBundle with the current timestamp.
func NewRevocation(id, fingerprint string) RevocationBundle {
	return RevocationBundle{
		ID:                 id,
		RevokedFingerprint: fingerprint,
		RevokedAt:          time.Now().Format(time.RFC3339),
	}
}
