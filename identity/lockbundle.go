package identity

import (
	"encoding/base64"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/qr"
)

// LockBundleOf returns an identity's public lock bundle — the exact fields
// lock export, QR pairing, and directory publish all ship. One constructor so
// every surface publishes the same shape.
func LockBundleOf(id Identity) qr.LockBundle {
	return qr.LockBundle{
		ID:          id.ID,
		Name:        id.Name,
		EncPubKey:   id.EncPubKey,
		SignPubKey:  id.SignPubKey,
		Fingerprint: id.Fingerprint,
		Email:       id.Email,
		Alias:       id.Alias,
		Sig:         id.LockSig,
	}
}

// SealLockSigWithKey computes the lock self-signature directly from a raw
// signing private key — used at creation and rotation where the freshly
// generated key is in hand before any Unlocked exists.
func SealLockSigWithKey(signPrivKey []byte, id Identity) (string, error) {
	sig, err := crypto.Sign(qr.CanonicalLockBytes(LockBundleOf(id)), signPrivKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
