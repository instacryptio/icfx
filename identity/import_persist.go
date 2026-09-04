package identity

import "fmt"

// PersistImported writes the plaintext index entry + encrypted meta for an
// identity whose private keys have already been stored in the keystore (by
// ImportBytes). It is the single source of truth for import persistence so the
// clients can't diverge — the CLI and the app both call it after storing keys.
//
// It is idempotent on the identity Name: an existing index entry is overwritten
// in place (so completing an orphaned/partial import is safe), otherwise a new
// entry is appended. The plaintext index carries the identity's Alias so alias
// selection, backup filenames, and directory publish work for imported
// identities without unlocking.
//
// Aliases are unique per profile: if info.Alias collides with a DIFFERENT
// existing identity, the alias is dropped to "" (aliasDropped=true) rather than
// failing the import — the user can set a new alias afterward. isFirst reports
// whether this is the profile's first identity (caller sets the default).
func PersistImported(store *Store, info Identity, backend string) (isFirst, aliasDropped bool, err error) {
	entries, err := store.LoadIndex()
	if err != nil {
		return false, false, fmt.Errorf("loading identity index: %w", err)
	}
	isFirst = len(entries) == 0

	// Refuse to overwrite a DIFFERENT identity that already occupies this name.
	// Upsert-by-name is only safe for completing an orphaned import of the SAME
	// keys; if an index entry with this name already exists with a different
	// fingerprint, this would hijack it (attacker bundle named like a victim's
	// identity, or a reconcile substituting a mismatched fingerprint).
	for i := range entries {
		if entries[i].Name != info.Name {
			continue
		}
		if entries[i].Fingerprint != "" && info.Fingerprint != "" && entries[i].Fingerprint != info.Fingerprint {
			return isFirst, false, fmt.Errorf("identity %q already exists with different keys — remove it first to replace", info.Name)
		}
		break
	}

	if err := CheckAliasUnique(entries, info.Alias, info.Name); err != nil {
		info.Alias = ""
		aliasDropped = true
	}

	info.Backend = backend
	if err := store.SaveMeta(info); err != nil {
		return isFirst, aliasDropped, fmt.Errorf("saving identity meta: %w", err)
	}

	entry := IdentityIndex{
		Name:        info.Name,
		Backend:     backend,
		HWKey:       info.HWKey,
		Fingerprint: info.Fingerprint,
		Alias:       info.Alias,
	}
	replaced := false
	for i := range entries {
		if entries[i].Name == info.Name {
			entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, entry)
	}
	if err := store.SaveIndex(entries); err != nil {
		return isFirst, aliasDropped, fmt.Errorf("saving identity index: %w", err)
	}
	return isFirst, aliasDropped, nil
}
