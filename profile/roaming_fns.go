package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
)

// RoamingExportFn ships each identity in its encrypted-at-rest form, GPG-style:
// file/HW keys travel as their on-disk ciphertext verbatim (never decrypted — so
// syncing is prompt-free and the cloud can't read them); a plain-keychain key (no
// independent secret) travels as raw key material, protected only by the bundle's
// outer cloud-key wrap. Export never prompts, so it is safe to call from any
// client (CLI, app, agent) without user interaction.
// keychain is the OS-keychain store roaming reads/writes; nil selects the
// platform default. Callers with a non-default keychain (e.g. the Android
// Keystore adapter) inject theirs.
func RoamingExportFn(keysDir string, keychain keystore.Keystore) IdentityExportFn {
	ks := keychainOrDefault(keychain)
	return func(idx identity.IdentityIndex) (RoamingEntry, error) {
		switch {
		case idx.HWKey:
			enc, sign, err := readAtRestCiphertext(idx, keysDir, ks)
			if err != nil {
				return RoamingEntry{}, err
			}
			challenge, err := os.ReadFile(filepath.Join(keysDir, idx.Name+".hwchallenge"))
			if err != nil {
				return RoamingEntry{}, fmt.Errorf("reading hw challenge for %q: %w", idx.Name, err)
			}
			// The KEK convention travels with the ciphertext: the destination
			// may store it under a different backend, but decryption must use
			// the origin's passphrase convention.
			return RoamingEntry{
				Protection: ProtectionHW,
				Enc:        enc, Sign: sign, Challenge: challenge,
				HWKEK: idx.HWKEKConvention(),
			}, nil
		case idx.Backend == identity.BackendFile:
			enc, sign, err := readAtRestCiphertext(idx, keysDir, ks)
			if err != nil {
				return RoamingEntry{}, err
			}
			return RoamingEntry{Protection: ProtectionPassphrase, Enc: enc, Sign: sign}, nil
		default: // plain keychain — no portable secret, extract raw key material
			encStr, err := ks.LoadEncryptionIdentity(idx.Name)
			if err != nil {
				return RoamingEntry{}, fmt.Errorf("reading keychain enc key for %q: %w", idx.Name, err)
			}
			sign, err := ks.LoadSigningKey(idx.Name)
			if err != nil {
				return RoamingEntry{}, fmt.Errorf("reading keychain sign key for %q: %w", idx.Name, err)
			}
			return RoamingEntry{Protection: ProtectionCloud, Enc: []byte(encStr), Sign: sign}, nil
		}
	}
}

func keychainOrDefault(ks keystore.Keystore) keystore.Keystore {
	if ks != nil {
		return ks
	}
	return keystore.NewKeychainStore()
}

// readAtRestCiphertext returns an identity's on-disk ciphertext (file backend) or
// keychain-stored ciphertext (keychain backend) verbatim, without decrypting.
func readAtRestCiphertext(idx identity.IdentityIndex, keysDir string, ks keystore.Keystore) (enc, sign []byte, err error) {
	if idx.Backend != identity.BackendFile {
		// Keychain-stored ciphertext (HW-decorated): the plain keychain holds the
		// ciphertext the decorator wrote; read it back as-is.
		encStr, lerr := ks.LoadEncryptionIdentity(idx.Name)
		if lerr != nil {
			return nil, nil, fmt.Errorf("reading keychain enc ciphertext for %q: %w", idx.Name, lerr)
		}
		sign, lerr = ks.LoadSigningKey(idx.Name)
		if lerr != nil {
			return nil, nil, fmt.Errorf("reading keychain sign ciphertext for %q: %w", idx.Name, lerr)
		}
		return []byte(encStr), sign, nil
	}
	enc, err = os.ReadFile(filepath.Join(keysDir, idx.Name+".enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("reading enc key for %q: %w", idx.Name, err)
	}
	sign, err = os.ReadFile(filepath.Join(keysDir, idx.Name+".sign"))
	if err != nil {
		return nil, nil, fmt.Errorf("reading sign key for %q: %w", idx.Name, err)
	}
	return enc, sign, nil
}

// RoamingImportOptions configures RoamingImportFn. The library carries no user
// interaction; callers inject the destination backend and any passphrase prompts.
type RoamingImportOptions struct {
	// KeysDir is where file-backed key material is written.
	KeysDir string
	// DestBackend is the backend a pulled identity lands in on this device
	// (identity.BackendFile or identity.BackendKeychain).
	DestBackend string
	// PromptExisting is called to obtain the ORIGIN passphrase of a
	// passphrase-protected key that must be decrypted to move into this device's
	// keychain. Required only when DestBackend is keychain and a passphrase key
	// is imported; may be nil otherwise. It returns the passphrase as a wipeable
	// []byte; the callee takes ownership and zeroes it after use.
	PromptExisting func(name string) ([]byte, error)
	// PromptNew is called to obtain a FRESH passphrase to protect a raw key that
	// lands on a file device. Required only when DestBackend is file and a raw
	// (cloud) key is imported; may be nil otherwise. It returns the passphrase as
	// a wipeable []byte; the callee takes ownership and zeroes it after use.
	PromptNew func(name string) ([]byte, error)
	// Notify optionally receives human-readable info messages (e.g. "set a
	// passphrase to protect this key at rest"). Nil discards them.
	Notify func(msg string)
	// Keychain is the OS-keychain store keychain-destined material is written
	// to; nil selects the platform default. Callers with a non-default
	// keychain (e.g. the Android Keystore adapter) inject theirs.
	Keychain keystore.Keystore
}

// RoamingImportFn stores a pulled identity per this device's backend, returning
// the backend it landed in. Ciphertext (passphrase/hw) is written verbatim on a
// file device (no prompt); landing a passphrase key on a keychain device needs
// the origin passphrase once (opts.PromptExisting); a raw cloud entry is stored
// directly on a keychain device, or given a fresh passphrase on a file device
// (opts.PromptNew).
func RoamingImportFn(opts RoamingImportOptions) IdentityImportFn {
	ks := keychainOrDefault(opts.Keychain)
	return func(name string, entry RoamingEntry) (string, error) {
		dest := opts.DestBackend
		switch entry.Protection {
		case ProtectionHW:
			// HW-ciphertext travels as-is; the challenge always lives on disk.
			if err := storeCiphertext(dest, opts.KeysDir, name, entry.Enc, entry.Sign, ks); err != nil {
				return "", err
			}
			if err := writeKeyFile(opts.KeysDir, name+".hwchallenge", entry.Challenge); err != nil {
				return "", err
			}
			return dest, nil

		case ProtectionPassphrase:
			if dest == identity.BackendFile {
				// Write the ciphertext verbatim — no prompt. Its passphrase (the
				// origin device's) is needed only later, to *use* the key.
				if err := storeCiphertext(identity.BackendFile, opts.KeysDir, name, entry.Enc, entry.Sign, ks); err != nil {
					return "", err
				}
				return identity.BackendFile, nil
			}
			// Keychain dest: decrypt once with the origin passphrase to move the
			// raw key into the OS keychain (can't store a key without plaintext).
			encPlain, signPlain, derr := decryptWithPrompt(opts, name, entry.Enc, entry.Sign)
			if derr != nil {
				return "", derr
			}
			if err := storeRawKeychain(name, encPlain, signPlain, ks); err != nil {
				return "", err
			}
			return identity.BackendKeychain, nil

		default: // ProtectionCloud — raw key (the outer wrap was already removed)
			if dest == identity.BackendKeychain {
				if err := storeRawKeychain(name, entry.Enc, entry.Sign, ks); err != nil {
					return "", err
				}
				return identity.BackendKeychain, nil
			}
			// File dest: this device has no keychain, so set a passphrase to
			// protect the key at rest.
			if err := encryptRawToFile(opts, name, entry.Enc, entry.Sign); err != nil {
				return "", err
			}
			return identity.BackendFile, nil
		}
	}
}

// storeCiphertext writes at-rest ciphertext verbatim into the destination backend.
func storeCiphertext(dest, keysDir, name string, enc, sign []byte, ks keystore.Keystore) error {
	if dest == identity.BackendFile {
		if err := writeKeyFile(keysDir, name+".enc", enc); err != nil {
			return err
		}
		return writeKeyFile(keysDir, name+".sign", sign)
	}
	if err := ks.StoreEncryptionIdentity(name, string(enc)); err != nil {
		return err
	}
	return ks.StoreSigningKey(name, sign)
}

// storeRawKeychain stores raw (plaintext) key material into the keychain.
func storeRawKeychain(name string, enc, sign []byte, ks keystore.Keystore) error {
	if err := ks.StoreEncryptionIdentity(name, string(enc)); err != nil {
		return err
	}
	return ks.StoreSigningKey(name, sign)
}

// decryptWithPrompt obtains a key's origin passphrase via opts.PromptExisting and
// decrypts its enc/sign ciphertext (used to move a passphrase-protected key into a
// keychain).
func decryptWithPrompt(opts RoamingImportOptions, name string, enc, sign []byte) (encPlain, signPlain []byte, err error) {
	if opts.PromptExisting == nil {
		return nil, nil, fmt.Errorf("importing %q into this device's keychain needs its passphrase, but no prompt was provided", name)
	}
	pass, err := opts.PromptExisting(name)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Zero(pass)
	encPlain, err = crypto.DecryptWithPassphraseBytes(enc, pass)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting %q (wrong passphrase?): %w", name, err)
	}
	signPlain, err = crypto.DecryptWithPassphraseBytes(sign, pass)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting %q (wrong passphrase?): %w", name, err)
	}
	return encPlain, signPlain, nil
}

// encryptRawToFile obtains a fresh at-rest passphrase via opts.PromptNew and writes
// the raw key material as passphrase-encrypted files (a raw cloud key landing on a
// file device — e.g. a keychain-first user adding a server).
func encryptRawToFile(opts RoamingImportOptions, name string, enc, sign []byte) error {
	if opts.PromptNew == nil {
		return fmt.Errorf("importing %q onto this file-backed device needs a new passphrase, but no prompt was provided", name)
	}
	if opts.Notify != nil {
		opts.Notify(fmt.Sprintf("This device stores keys in a file; set a passphrase to protect %q at rest.", name))
	}
	pass, err := opts.PromptNew(name)
	if err != nil {
		return err
	}
	defer crypto.Zero(pass)
	encCt, err := crypto.EncryptWithPassphraseBytes(enc, pass)
	if err != nil {
		return err
	}
	signCt, err := crypto.EncryptWithPassphraseBytes(sign, pass)
	if err != nil {
		return err
	}
	if err := writeKeyFile(opts.KeysDir, name+".enc", encCt); err != nil {
		return err
	}
	return writeKeyFile(opts.KeysDir, name+".sign", signCt)
}

// writeKeyFile writes a key file into the keys dir with 0600, creating the dir.
func writeKeyFile(keysDir, filename string, data []byte) error {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("creating keys directory: %w", err)
	}
	return os.WriteFile(filepath.Join(keysDir, filename), data, 0600)
}
