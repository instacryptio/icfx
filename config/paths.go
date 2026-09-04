package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ErrPathUnset is returned when a platform requires the consumer to provide a
// path via Set{Config,Data,Key}Path before any path-returning function is
// called. Currently this only applies to mobile (android/ios) where there is
// no usable home directory by default.
var ErrPathUnset = errors.New("config: path not set; call SetConfigDir/SetDataPath/SetKeyPath before use")

var (
	configDirOverride string
	dataPathOverride  string
	keyPathOverride   string
	tempDirOverride   string
)

// SetConfigDir sets the config directory override.
func SetConfigDir(p string) {
	configDirOverride = p
}

// SetTempPath sets the scratch/temp directory override. icfx writes transient
// files here (e.g. the streaming-encrypt ciphertext buffer). Sandboxed consumers
// (android/ios) MUST set this to an app-writable dir, since the OS default
// (os.TempDir()) points outside the app sandbox (e.g. /data/local/tmp).
func SetTempPath(p string) {
	tempDirOverride = p
}

// TempDir returns the resolved scratch directory: the override if set, else the
// OS default (os.TempDir()). Never errors — unlike ConfigDir/DataDir there is
// always a usable fallback on desktop.
func TempDir() string {
	if tempDirOverride != "" {
		return tempDirOverride
	}
	return os.TempDir()
}

// SetDataPath sets the data directory override.
func SetDataPath(p string) {
	dataPathOverride = p
}

// SetKeyPath sets the key directory override.
func SetKeyPath(p string) {
	keyPathOverride = p
}

// ConfigDir returns the resolved config directory (override or default).
func ConfigDir() (string, error) {
	if configDirOverride != "" {
		return configDirOverride, nil
	}
	return DefaultConfigDir()
}

// DefaultConfigDir returns the platform-specific config directory for icfx.
// On android/ios the consumer must call SetConfigDir first; otherwise this
// returns ErrPathUnset.
func DefaultConfigDir() (string, error) {
	switch runtime.GOOS {
	case "android", "ios":
		return "", fmt.Errorf("DefaultConfigDir on %s: %w", runtime.GOOS, ErrPathUnset)
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("DefaultConfigDir: APPDATA env var not set")
		}
		return filepath.Join(appdata, "icfx", "config"), nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "icfx"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", "icfx"), nil
}

// DefaultDataDir returns the platform-specific data directory for icfx.
// On android/ios the consumer must call SetDataPath first.
func DefaultDataDir() (string, error) {
	switch runtime.GOOS {
	case "android", "ios":
		return "", fmt.Errorf("DefaultDataDir on %s: %w", runtime.GOOS, ErrPathUnset)
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("DefaultDataDir: APPDATA env var not set")
		}
		return filepath.Join(appdata, "icfx", "data"), nil
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "icfx"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "icfx"), nil
}

// DefaultKeysDir returns the default keys directory (~/.icfx/lk/).
// This is intentionally separate from DataDir to prevent accidental syncing.
// On android/ios the consumer must call SetKeyPath first.
func DefaultKeysDir() (string, error) {
	switch runtime.GOOS {
	case "android", "ios":
		return "", fmt.Errorf("DefaultKeysDir on %s: %w", runtime.GOOS, ErrPathUnset)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".icfx", "lk"), nil
}

// DataDir returns the resolved data directory (override or default).
func DataDir() (string, error) {
	if dataPathOverride != "" {
		return dataPathOverride, nil
	}
	return DefaultDataDir()
}

// KeysDir returns the resolved keys directory (override or default).
func KeysDir() (string, error) {
	if keyPathOverride != "" {
		return keyPathOverride, nil
	}
	return DefaultKeysDir()
}

// ConfigFilePath returns the path to the main config file.
func ConfigFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// IdentitiesFilePath returns the path to the identities data file.
func IdentitiesFilePath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identities.json"), nil
}

// ContactsFilePath returns the path to the contacts data file.
func ContactsFilePath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "contacts.json"), nil
}

// GroupsFilePath returns the path to the contact-groups data file (sibling to
// contacts.json). A group is a name + a list of member contact IDs.
func GroupsFilePath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "groups.json"), nil
}

// IdentityMetaDir returns the directory holding per-identity meta files.
// One age-encrypted .meta file per identity lives there, each readable only
// by an unlocked instance of that identity (encrypted to its own EncPubKey).
func IdentityMetaDir() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identities"), nil
}

// EnsureDirectories creates all necessary directories.
func EnsureDirectories() error {
	for _, fn := range []func() (string, error){ConfigDir, DataDir, KeysDir} {
		dir, err := fn()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	return nil
}
