package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds application-level settings
type Config struct {
	ConfPath        string `toml:"conf_path"`
	DataPath        string `toml:"data_path"`
	KeyPath         string `toml:"key_path"`
	DefaultIdentity string `toml:"default_identity"`
	DefaultFormat   string `toml:"default_format"` // "icfx" or "age"
	Keystore        string `toml:"keystore"`       // "keychain" or "file"
	Verbose         bool   `toml:"verbose"`
	Banner          bool   `toml:"banner"`
	// AutoLockMinutes is the idle timeout (in minutes) after which ic-app
	// clears its in-memory session passphrase enclave and forces re-unlock.
	// 0 disables auto-lock entirely. Default 15. Only consulted by ic-app;
	// ic-cli is request-scoped and has no session to lock.
	AutoLockMinutes int `toml:"auto_lock_minutes"`

	// Cloud settings. These are non-secret configuration only — the cloud
	// session tokens live in the OS keychain / a 0600 creds file, never here.
	// The per-resource sync flags default false: nothing syncs until the user
	// opts in during cloud signup/setup.
	CloudEnabled        bool `toml:"cloud_enabled"`
	CloudSyncContacts   bool `toml:"cloud_sync_contacts"`
	CloudSyncSettings   bool `toml:"cloud_sync_settings"`
	CloudSyncIdentities bool `toml:"cloud_sync_identities"`
	// CloudSyncChoicePending marks that a sign-out happened and the next login
	// must re-confirm the sync-tier choice before anything auto-syncs (ic-app
	// gates its sync on this). Defaults false so already-configured devices keep
	// syncing across an upgrade; a sign-out sets it true, SetSyncTiers clears it.
	CloudSyncChoicePending bool   `toml:"cloud_sync_choice_pending"`
	CloudBaseURL           string `toml:"cloud_base_url"`
	// CloudAutoSyncMinutes is the ic-app background sync interval (0 = off).
	// The GUI also syncs instantly on server change events while this is on;
	// ic-cli stays manual and ignores it.
	CloudAutoSyncMinutes int `toml:"cloud_auto_sync_minutes"`

	// BackupNudgeDismissed suppresses the create-time "back up your keys" prompt
	// once the user has chosen "don't ask again".
	BackupNudgeDismissed bool `toml:"backup_nudge_dismissed"`

	// WelcomeCompleted records that ic-app's first-launch welcome wizard has
	// been finished or skipped, so it never re-shows. Set once (also auto-set
	// for existing users who already have identities). Only consulted by
	// ic-app; ic-cli has no welcome wizard.
	WelcomeCompleted bool `toml:"welcome_completed"`
}

// DefaultCloudBaseURL is where the cloud client points when unset.
// Local development overrides it via the cloud_base_url config key.
const DefaultCloudBaseURL = "https://cloud.instacrypt.io"

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		DefaultIdentity: "",
		DefaultFormat:   "icfx",
		Keystore:        "keychain",
		Verbose:         false,
		Banner:          true,
		AutoLockMinutes: 15,
		// Deliberately EMPTY: empty means "use the compiled-in
		// DefaultCloudBaseURL". Baking the default into the config file would
		// freeze it at creation time — configs written before a default-URL
		// change would silently keep pointing at the old server forever.
		CloudBaseURL: "",
		// Background sync defaults ON at a gentle cadence; the master cloud
		// switch still gates everything (nothing runs while cloud is off).
		CloudAutoSyncMinutes: 10,
	}
}

// Load reads config from the default path, following conf_path redirect if set.
func Load() (*Config, error) {
	path, err := ConfigFilePath()
	if err != nil {
		return nil, fmt.Errorf("resolving config file path: %w", err)
	}
	cfg, err := LoadFrom(path)
	if err != nil {
		return nil, err
	}

	// Follow conf_path redirect
	if cfg.ConfPath == "" {
		return cfg, nil
	}

	expanded := ExpandPath(cfg.ConfPath)
	redirected, err := LoadFrom(expanded)
	if err != nil {
		return nil, fmt.Errorf("loading redirected config from %s: %w", expanded, err)
	}
	// Preserve the conf_path so Save knows where to write
	redirected.ConfPath = cfg.ConfPath
	return redirected, nil
}

// LoadFrom reads config from a specific path. Used by Load (which then
// resolves the conf_path redirect) and by profile import (which parses
// the bundled config without going through the redirect machinery).
func LoadFrom(path string) (*Config, error) {
	cfg := DefaultConfig()

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := toml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config. If conf_path is set, the full config goes to the
// redirect target and a minimal pointer stays at the default location.
func (c *Config) Save() error {
	if err := EnsureDirectories(); err != nil {
		return err
	}

	defaultPath, err := ConfigFilePath()
	if err != nil {
		return fmt.Errorf("resolving config file path: %w", err)
	}

	if c.ConfPath == "" {
		return c.saveTo(defaultPath)
	}

	// Write full config (without conf_path) to the redirect target
	expanded := ExpandPath(c.ConfPath)
	if err := os.MkdirAll(filepath.Dir(expanded), 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	full := *c
	full.ConfPath = ""
	if err := full.saveTo(expanded); err != nil {
		return err
	}

	// Write minimal redirect at default location
	redirect := &Config{ConfPath: c.ConfPath}
	return redirect.saveTo(defaultPath)
}

// saveTo writes the config to a specific path atomically (temp file + rename).
func (c *Config) saveTo(path string) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return WriteFileAtomic(path, buf.Bytes())
}

// Set updates a config key by name
func (c *Config) Set(key, value string) error {
	switch key {
	case "conf_path":
		if value != "" {
			expanded, err := validatePath(value)
			if err != nil {
				return fmt.Errorf("invalid conf_path: %w", err)
			}
			value = expanded
		}
		c.ConfPath = value
	case "data_path":
		if value != "" {
			expanded, err := validatePath(value)
			if err != nil {
				return fmt.Errorf("invalid data_path: %w", err)
			}
			value = expanded
		}
		c.DataPath = value
	case "key_path":
		if value != "" {
			expanded, err := validatePath(value)
			if err != nil {
				return fmt.Errorf("invalid key_path: %w", err)
			}
			value = expanded
		}
		c.KeyPath = value
	case "default_identity":
		c.DefaultIdentity = value
	case "default_format":
		c.DefaultFormat = value
	case "keystore":
		if value != "keychain" && value != "file" {
			return fmt.Errorf("keystore must be %q or %q (got %q)", "keychain", "file", value)
		}
		c.Keystore = value
	case "verbose":
		c.Verbose = value == "true"
	case "banner":
		c.Banner = value == "true"
	case "auto_lock_minutes":
		n, err := parseNonNegativeInt(value)
		if err != nil {
			return fmt.Errorf("auto_lock_minutes: %w", err)
		}
		c.AutoLockMinutes = n
	case "cloud_enabled":
		c.CloudEnabled = value == "true"
	case "cloud_sync_contacts":
		c.CloudSyncContacts = value == "true"
	case "cloud_sync_settings":
		c.CloudSyncSettings = value == "true"
	case "cloud_sync_identities":
		c.CloudSyncIdentities = value == "true"
	case "cloud_sync_choice_pending":
		c.CloudSyncChoicePending = value == "true"
	case "cloud_auto_sync_minutes":
		n, err := parseNonNegativeInt(value)
		if err != nil {
			return fmt.Errorf("cloud_auto_sync_minutes: %w", err)
		}
		c.CloudAutoSyncMinutes = n
	case "backup_nudge_dismissed":
		c.BackupNudgeDismissed = value == "true"
	case "welcome_completed":
		c.WelcomeCompleted = value == "true"
	case "cloud_base_url":
		if err := ValidateCloudBaseURL(value); err != nil {
			return err
		}
		c.CloudBaseURL = value
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

// ValidateCloudBaseURL checks a cloud server base URL. Empty is allowed (the
// default is used). Otherwise the scheme must be http or https, and plaintext
// http:// is permitted ONLY for loopback hosts (localhost / 127.0.0.0-8 / ::1)
// — sending the Argon2id auth verifier or a bearer token over cleartext to a
// remote host would hand a passive MITM the full login credential.
func ValidateCloudBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid cloud server URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing plaintext http:// to non-loopback host %q — use https:// (http is allowed only for localhost)", u.Hostname())
	default:
		return fmt.Errorf("cloud server URL must be http:// or https:// (got scheme %q)", u.Scheme)
	}
}

// isLoopbackHost reports whether host is a loopback name or address.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// parseNonNegativeInt parses a non-negative integer string. Used for
// numeric config settings entered as strings via the CLI / bridge layer.
func parseNonNegativeInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("must be non-negative: %d", n)
	}
	return n, nil
}

// ExpandPath expands ~/  prefix to the user's home directory.
func ExpandPath(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}

// validatePath checks that a path is absolute or starts with ~/, and expands it.
func validatePath(p string) (string, error) {
	if strings.HasPrefix(p, "~/") {
		return ExpandPath(p), nil
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path must be absolute or start with ~/")
	}
	return p, nil
}
