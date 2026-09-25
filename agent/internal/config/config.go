// Package config reads and writes the agent configuration file.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Default paths. They can be overridden with XG_CONFIG_DIR for tests.
const (
	DefaultDir = "/etc/xmartguard"
	fileName   = "agent.json"
	keyName    = "identity.key"
)

// Config is persisted at <dir>/agent.json.
type Config struct {
	ServerURL string `json:"server_url"`
	ServerID  string `json:"server_id"`
	// InsecureTLS allows self-signed portal certificates (testing only).
	InsecureTLS bool `json:"insecure_tls,omitempty"`
}

// Dir returns the configuration directory.
func Dir() string {
	if d := os.Getenv("XG_CONFIG_DIR"); d != "" {
		return d
	}
	return DefaultDir
}

// Path returns the config file path.
func Path() string { return filepath.Join(Dir(), fileName) }

// KeyPath returns the identity key path.
func KeyPath() string { return filepath.Join(Dir(), keyName) }

// Load reads the config file.
func Load() (*Config, error) {
	raw, err := os.ReadFile(Path())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.ServerURL == "" || c.ServerID == "" {
		return nil, errors.New("config: server_url and server_id are required")
	}
	return &c, nil
}

// Save writes the config atomically with mode 0600.
func (c *Config) Save() error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := Path() + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path())
}

// NormalizeURL trims whitespace and trailing slashes and validates the scheme.
func NormalizeURL(u string) (string, error) {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return "", errors.New("server URL must start with https:// or http://")
	}
	return u, nil
}
