package link

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

// Credentials is the durable awlk_ host credential persisted after the
// first successful /link registration — see the root README's "Once
// linked" note. Never holds the one-time awbs_ bootstrap token: that's
// only ever passed in via --token and is single-use on the server side
// anyway, so there is nothing of it worth caching.
type Credentials struct {
	RemoteHostID   string `json:"remote_host_id"`
	HostCredential string `json:"host_credential"`
}

// DefaultCredentialsPath returns ~/.aw-remote-host/credentials.json.
func DefaultCredentialsPath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "credentials.json"), nil
}

// LoadCredentials reads path, returning (nil, nil) if it doesn't exist.
func LoadCredentials(path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	return &c, nil
}

// SaveCredentials writes c to path with mode 0600, creating parent
// directories (0700) as needed.
func SaveCredentials(path string, c *Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// DeleteCredentials removes path, treating "already gone" as success.
func DeleteCredentials(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
