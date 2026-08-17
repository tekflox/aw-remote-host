// Package state persists small local values the bootstrap CLI needs across
// runs but that aren't part of the /link credential itself — e.g. the
// generated Postgres password (must stay stable across re-runs, or the
// existing data volume's auth breaks) and the last known workspace slug
// (so `status` can report something useful without dialing /link).
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// State is the on-disk shape of ~/.aw-remote-host/state.json.
type State struct {
	PostgresPassword string `json:"postgres_password,omitempty"`
	WorkspaceSlug    string `json:"workspace_slug,omitempty"`
	// Provisioned is true once bootstrap-workspace --with-workspace (or the
	// control-plane-driven "bootstrap" ops verb) has installed the local
	// runtime (podman, postgres, redis, aw-workspace) at least once. A lean
	// link (the default) leaves this false — `status` uses it to decide
	// whether checking those modules' health is meaningful, and a later
	// --with-workspace run sets it permanently true (never reset back to
	// false; re-provisioning doesn't "undo" a prior install).
	Provisioned bool `json:"provisioned,omitempty"`
	// HostPower is what the operator ASKED for via --host-power (grant names,
	// or the ones "all" expanded to) — not what this host can deliver.
	//
	// The request is what persists, and the probe re-runs on every bootstrap
	// and every `status`, on purpose: a machine that gains /dev/kvm later
	// (nested virt enabled, the user added to the kvm group) starts offering
	// it without anyone remembering to re-run the flag. Storing the effective
	// set instead would freeze a "no" that has since become a "yes".
	//
	// Empty on every host that never opted in, which is the default.
	HostPower []string `json:"host_power,omitempty"`
}

// DefaultPath returns ~/.aw-remote-host/state.json.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "state.json"), nil
}

// Load reads path, returning a zero-value State (not an error) if it
// doesn't exist yet.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return &s, nil
}

// Save writes s to path with mode 0600, creating parent directories
// (0700) as needed.
func Save(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
