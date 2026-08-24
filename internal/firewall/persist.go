package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

// persisted is the on-disk shape of ~/.aw-remote-host/firewall.json — the
// last rule set this host successfully applied, kept purely as a boot-time
// CACHE (Card B instructions: "É CACHE, não fonte da verdade — o control
// plane vence no próximo register"). aw-backend re-pushes the real state
// via a firewall_apply frame right after every "registered" reply; this
// file only covers the gap between process start and that frame landing,
// e.g. a host that reboots without network.
type persisted struct {
	Rules    []Rule `json:"rules"`
	Lockdown bool   `json:"lockdown"`
	Revision int    `json:"revision"`
}

// StatePath returns ~/.aw-remote-host/firewall.json.
func StatePath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "firewall.json"), nil
}

// statePathOverride is StatePath, indirected so tests can point SelfHeal at
// a t.TempDir() instead of this process's real home directory.
var statePathOverride = StatePath

// Load reads path, returning (nil, nil) — not an error — when this host has
// never had a firewall rule applied yet, which is the default/common case.
func Load(path string) (*persisted, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read firewall state: %w", err)
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse firewall state: %w", err)
	}
	return &p, nil
}

// Save persists the last-applied rule set with mode 0600, matching
// internal/state's convention for everything under ~/.aw-remote-host.
func Save(path string, rules []Rule, lockdown bool, revision int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(persisted{Rules: rules, Lockdown: lockdown, Revision: revision}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal firewall state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// SelfHeal reapplies the last-known-applied rule set before this process
// dials /link, so a host that reboots without network still comes back up
// firewalled instead of wide open until the control plane happens to
// reconnect (Card B instructions). A no-op, not an error, when this host
// has never had a rule applied (persisted file absent) or when the probe
// says the host isn't privileged enough to apply anything locally — the
// same honest "prove and report" contract Apply itself follows, just with
// nowhere to report to yet this early in startup, so it prints instead.
func SelfHeal(ctx context.Context, runner Runner) error {
	path, err := statePathOverride()
	if err != nil {
		return err
	}
	p, err := Load(path)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}

	backend := DetectBackend(runner)
	name, privileged, reason, err := backend.Probe(ctx)
	if err != nil {
		return fmt.Errorf("firewall self-heal: probe failed: %w", err)
	}
	if !privileged {
		fmt.Fprintf(os.Stderr, "firewall: self-heal skipped — %s backend not privileged: %s\n", name, reason)
		return nil
	}
	if err := backend.Apply(ctx, p.Rules, p.Lockdown); err != nil {
		return fmt.Errorf("firewall self-heal: apply failed: %w", err)
	}
	fmt.Printf("firewall: self-heal reapplied %d rule(s) (revision %d, lockdown=%v) via %s\n",
		len(p.Rules), p.Revision, p.Lockdown, name)
	return nil
}
