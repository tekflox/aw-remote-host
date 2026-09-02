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

	"github.com/tekflox/aw-remote-host/internal/homedir"
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
	// VPN records this host's enrolment in the tenant mesh. Nil on every host
	// that never ran the vpn module, which is the default.
	VPN *VPNState `json:"vpn,omitempty"`
}

// VPNState is what the vpn bootstrap module needs to remember between runs:
// which control plane this node answers to, what it registered as, and
// whether it was asked to offer itself as an exit gate.
//
// The pre-auth key is deliberately NOT here. It is a credential that is
// single-use by default and is consumed by `tailscale up`; storing it would
// leave a secret on disk that buys nothing, since a re-run of an already
// enrolled node needs no key at all.
//
// AdvertiseExit is the REQUEST, in the same sense as HostPower above — what
// the operator asked for. Whether the mesh honours it is a separate question
// with a separate answer (headscale has to approve the 0.0.0.0/0 route), read
// live from the node in `status` rather than frozen here.
type VPNState struct {
	LoginServer   string `json:"login_server,omitempty"`
	NodeName      string `json:"node_name,omitempty"`
	AdvertiseExit bool   `json:"advertise_exit,omitempty"`
	// EnrolledAt is RFC3339, for a status line that can say how old this is.
	EnrolledAt string `json:"enrolled_at,omitempty"`
	// ExitNode is the gate `vpn use-exit` last confirmed, and ExitNodeIP its
	// mesh address. Written only AFTER egress was confirmed through the new
	// route — an attempt that was reverted leaves nothing here, so this file
	// never claims a selection that did not survive its own confirmation.
	//
	// As with AdvertiseExit, this is a record, not a source of truth. What is
	// actually in force is read live from `tailscale debug prefs` by `status`,
	// because the case that hurts is exactly the one where the two disagree.
	ExitNode   string `json:"exit_node,omitempty"`
	ExitNodeIP string `json:"exit_node_ip,omitempty"`
	// ExitSelectedAt is RFC3339.
	ExitSelectedAt string `json:"exit_selected_at,omitempty"`
	// ExitExclusions is the prefix list that was pinned outside the tunnel
	// when the gate was selected, kept for reporting. `status` lists what the
	// kernel actually has rather than this, and compares the two.
	ExitExclusions []string `json:"exit_exclusions,omitempty"`
	// ExternalRoute is the container this host is routing out through an
	// external tunnel it terminates itself — internal/vpn/externalroute.go,
	// which is a different mechanism from the mesh gate above and can be in
	// force at the same time as one.
	//
	// Unlike ExitNode this record is not only for reporting: it is what
	// Reassert re-applies on a timer, because systemd-networkd flushes foreign
	// routing policy rules whenever it restarts and takes this rule with it.
	// So it is still written only after a confirmed apply — a record for an
	// apply that never confirmed would be re-asserted forever.
	ExternalRoute *ExternalRouteState `json:"external_route,omitempty"`
}

// ExternalRouteState is one container's egress pinned to an external tunnel.
//
// SourceIP is runtime IPAM and moves whenever the container is recreated,
// which is why ContainerID and Container are both kept: they are what a
// re-resolve can key on, and what makes a stale SourceIP detectable rather
// than silently re-applied to whatever moved into that address.
type ExternalRouteState struct {
	Container   string   `json:"container"`
	ContainerID string   `json:"container_id,omitempty"`
	SourceIP    string   `json:"source_ip"`
	Table       int      `json:"table"`
	Priority    int      `json:"priority"`
	Runtime     string   `json:"runtime,omitempty"`
	TunnelDev   string   `json:"tunnel_dev,omitempty"`
	MainGateway string   `json:"main_gateway,omitempty"`
	MainDev     string   `json:"main_dev,omitempty"`
	Exclusions  []string `json:"exclusions,omitempty"`
	// RoutedAt is RFC3339.
	RoutedAt string `json:"routed_at,omitempty"`
}

// DefaultPath returns ~/.aw-remote-host/state.json.
func DefaultPath() (string, error) {
	home, err := homedir.Dir()
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
