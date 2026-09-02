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
	"strconv"
	"strings"

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
	// LastBootstrapVersion is the aw-remote-host CLI version that last
	// completed a full (non-workspace-only) bootstrap on this host. Empty on
	// every host that has never run one, or whose only bootstrap so far ran
	// a "dev" build. See RecordBootstrapVersion / CheckDowngrade — the guard
	// this backs exists because of a real incident (2026-09-02,
	// incident:byod-postgres-lost-bind-mount-2026-09-02): an outer container
	// recreation lost this host's nested-podman container registry (fixed
	// separately, see bootstrap/lib/podman_storage.sh) AND rolled the running
	// binary back to a pre-fix August build baked into a docker image that
	// had never been rebuilt, which then silently re-ran the full manifest
	// from scratch straight onto empty named volumes.
	LastBootstrapVersion string `json:"last_bootstrap_version,omitempty"`
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

// Update applies mutate to the state ON DISK and writes it back, instead of
// saving a struct the caller has been holding.
//
// Save is whole-file and last-write-wins, which is fine for a command that
// runs and exits and wrong for the daemon, which loads State once at startup
// and can then run for days. Anything a VERB writes during that time —
// vpn.saveExitState's ExitNode, externalroute.go's ExternalRoute — is invisible
// to that in-memory copy, so the next `Save(path, st)` from the daemon silently
// erases it.
//
// That is not hypothetical: measured on the production bare metal 2026-09-02,
// an external route recorded at 17:51 was gone from state.json at 17:58,
// dropped by the daemon re-saving a struct it had loaded at 17:08. The route
// itself was still installed in the kernel, so nothing looked broken — the
// record that Reassert needs to put it back after a flush was simply not
// there any more, which is the silent-degradation shape this house keeps
// finding.
func Update(path string, mutate func(*State)) error {
	s, err := Load(path)
	if err != nil {
		return err
	}
	mutate(s)
	return Save(path, s)
}

// RecordBootstrapVersion updates the state at path with runningVersion as
// the version that just completed a full bootstrap. Blank/"dev" versions (a
// developer's own unreleased build) are never recorded — they have no
// meaningful order against a real release and would make every subsequent
// release look like a downgrade.
func RecordBootstrapVersion(path, runningVersion string) error {
	runningVersion = strings.TrimSpace(runningVersion)
	if runningVersion == "" || runningVersion == "dev" {
		return nil
	}
	return Update(path, func(s *State) { s.LastBootstrapVersion = runningVersion })
}

// CheckDowngrade returns a descriptive error if runningVersion is OLDER
// than the LastBootstrapVersion already recorded at path — unless force is
// true. This exists because a full bootstrap re-runs every module's
// install.sh from scratch, which is exactly what silently reset postgres/
// redis onto empty storage on 2026-09-02: the binary that ran that
// bootstrap was older than the fixes this host had already been running
// with for weeks, and nothing stopped it from reinitializing everything.
//
// Never blocks when there is nothing meaningful to compare: a blank or
// "dev" runningVersion, no version recorded yet at path, or either string
// failing to parse as a plain "vX.Y.Z" release tag — the only shape this
// CLI's release process produces, so an unparsable value means state.json
// predates this field or was hand-edited, not a real downgrade signal.
func CheckDowngrade(path, runningVersion string, force bool) error {
	if force {
		return nil
	}
	runningVersion = strings.TrimSpace(runningVersion)
	if runningVersion == "" || runningVersion == "dev" {
		return nil
	}
	s, err := Load(path)
	if err != nil {
		return err
	}
	if s.LastBootstrapVersion == "" {
		return nil
	}
	cmp, ok := compareVersions(runningVersion, s.LastBootstrapVersion)
	if !ok || cmp >= 0 {
		return nil
	}
	return fmt.Errorf(
		"refusing a full bootstrap: this binary is %s, but %s already completed one on this host. "+
			"A full bootstrap re-runs every module from scratch (podman/postgres/redis, and workspace where "+
			"applicable), which can silently reset postgres/redis onto empty storage even though the real data "+
			"on disk is untouched. Pass --force if running an older binary here is intentional.",
		runningVersion, s.LastBootstrapVersion,
	)
}

// compareVersions compares a and b as "vX.Y.Z"-style dotted-integer
// versions and returns -1/0/1, or ok=false if either fails to parse that
// way — callers must not treat that as a meaningful comparison in either
// direction.
func compareVersions(a, b string) (cmp int, ok bool) {
	pa, aok := parseVersion(a)
	pb, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			if va < vb {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion parses "v0.1.66" (an optional leading "v", dot-separated
// non-negative integers) into [0, 1, 66]. Returns ok=false for anything
// else, including an empty string.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		nums[i] = n
	}
	return nums, true
}
