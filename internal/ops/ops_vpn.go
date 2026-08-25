// VPN verb — see internal/vpn for the tailscale reading itself, and
// aw-backend's GET /api/workspaces/{slug}/mesh-status for the control-plane
// side that aggregates one of these per host into the Networking screen.
//
// Deliberately NOT in workspaceLifecycleVerbs (ops.go): those verbs need
// podman, which a lean-linked host never has. Reading mesh membership needs
// tailscale and nothing else, and a lean-linked host — a laptop, a Windows
// box — is exactly the kind of machine most likely to be ON the mesh.
package ops

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// tailscaleSearchPath is where a tailscale binary lives when it is not on the
// daemon's own PATH. macOS is the case that forced this to exist: Homebrew
// installs to /opt/homebrew/bin, which a launchd-started process does not
// inherit, so a bare LookPath on Mac.Home answers "not installed" about a
// machine that is demonstrably on the mesh.
var tailscaleSearchPath = []string{
	"/usr/bin/tailscale",
	"/usr/local/bin/tailscale",
	"/opt/homebrew/bin/tailscale",
	"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
}

// lookupTailscale resolves the tailscale binary, or "" when this host has
// none. A var so a test can pin the answer instead of depending on whatever
// happens to be installed on the machine running `go test`.
var lookupTailscale = func() string {
	if path, err := exec.LookPath("tailscale"); err == nil {
		return path
	}
	for _, candidate := range tailscaleSearchPath {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// tailscaleRunner rewrites the bare "tailscale" internal/vpn shells out to
// into the absolute path lookupTailscale found, so the vpn package keeps its
// simple Runner contract and the PATH problem is solved in exactly one place.
type tailscaleRunner struct {
	inner Runner
	bin   string
}

func (t tailscaleRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "tailscale" && t.bin != "" {
		name = t.bin
	}
	return t.inner.Run(ctx, name, args...)
}

// VPNStatus reports this host's mesh membership — what the Networking screen
// renders. Read-only: it runs `tailscale status`, `tailscale debug prefs` and
// one `tailscale ping` per online peer, and changes nothing.
//
// "Not installed" and "installed but not up" are both SUCCESSFUL answers here,
// carrying a written `reason`, not errors. Most hosts in an account are not on
// the mesh, and returning an error for the normal case would leave the control
// plane unable to tell "this host says it is off the mesh" from "this host
// could not be asked" — which is the exact distinction the screen exists to
// keep. A host that reports nothing must render as unknown, never as down.
//
// Response keys are snake_case like every other verb's; the control plane
// maps them onto the UI's shape rather than this host guessing at it.
func (h *Handler) VPNStatus(ctx context.Context) (map[string]any, error) {
	bin := lookupTailscale()
	if bin == "" {
		return map[string]any{
			"installed": false,
			"running":   false,
			"reason":    "the tailscale CLI is not installed on this host",
		}, nil
	}
	runner := tailscaleRunner{inner: h.runner(), bin: bin}

	status, err := vpn.FetchStatus(ctx, runner)
	if err != nil {
		return map[string]any{
			"installed": true,
			"running":   false,
			"reason":    "could not read tailscale status: " + err.Error(),
		}, nil
	}

	out := map[string]any{
		"installed":     true,
		"running":       status.Running(),
		"backend_state": status.BackendState,
		"version":       status.Version,
		"node_name":     status.NodeName,
		"dns_name":      status.DNSName,
		"tailnet":       status.Tailnet,
		"mesh_ip":       primaryMeshIP(status.MeshIPs),
		"mesh_ips":      status.MeshIPs,
		"online":        status.Online,
		"offers_exit":   status.OffersExit,
	}
	if !status.Running() {
		out["reason"] = "tailscale is installed but the node is not up (BackendState=" + status.BackendState + ")"
	}

	// Prefs are what this node was ASKED to do, and carry the one setting on
	// it that can cut it off from everything: the exit gate in force. A read
	// failure is reported rather than swallowed — "we could not read it" must
	// not render identically to "there isn't one".
	prefs, prefsErr := vpn.FetchPrefs(ctx, runner)
	if prefsErr == nil {
		out["login_server"] = prefs.LoginServer
		out["advertises_exit"] = prefs.AdvertisesExit
		out["accepts_routes"] = prefs.AcceptsRoutes
		out["accepts_dns"] = prefs.AcceptsDNS
		out["exit_node"] = exitNodeName(prefs, status.Peers)
		out["exit_node_ip"] = prefs.ExitNodeIP
	} else {
		out["prefs_error"] = prefsErr.Error()
	}

	// Only worth measuring while the node is up — pinging peers from a
	// stopped tailscaled buys one timeout per peer and no information.
	if status.Running() {
		vpn.MeasurePaths(ctx, runner, status.Peers)
	}
	out["peers"] = peerPayload(status.Peers)
	return out, nil
}

// exitNodeName resolves the exit gate IN FORCE to something a human reads.
// Measured 2026-08-25: `tailscale debug prefs` records a selection as
// ExitNodeID and quite often leaves ExitNodeIP empty, so the id is matched
// against the peer list first. When no peer carries either, the raw id or ip
// is returned rather than a blank — "the gate this node routes through is
// gone" is a real state, and worth saying.
func exitNodeName(prefs vpn.Prefs, peers []vpn.Peer) string {
	if !prefs.UsesExitNode {
		return ""
	}
	for _, peer := range peers {
		if prefs.ExitNodeID != "" && peer.ID == prefs.ExitNodeID {
			return peer.Name
		}
		if prefs.ExitNodeIP == "" {
			continue
		}
		for _, ip := range peer.IPs {
			if ip == prefs.ExitNodeIP {
				return peer.Name
			}
		}
	}
	if prefs.ExitNodeIP != "" {
		return prefs.ExitNodeIP
	}
	return prefs.ExitNodeID
}

func peerPayload(peers []vpn.Peer) []map[string]any {
	out := make([]map[string]any, 0, len(peers))
	for _, peer := range peers {
		out = append(out, map[string]any{
			"id":          peer.ID,
			"name":        peer.Name,
			"dns_name":    peer.DNSName,
			"mesh_ip":     primaryMeshIP(peer.IPs),
			"mesh_ips":    peer.IPs,
			"os":          peer.OS,
			"online":      peer.Online,
			"active":      peer.Active,
			"offers_exit": peer.OffersExit,
			"path":        string(peer.Path),
			"via":         peer.Via(),
			"latency":     peer.Latency,
			"measured":    peer.Measured,
		})
	}
	return out
}

// primaryMeshIP picks the IPv4 address. Tailscale hands every node both a
// 100.64/10 v4 and an fd7a::/48 v6; the v4 is the one people recognise and
// paste, and the screen has room for one address, not two.
func primaryMeshIP(ips []string) string {
	for _, ip := range ips {
		if strings.Contains(ip, ".") {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}
