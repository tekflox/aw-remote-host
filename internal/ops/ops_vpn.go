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
	"strings"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// lookupTailscale resolves the tailscale binary, or "" when this host has
// none. A var so a test can pin the answer instead of depending on whatever
// happens to be installed on the machine running `go test`.
//
// The search list itself moved to internal/vpn on 2026-09-01, because
// vpn.Probe needs the same answer: it now reads whether this node is ALREADY
// enrolled, and a probe that could not find Homebrew's tailscale would report
// a Mac as off a mesh it has been on for a week.
var lookupTailscale = vpn.LookupTailscale

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

// probeEligibility answers "could this host join the mesh, and if not why" —
// vpn.Resolve over a fresh vpn.Probe. A var so a test can pin a verdict rather
// than depending on whatever machine runs `go test`, which is the exact
// dependency the Host/Resolve split exists to avoid.
var probeEligibility = func() vpn.Eligibility { return vpn.Resolve(vpn.Probe()) }

// eligibilityPayload renders the verdict for the control plane.
//
// It rides on vpn_status rather than on a verb of its own because the
// Networking screen asks it in the same breath as "is this host on the mesh":
// that screen used to say root and /dev/net/tun were "not reported by any API
// yet", and the probe has answered both — with a written sentence — since
// v0.1.51.
//
// `enroll_refusal` is a complete sentence and is meant to be shown verbatim.
// A screen that renders its own generic reason next to a `false` throws away
// the only part of this that tells a human what to fix.
func eligibilityPayload(e vpn.Eligibility) map[string]any {
	return map[string]any{
		"can_enroll":         e.CanEnroll,
		"enroll_refusal":     e.EnrollRefusal,
		"can_advertise_exit": e.CanAdvertiseExit,
		"exit_refusal":       e.ExitRefusal,
		// The third answer. `can_advertise_exit: true` with a non-empty
		// warning is a host that MAY be a gate and costs something to choose
		// — the WSL2 case. A screen that rendered only the boolean would
		// offer it silently, which is how every byte of somebody's traffic
		// ends up on a public relay without them being told.
		"exit_warning": e.ExitWarning,
		// The CLIENT-side verdict, and the one the gate picker on the
		// Networking screen actually needs: "can this host be pointed at a
		// gate". can_advertise_exit answers the opposite question and a
		// screen that used it would hide every machine that can only be a
		// client, which is most of them.
		"can_select_exit":     e.CanSelectExit,
		"select_exit_refusal": e.SelectExitRefusal,
		"installer":           e.Installer,
	}
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
//
// `eligibility` is on EVERY path out of here, including the two that report no
// mesh at all — a host with no tailscale is precisely the one whose reader
// wants to know whether it could have it.
func (h *Handler) VPNStatus(ctx context.Context) (map[string]any, error) {
	eligibility := eligibilityPayload(probeEligibility())

	bin := lookupTailscale()
	if bin == "" {
		return map[string]any{
			"installed":   false,
			"running":     false,
			"reason":      "the tailscale CLI is not installed on this host",
			"eligibility": eligibility,
		}, nil
	}
	runner := tailscaleRunner{inner: h.runner(), bin: bin}

	status, err := vpn.FetchStatus(ctx, runner)
	if err != nil {
		return map[string]any{
			"installed":   true,
			"running":     false,
			"reason":      "could not read tailscale status: " + err.Error(),
			"eligibility": eligibility,
		}, nil
	}

	out := map[string]any{
		"eligibility":   eligibility,
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
