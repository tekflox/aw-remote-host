// The external_tunnels block on vpn_status — the non-mesh WireGuard
// interfaces this host runs, read from `wg show all dump`. See card
// vpn:remote-host-reports-external-tunnels and
// docs/architecture/external-vpns-in-networking.md §3.1: a new block on the
// existing verb, not a verb of its own, because `wg show` is a local
// shellout with no network round trip — the same rule that keeps
// eligibility (this file's neighbour, ops_vpn.go) off a verb of its own and
// puts VPNPublicIP (ops_vpn_exit.go) on one, because that one dials out.
//
// Read-only: this file never starts, stops or reconfigures a tunnel. The
// write path is the separate, blocked card vpn:remote-host-dials-external-vpn.
package ops

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// lookupWG resolves the `wg` binary, or "" when this host has none. A var so
// a test can pin the answer instead of depending on whatever happens to be
// installed on the machine running `go test` — same reason lookupTailscale
// (ops_vpn.go) is a var rather than a plain function.
var lookupWG = func() string {
	path, err := exec.LookPath("wg")
	if err != nil {
		return ""
	}
	return path
}

// nowUnix is time.Now().Unix(), indirected so a test can fix "now" instead
// of asserting against a moving target.
var nowUnix = func() int64 { return time.Now().Unix() }

// meshInterfaceName is excluded from external_tunnels BY NAME, not by
// heuristic: the mesh already has its own reporting on this same verb, and a
// mesh interface shown as an "external VPN" would render the mesh as an
// upstream of itself.
const meshInterfaceName = "tailscale0"

// externalTunnelsPayload answers "what non-mesh WireGuard interfaces is this
// host running, right now". Called on every path out of VPNStatus, the same
// discipline eligibility gets, because a host with no tailscale at all is
// exactly the kind of host most likely to be running its own external
// tunnel.
//
// A host with no `wg` binary, or one where the shellout is refused (no root,
// no CAP_NET_ADMIN — internal/lanfastpath's DefaultPort comment is the
// standing reminder that aw-remote-host does not always run as root),
// reports "supported": false and NEVER pretends the tunnel is down. Most
// hosts in an account run nothing here at all; conflating "could not ask"
// with "asked, and there is nothing" would make this block lie about its
// own confidence to a screen a human reads.
func externalTunnelsPayload(ctx context.Context, r Runner, host vpn.Host) map[string]any {
	bin := lookupWG()
	if bin == "" {
		return map[string]any{
			"supported": false,
			"reason":    "the wg CLI is not installed on this host",
		}
	}

	// Same privilege bargain as every other host-side WireGuard/tailscale
	// shellout in this package (internal/vpn/usexit.go's ScopeRefusal):
	// `sudo -n` never prompts, so a host with neither root nor a NOPASSWD
	// entry fails immediately and the refusal below is reported as unknown,
	// not as a hang.
	privileged := vpn.PrivilegedRunner{Inner: r, Sudo: host.OS != "darwin" && host.UID != 0}
	out, err := privileged.Run(ctx, bin, "show", "all", "dump")
	if err != nil {
		return map[string]any{
			"supported": false,
			"reason":    "could not read wg show all dump: " + err.Error(),
		}
	}

	return map[string]any{
		"supported": true,
		"tunnels":   parseWGDump(out),
	}
}

// parseWGDump turns `wg show all dump` output into one entry per
// (interface, peer) pair. That shape fits both a client tunnel (one
// interface, one peer — the provider it dials) and a hub like aw-vpn-hub
// (one interface, many peers — see this file's test fixture, captured
// 2026-09-02 off the production bare metal). The interface line — 5 fields,
// carrying this host's own PRIVATE key — is skipped outright: a private key
// must never leave this host, and the architecture doc's field list names
// only the peer's public key.
func parseWGDump(dump string) []map[string]any {
	tunnels := []map[string]any{}
	for _, line := range strings.Split(dump, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 9 {
			continue // the interface line (5 fields), or a trailing blank line
		}
		iface := fields[0]
		if iface == meshInterfaceName {
			continue
		}
		rx, _ := strconv.ParseUint(fields[6], 10, 64)
		tx, _ := strconv.ParseUint(fields[7], 10, 64)
		tunnel := map[string]any{
			"interface":         iface,
			"peer_public_key":   fields[1],
			"endpoint":          noneAsEmpty(fields[3]),
			"allowed_ips":       splitAllowedIPs(fields[4]),
			"transfer_rx_bytes": rx,
			"transfer_tx_bytes": tx,
		}
		mergeHandshake(tunnel, fields[5])
		tunnels = append(tunnels, tunnel)
	}
	return tunnels
}

// mergeHandshake sets last_handshake_never/last_handshake_age_seconds on
// tunnel. A `latest-handshake` of 0 means no handshake has EVER happened —
// rendering that as an age computes an age since the Unix epoch.
// aw-backend's _wireguard_handshake_age (vpn_poller.py:64-66) already skips
// ts==0 for the same reason; this is the Go side of the same rule.
func mergeHandshake(tunnel map[string]any, raw string) {
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ts == 0 {
		tunnel["last_handshake_never"] = true
		tunnel["last_handshake_age_seconds"] = nil
		return
	}
	age := nowUnix() - ts
	if age < 0 {
		age = 0
	}
	tunnel["last_handshake_never"] = false
	tunnel["last_handshake_age_seconds"] = age
}

// noneAsEmpty renders wg's own "(none)" placeholder — printed for a peer
// with no known endpoint — as "", so a reader downstream checks for an empty
// string like every other absent value on this verb instead of learning a
// second convention.
func noneAsEmpty(field string) string {
	if field == "(none)" {
		return ""
	}
	return field
}

// splitAllowedIPs turns wg's comma-joined allowed-ips field ("0.0.0.0/0,::/0")
// into a list, matching the shape peerPayload (ops_vpn.go) already uses for
// mesh IPs.
func splitAllowedIPs(field string) []string {
	if field == "" || field == "(none)" {
		return []string{}
	}
	return strings.Split(field, ",")
}
