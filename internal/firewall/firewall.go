// Package firewall turns the persisted firewall rules the control plane
// sends over a "firewall_apply" cmd frame (see internal/ops/ops_firewall.go)
// into real, idempotent iptables/nftables state on this host — and, when it
// can't, says exactly why instead of failing mute.
//
// The daemon that hosts this package runs WITHOUT root by design (see
// internal/lanfastpath's DefaultPort comment: "macbook-fred's `aw` user has
// no passwordless sudo"). `iptables -N`/`nft add table` need root, so on a
// typical host this WILL fail with EPERM — that is expected, not a bug. The
// contract this package exists to keep is: probe honestly, report the
// backend and privilege level, and never pretend a rule took effect when it
// didn't. A UI listing rules that were never actually applied is worse than
// the feature being absent (Card B instructions, 2026-08-24).
package firewall

import (
	"context"
	"os/exec"
	"runtime"
	"sort"

	"github.com/tekflox/aw-remote-host/internal/lanfastpath"
)

// Rule is one persisted firewall rule as the control plane sends it in a
// firewall_apply frame's "rules" array — field names match aw-backend's
// FirewallRule REST shape (Card A contract) so args["rules"] round-trips
// through json.Marshal/Unmarshal with no field-by-field mapping.
type Rule struct {
	Action     string `json:"action"`   // "allow" | "deny"
	Protocol   string `json:"protocol"` // "tcp" | "udp"
	PortFrom   int    `json:"port_from"`
	PortTo     int    `json:"port_to"`
	SourceCIDR string `json:"source_cidr"`
	Interface  string `json:"interface"`
	Priority   int    `json:"priority"`
}

// State is what Status (and, on success, Apply) reports back — the shape
// ops_firewall.go maps onto the firewall_apply/firewall_status verb
// response for aw-backend to persist into FirewallHostState.
type State struct {
	Backend          string // "nft" | "iptables" | "unsupported"
	Privileged       bool
	PrivilegedReason string // only meaningful when Privileged is false
	AppliedRevision  int
	Chain            []string // live dump of AW-FW-IN, for diagnostics
}

// Runner abstracts the iptables/nft/which shellouts so tests never touch a
// real firewall. Same shape as ops.Runner — any value satisfying that
// interface satisfies this one too, so ops.DefaultRunner (or a Handler's
// configured Runner) passes straight through with no adapter.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (output string, err error)
}

// Backend is one firewall implementation (nft, iptables, or the
// unsupported stub for non-Linux hosts). The interface is deliberately
// chain-agnostic — it is what makes a future pf/netsh backend a new file,
// not a rewrite (Card B instructions).
type Backend interface {
	// Probe runs something read-only and reports what this host can
	// actually do — never escalates privilege, never mutates state.
	Probe(ctx context.Context) (name string, privileged bool, reason string, err error)
	// Apply pushes the FULL desired state (baseline + rules, in priority
	// order) — never incremental. Two calls with the same input must leave
	// the same live rules (idempotent).
	Apply(ctx context.Context, rules []Rule, lockdown bool) error
	// Status reports the backend's current live state without changing it.
	Status(ctx context.Context) (State, error)
}

// ChainIn and ChainFWD are this host's own chains, jumped into from INPUT
// (host-terminating traffic) and DOCKER-USER/FORWARD (container-published
// ports) respectively — see aw-firewall-apply.sh's header comment for why
// both insertion points are needed: Docker/podman's NAT pulls published
// container ports out of INPUT before any INPUT-only filter ever sees them.
const (
	ChainIn  = "AW-FW-IN"
	ChainFWD = "AW-FW-FWD"
)

// lookPath is exec.LookPath, indirected so tests can pick a backend without
// depending on what iptables/nft binaries happen to exist on the machine
// running the test suite.
var lookPath = exec.LookPath

// goos is runtime.GOOS, indirected for the same reason as lookPath.
var goos = runtime.GOOS

// DetectBackend picks nft (preferred — RISK 2 in the card notes that on an
// iptables-nft host, `iptables -C` checks can misreport and the tables end
// up mixed) if the binary exists, else iptables, else the unsupported stub.
// v1 is Linux-only on purpose (Card B PO refinement, 2026-08-24) — macOS and
// Windows always get unsupportedBackend, no pf/netsh guessing.
func DetectBackend(runner Runner) Backend {
	if goos != "linux" {
		return unsupportedBackend{reason: "host OS is " + goos + " — firewall management is Linux-only in v1"}
	}
	if _, err := lookPath("nft"); err == nil {
		return nftBackend{runner: runner}
	}
	if _, err := lookPath("iptables"); err == nil {
		return iptablesBackend{runner: runner}
	}
	return unsupportedBackend{reason: "neither nft nor iptables was found on this host's PATH"}
}

// chainRule is the fully-resolved, backend-agnostic shape buildRuleset
// produces — "allow"/"deny" already turned into ACCEPT/DROP, baseline and
// user rules already merged into one ordered list. Each backend's Apply
// translates this into its own argv.
type chainRule struct {
	Action     string // "ACCEPT" | "DROP"
	Protocol   string // "tcp" | "udp" | "" (protocol-less match, e.g. state/loopback)
	PortFrom   int    // 0 means "no port match"
	PortTo     int
	SourceCIDR string // "" means no source match
	Interface  string // "" means no interface match
	StateMatch string // "ESTABLISHED,RELATED" or ""
}

// rfc1918 are the private ranges lanfastpath's port is whitelisted from —
// this baseline entry exists purely so a lockdown doesn't silently kill the
// LAN fast-path lanfastpath.go just built (Card B instructions: "sem ele,
// ligar lockdown mata silenciosamente o LAN fast-path").
var rfc1918 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// buildRuleset produces the full, ordered rule list for BOTH AW-FW-IN and
// AW-FW-FWD — the same content goes into each chain because a persisted
// rule's port has no "native service" vs "container-published" tag in the
// schema (Card A's FirewallRule has no such field); applying it to both
// chains is the safe, symmetric reading of an ambiguous port number.
//
// Baseline is ALWAYS first and is not user-removable:
//  1. ESTABLISHED,RELATED accept — keeps the /link tunnel itself alive;
//     omitting this is what would make a lockdown unreachable.
//  2. loopback accept.
//  3. 22/tcp accept — so a locked-down host doesn't lose its own admin SSH.
//  4. lanfastpath.DefaultPort/tcp accept, RFC1918 sources only.
//
// After baseline: every user rule, priority ascending (ties keep arrival
// order — sort.SliceStable), action mapped straight to ACCEPT/DROP. Both
// allow and deny rules are emitted regardless of lockdown, not just the
// "expected" one for that mode — first-match-wins means a deny can still
// carve an exception out of a broader allow (or vice versa) placed later in
// priority order, and refusing to emit the "redundant-looking" half would
// silently break that carve-out pattern.
//
// Only when lockdown is true does a trailing catch-all DROP get appended —
// that is the actual default-deny switch; lockdown=false leaves the chain
// falling through to INPUT/FORWARD's own (typically ACCEPT) policy.
func buildRuleset(rules []Rule, lockdown bool) []chainRule {
	out := []chainRule{
		{StateMatch: "ESTABLISHED,RELATED", Action: "ACCEPT"},
		{Interface: "lo", Action: "ACCEPT"},
		{Protocol: "tcp", PortFrom: 22, PortTo: 22, Action: "ACCEPT"},
	}
	for _, cidr := range rfc1918 {
		out = append(out, chainRule{
			Protocol: "tcp", PortFrom: lanfastpath.DefaultPort, PortTo: lanfastpath.DefaultPort,
			SourceCIDR: cidr, Action: "ACCEPT",
		})
	}

	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority < sorted[j].Priority })

	for _, r := range sorted {
		action := "DROP"
		if r.Action == "allow" {
			action = "ACCEPT"
		}
		out = append(out, chainRule{
			Protocol: r.Protocol, PortFrom: r.PortFrom, PortTo: r.PortTo,
			SourceCIDR: r.SourceCIDR, Interface: r.Interface, Action: action,
		})
	}

	if lockdown {
		out = append(out, chainRule{Action: "DROP"})
	}
	return out
}
