package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/tekflox/aw-remote-host/internal/ops"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// Phase 2 of the vpn module: `vpn use-exit <node>` and `vpn clear-exit`.
//
// The SEQUENCE that makes this safe — measure, arm, pin, move, confirm,
// revert — lives in internal/vpn/usexit.go, not here, because the control
// plane can now ask for the same thing over the /link tunnel (`vpn_use_exit`,
// internal/ops/ops_vpn_exit.go) and two copies of that sequence would drift.
// What is left in this file is what a command line adds on top of it: parsing
// the flags, printing the narration, and the --plan preview.

func runVPNUseExit(args []string) error {
	fs := flag.NewFlagSet("vpn use-exit", flag.ContinueOnError)
	controlPlane := fs.String("control-plane", defaultControlPlane, "control plane base URL — its address is pinned outside the tunnel and its reachability is part of the confirmation")
	expectEgress := fs.String("expect-egress", "", "the public IP the exit gate should present. Given, confirmation is an exact match; omitted, confirmation is that the public IP CHANGED, which is the only evidence available without it")
	excludeRaw := fs.String("exclude", "", "extra comma-separated IPv4 addresses or CIDRs to keep outside the tunnel, on top of the control plane and every network this host is already attached to")
	deadman := fs.Duration("deadman", vpn.DefaultDeadmanTimeout, "how long before an unconfirmed selection reverts itself")
	confirmTimeout := fs.Duration("confirm-timeout", vpn.DefaultConfirmTimeout, "how long to keep trying to confirm egress before giving up and reverting")
	persist := fs.Bool("persist-across-reboot", false, "do NOT install the boot guard, leaving the selection to survive a reboot. Read the warning this prints before using it")
	plan := fs.Bool("plan", false, "print the gate, the exclusions and the confirmation that would run, and change nothing")

	// The node is lifted out before flag parsing rather than read back with
	// fs.Arg(0) afterwards. Go's flag package stops at the first
	// non-flag argument, so `use-exit aw-baremetal --plan` would parse zero
	// flags and silently treat --plan as a second positional — which is
	// exactly how a human types it, and on this command "the safety flag was
	// ignored" is not an acceptable way to find that out.
	wanted, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if wanted == "" && fs.NArg() == 1 {
		wanted = fs.Arg(0)
	}
	if wanted == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: aw-remote-host vpn use-exit <node> [flags] — <node> is a peer name, mesh name or mesh IP from `aw-remote-host status`")
	}

	ctx := context.Background()
	spec := vpn.UseExitSpec{
		Runner:              ops.DefaultRunner,
		ControlPlane:        *controlPlane,
		Node:                wanted,
		ExpectEgress:        *expectEgress,
		Exclude:             splitList(*excludeRaw),
		Deadman:             *deadman,
		ConfirmTimeout:      *confirmTimeout,
		PersistAcrossReboot: *persist,
	}

	// The eligibility report is the command's own courtesy — it says what this
	// machine can and cannot do BEFORE anything refuses, so a refusal below
	// reads as a consequence rather than a surprise.
	reportEligibility(vpn.Resolve(vpn.Probe()))

	if *plan {
		resolved, err := vpn.PlanUseExit(ctx, spec)
		if err != nil {
			return err
		}
		// The preview survives a refusal — it changes nothing by construction,
		// and on a host that cannot be routed container-scoped it is the only
		// place the REASON can be read next to what that host actually
		// resolves to. It leads with the refusal so it cannot be mistaken for
		// a go-ahead.
		if resolved.Refusal != "" {
			fmt.Printf("vpn: REFUSED — %s\n", resolved.Refusal)
			fmt.Println("vpn: what follows is a read-only preview; applying it on this host is not possible.")
		}
		printPlanHeader(*resolved)
		fmt.Printf("[plan] would arm a dead-man's switch for %s BEFORE changing anything, reverting with `tailscale set --exit-node=` if this run does not confirm BOTH halves\n", *deadman)
		// The commands come from the platform rather than from this file, so
		// a preview cannot claim an `ip rule` on a machine that has none.
		for _, line := range resolved.Narration {
			fmt.Printf("[plan] %s\n", line)
		}
		if resolved.ProbeNetwork != "" {
			fmt.Printf("[plan] would then measure container egress from a throwaway container on network %q (%s) and %s, AND re-measure this host's own public IP and require it to be UNCHANGED — reverting immediately if either fails\n", resolved.ProbeNetwork, resolved.ProbeNetworkReason, expectationSentence(*expectEgress))
		} else {
			fmt.Printf("[plan] container egress could not be measured: %s\n", resolved.ProbeNetworkReason)
		}
		if !*persist {
			fmt.Printf("[plan] would install the %s boot guard, so a restart clears the selection rather than coming back up on a gate nothing re-confirmed\n", vpn.BootGuardName())
		}
		return nil
	}

	// Refused here as well as inside UseExit, so the command exits on the
	// sentence alone rather than printing it once as narration and again as
	// the error. `--plan` above is deliberately still reachable, and
	// `clear-exit` is untouched: the way off a gate must never refuse.
	if refusal := vpn.ScopeRefusal(ctx, ops.DefaultRunner); refusal != "" {
		return fmt.Errorf("%s\n\nTo see what this host resolves to, without changing anything: aw-remote-host vpn use-exit %s --plan", refusal, wanted)
	}

	_, err := vpn.UseExit(ctx, spec, printProgress)
	return err
}

func runVPNClearExit(args []string) error {
	fs := flag.NewFlagSet("vpn clear-exit", flag.ContinueOnError)
	plan := fs.Bool("plan", false, "print what would be undone, and change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *plan {
		fmt.Println("[plan] would stand down any armed dead-man's switch")
		fmt.Println("[plan] would run: tailscale set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false")
		fmt.Println("[plan] would remove every ip rule this module installs — the container routes, the host bypass, the mesh-preserve rule and the exclusions (on macOS there is nothing to remove)")
		fmt.Printf("[plan] would remove the %s boot guard\n", vpn.BootGuardName())
		fmt.Println("[plan] would then measure BOTH the host's and the containers' egress, which with no gate in force should be the same address")
		return nil
	}

	_, err := vpn.ClearExit(context.Background(), vpn.ClearExitSpec{Runner: ops.DefaultRunner}, printProgress)
	return err
}

// printProgress is the CLI's rendering of vpn.Progress. Every line keeps the
// `vpn:` prefix the command has always printed, so a operator's grep and this
// project's own runbooks still match.
func printProgress(level, message string) {
	switch level {
	case "warning":
		fmt.Printf("vpn: WARNING — %s\n", message)
	case "error":
		fmt.Printf("vpn: %s\n", message)
	default:
		fmt.Printf("vpn: %s\n", message)
	}
}

func printPlanHeader(p vpn.UseExitPlan) {
	fmt.Printf("vpn: exit gate %s (%s), path %s\n", p.Gate.Name, p.GateIP, p.Gate.PathDescription())
	if p.Runtime.Present() {
		fmt.Printf("vpn: container runtime: %s (%s)\n", p.Runtime.Name, p.Runtime.Version)
	}
	if len(p.Routes.Containers) > 0 {
		fmt.Println("vpn: these CONTAINER networks would move onto the gate — and nothing else would:")
		for _, c := range p.Routes.Containers {
			fmt.Printf("vpn:   %-20s %s\n", c.Prefix, strings.Join(c.Networks, ", "))
		}
		fmt.Println("vpn: this MACHINE's own public IP would NOT change. That is asserted, not hoped for: a host whose address moved is a failed apply and reverts.")
	}
	if len(p.Exclusions.Exclusions) > 0 {
		fmt.Println("vpn: these prefixes stay OUTSIDE the tunnel, for the containers too:")
		for _, e := range p.Exclusions.Exclusions {
			fmt.Printf("vpn:   %-20s %s\n", e.Prefix, e.Reason)
		}
	}
	if p.Manageability != "" {
		fmt.Printf("vpn: WARNING — %s\n", p.Manageability)
	}
}

// reportExitStatus is the phase-2 half of `aw-remote-host status`: which gate
// is in force, what the real egress IP is, what is pinned outside the tunnel,
// and whether a revert is pending.
//
// It reads all four from the machine rather than from state.json. The case
// that hurts is exactly the one where the record and the machine disagree —
// a selection made by something else, an exclusion set that outlived the
// selection that created it, a switch that already fired.
func reportExitStatus(ctx context.Context, prefs vpn.Prefs, prefsErr error, st *state.State) {
	host := vpn.Probe()
	// No sudo wrapper on darwin: everything read below (`route -n get`,
	// `tailscale debug prefs`) works as the ordinary user there, and wrapping
	// it would turn a readable status into "sudo: a password is required".
	runner := vpn.PrivilegedRunner{Inner: ops.DefaultRunner, Sudo: host.OS != "darwin" && host.UID != 0}

	if deadman, err := vpn.LoadDeadman(); err == nil && deadman != nil {
		fmt.Printf("vpn: %s\n", deadman.Describe())
	}

	live, err := vpn.ListRouteRules(ctx, runner)
	if err == nil && len(live) > 0 {
		fmt.Printf("vpn: routing rules in force: %s\n", strings.Join(live, "; "))
	}

	if prefsErr != nil || !prefs.UsesExitNode {
		// A rule set with no selection to justify it is precisely the
		// leftover-state shape that cost two days of silent downtime here.
		if len(live) > 0 {
			fmt.Println("vpn: NOTE — those rules exist but NO exit node is selected. They are inert: the `lookup main` ones send traffic where it would go anyway, and the `lookup 52` ones find no default route in that table while nothing is selected, so the kernel falls through. Nothing should have left them behind: run `aw-remote-host vpn clear-exit` to tidy up.")
		}
		if recorded := recordedExit(st); recorded != "" && prefsErr == nil {
			fmt.Printf("vpn: NOTE — local state records exit node %q, but this node has none selected. Something cleared it — most likely the dead-man's switch or the boot guard.\n", recorded)
		}
		return
	}

	// Naming the gate takes both fields. Measured on a real selection made by
	// this very command (lab node, 2026-08-25): tailscale recorded
	// ExitNodeID="1" and left ExitNodeIP EMPTY, so an IP-only match reported
	// the gate as "1" and then wrongly accused state.json of disagreeing with
	// the machine. Matching the stable node id is what turns it back into a
	// name a human recognises.
	gate := exitNodeLabel(ctx, prefs)
	fmt.Printf("vpn: EXIT NODE IN FORCE — this host's CONTAINER networks go through %s\n", gate.label)
	if !prefs.ExitNodeAllowLANAccess {
		fmt.Println("vpn: WARNING — exit-node-allow-lan-access is OFF, so this host's own LAN is inside the tunnel. Nothing this command installs turns that off; something else set it.")
	}
	if prefs.AcceptsDNS {
		fmt.Println("vpn: WARNING — accept-dns is ON while an exit node is in force. That rewrites this host's resolver, which is the same lockout arriving through DNS instead of routing. Nothing in this module turns it on.")
	}

	// The honest part: the interface being up proves nothing, so say what the
	// real egress addresses are — BOTH, because with a gate in force the pair
	// is what answers "did it work" and "is the host still where it was". Two
	// equal addresses here mean either the gate did nothing or the host moved
	// too, and those are indistinguishable from the container's number alone.
	if dev, devErr := vpn.RouteDevice(ctx, runner, "1.1.1.1"); devErr == nil && dev != "" {
		fmt.Printf("vpn: this HOST's route for 1.1.1.1 leaves via %s (a tailscale interface here would mean the host is routed, which it must not be)\n", dev)
	}
	if egress, egressErr := vpn.PublicIP(ctx); egressErr == nil {
		fmt.Printf("vpn: HOST public egress IP: %s (measured via %s) — with a gate in force this must be the SAME address as before it\n", egress.IP, egress.Via)
	} else {
		fmt.Printf("vpn: HOST public egress IP: UNKNOWN — this host could not reach the internet at all (%v).\n", egressErr)
	}
	reportContainerEgress(ctx, runner)
	if !vpn.BootGuardInstalled() {
		fmt.Printf("vpn: WARNING — the %s boot guard is NOT installed. An exit-node selection survives a reboot and nothing re-confirms it on the way back up, so this host can come back with its default route on a gate that has since stopped forwarding.\n", vpn.BootGuardName())
	}
	if recorded := recordedExit(st); recorded != "" && gate.name != "" && gate.name != recorded {
		fmt.Printf("vpn: NOTE — local state records exit node %q, but %q is what is actually in force.\n", recorded, gate.name)
	}
	// On darwin an empty rule list is the design, not a fault — this module
	// installs no routes there — so the warning would be false. The same fact
	// is still reported, as the manageability sentence use-exit prints, rather
	// than as an accusation that something went wrong.
	if len(live) == 0 && host.OS == "linux" {
		fmt.Println("vpn: WARNING — an exit node is in force and this module's routing rules are NOT installed. That means tailscale's own `from all lookup 52` is unopposed, so this MACHINE's traffic is going through the gate and not just its containers' — the exact scope this feature was rewritten to stop. Run `aw-remote-host vpn clear-exit` now, or re-select the gate with `vpn use-exit`, which installs them.")
	}
	if host.OS == "darwin" {
		fmt.Println("vpn: NOTE — on macOS this module installs no routing rules of its own, and cannot route containers separately from the machine at all. A selection in force here is routing the WHOLE Mac. Run `aw-remote-host vpn clear-exit` from this keyboard, or restart — the boot guard clears the selection at login.")
	}
}

// reportContainerEgress is the second address `status` owes a reader on a host
// that has containers. Best-effort and never fatal: a host with no runtime
// says so, which is a real and permanent answer for a Mac or a native Windows
// link, and it never falls back to reprinting the host's own address — two
// numbers that are equal because one was copied would make an unapplied gate
// look applied.
func reportContainerEgress(ctx context.Context, runner vpn.Runner) {
	runtime, err := vpn.DetectContainerRuntime(ctx, runner)
	if err != nil {
		fmt.Printf("vpn: CONTAINER egress IP: not measurable — %v\n", err)
		return
	}
	networks, err := vpn.ContainerNetworks(ctx, runner, runtime)
	if err != nil || len(networks) == 0 {
		fmt.Printf("vpn: CONTAINER egress IP: not measurable — %s answers but defines no network with an IPv4 subnet\n", runtime.Name)
		return
	}
	probeNetwork, _ := vpn.PickProbeNetwork(runtime, networks)
	res := vpn.MeasureContainerEgress(ctx, runner, runtime, probeNetwork)
	if res.IP == "" {
		fmt.Printf("vpn: CONTAINER egress IP: UNKNOWN — %s\n", res.Error)
		return
	}
	fmt.Printf("vpn: CONTAINER egress IP: %s (measured via %s, from a throwaway container on %s network %s)\n", res.IP, res.Via, res.Runtime, res.Network)
}

// exitGate is the gate a selection points at: the peer's name when it could
// be resolved, and a label safe to print either way.
type exitGate struct {
	name  string
	label string
}

// exitNodeLabel turns whichever of ExitNodeID/ExitNodeIP tailscale filled in
// back into a peer name. When neither matches a known peer the raw value is
// printed rather than nothing — a selection pointing at a node that has since
// left the mesh is a real state, and the useful thing to say about it is that
// it is still in force.
func exitNodeLabel(ctx context.Context, prefs vpn.Prefs) exitGate {
	raw := prefs.ExitNodeIP
	if raw == "" {
		raw = prefs.ExitNodeID
	}
	status, err := vpn.FetchStatus(ctx, ops.DefaultRunner)
	if err != nil {
		return exitGate{label: raw}
	}
	for _, p := range status.Peers {
		match := prefs.ExitNodeID != "" && p.ID == prefs.ExitNodeID
		for _, ip := range p.IPs {
			if prefs.ExitNodeIP != "" && ip == prefs.ExitNodeIP {
				match = true
			}
		}
		if match {
			return exitGate{name: p.Name, label: fmt.Sprintf("%s (%s)", p.Name, vpn.FirstMeshV4(p.IPs))}
		}
	}
	return exitGate{label: raw + " — which is NOT a peer this node can currently see, so the gate may have left the mesh"}
}

func recordedExit(st *state.State) string {
	if st == nil || st.VPN == nil {
		return ""
	}
	return st.VPN.ExitNode
}

// splitLeadingArg peels a leading positional argument off argv, leaving the
// flags for flag.Parse. Only position 0 is considered, so a flag's value can
// never be mistaken for it.
func splitLeadingArg(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func expectationSentence(expect string) string {
	if expect == "" {
		return "require it to have CHANGED"
	}
	return "require it to be exactly " + expect
}

// vpnExitUsage is printed by the top-level usage; kept next to the flags it
// describes so the two cannot drift.
// Trimmed of newlines only, never TrimSpace: the leading indent on the first
// line is what lines it up with the command list it is spliced into.
var vpnExitUsage = strings.Trim(`
  vpn use-exit <node>   Route this host's CONTAINERS out through <node>. THIS
                        MACHINE'S OWN PUBLIC IP DOES NOT CHANGE — that is
                        asserted afterwards, and a host whose address moved is
                        a failed apply that reverts. The container networks
                        come from the runtime (docker/podman), keyed on each
                        network's CIDR and never on a container's address. A
                        host with no container runtime is REFUSED rather than
                        routed whole, and so is macOS, whose containers live
                        behind a VM's NAT. Arms a dead-man's switch before
                        touching anything; confirms BOTH halves after.
      --expect-egress   the public IP the gate should present to the
                        CONTAINERS (exact match). Without it, confirmation is
                        that the container address changed and the host's
                        did not.
      --exclude         extra comma-separated IPs/CIDRs to keep outside
      --deadman         unconfirmed selections revert after this (default 2m)
      --confirm-timeout how long to keep trying to confirm (default 45s)
      --persist-across-reboot
                        skip the boot guard, letting the selection survive a
                        reboot. Read what it prints before using it.
      --plan            print the gate, the container networks, the rules and
                        the confirmation that would run, and change nothing

  vpn clear-exit        Undo the above: clear the selection, remove every rule
                        this module installed, remove the boot guard, and
                        report the host's and the containers' egress, which
                        should come back to the same address.
`, "\n")
