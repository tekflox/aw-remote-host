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
		printPlanHeader(*resolved)
		fmt.Printf("[plan] would arm a dead-man's switch for %s BEFORE changing anything, reverting with `tailscale set --exit-node=` if this run does not confirm egress\n", *deadman)
		// The commands come from the platform rather than from this file, so
		// a preview cannot claim an `ip rule` on a machine that has none.
		for _, line := range resolved.Narration {
			fmt.Printf("[plan] %s\n", line)
		}
		fmt.Printf("[plan] would then fetch this host's real public IP and %s, reverting immediately if it does not\n", expectationSentence(*expectEgress))
		if !*persist {
			fmt.Printf("[plan] would install the %s boot guard, so a restart clears the selection rather than coming back up on a gate nothing re-confirmed\n", vpn.BootGuardName())
		}
		return nil
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
		fmt.Println("[plan] would remove whatever this platform pinned outside the tunnel (on Linux, every ip rule at priority 5260; on macOS there is nothing to remove)")
		fmt.Printf("[plan] would remove the %s boot guard\n", vpn.BootGuardName())
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
	if len(p.Exclusions.Exclusions) > 0 {
		fmt.Println("vpn: these prefixes stay OUTSIDE the tunnel:")
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

	live, err := vpn.ListExclusions(ctx, runner)
	if err == nil && len(live) > 0 {
		fmt.Printf("vpn: route exclusions in force (outside the tunnel): %s\n", strings.Join(live, ", "))
	}

	if prefsErr != nil || !prefs.UsesExitNode {
		// An exclusion set with no selection to justify it is precisely the
		// leftover-state shape that cost two days of silent downtime here.
		if len(live) > 0 {
			fmt.Println("vpn: NOTE — those exclusions exist but NO exit node is selected. They are inert (they only send traffic to the main routing table, which is where it would go anyway), but nothing should have left them behind: run `aw-remote-host vpn clear-exit` to tidy up.")
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
	fmt.Printf("vpn: EXIT NODE IN FORCE — this machine's default route goes through %s\n", gate.label)
	if !prefs.ExitNodeAllowLANAccess {
		fmt.Println("vpn: WARNING — exit-node-allow-lan-access is OFF, so this host's own LAN is inside the tunnel. Nothing this command installs turns that off; something else set it.")
	}
	if prefs.AcceptsDNS {
		fmt.Println("vpn: WARNING — accept-dns is ON while an exit node is in force. That rewrites this host's resolver, which is the same lockout arriving through DNS instead of routing. Nothing in this module turns it on.")
	}

	// The honest part: the interface being up proves nothing, so say what the
	// real egress address is.
	if dev, devErr := vpn.RouteDevice(ctx, runner, "1.1.1.1"); devErr == nil && dev != "" {
		fmt.Printf("vpn: default route for 1.1.1.1 leaves via %s\n", dev)
	}
	if egress, egressErr := vpn.PublicIP(ctx); egressErr == nil {
		fmt.Printf("vpn: REAL public egress IP: %s (measured via %s)\n", egress.IP, egress.Via)
	} else {
		fmt.Printf("vpn: REAL public egress IP: UNKNOWN — this host could not reach the internet at all (%v). With an exit node in force that means the gate is not forwarding.\n", egressErr)
	}
	if !vpn.BootGuardInstalled() {
		fmt.Printf("vpn: WARNING — the %s boot guard is NOT installed. An exit-node selection survives a reboot and nothing re-confirms it on the way back up, so this host can come back with its default route on a gate that has since stopped forwarding.\n", vpn.BootGuardName())
	}
	if recorded := recordedExit(st); recorded != "" && gate.name != "" && gate.name != recorded {
		fmt.Printf("vpn: NOTE — local state records exit node %q, but %q is what is actually in force.\n", recorded, gate.name)
	}
	// On darwin an empty exclusion list is the design, not a fault — this
	// module installs no routes there — so the warning would be false. The
	// same fact is still reported, as the manageability sentence use-exit
	// prints, rather than as an accusation that something went wrong.
	if len(live) == 0 && host.OS == "linux" {
		fmt.Println("vpn: WARNING — an exit node is in force and there are NO route exclusions. The control plane is inside the tunnel; if the gate stops forwarding, this host is unmanageable. Run `aw-remote-host vpn clear-exit`, or re-select the gate with `vpn use-exit`, which installs them.")
	}
	if host.OS == "darwin" {
		fmt.Println("vpn: NOTE — on macOS this module installs no route exclusions (tailscaled owns the utun and the LAN stays out natively). The control plane is inside the tunnel while a gate is in force: if it stops forwarding, run `aw-remote-host vpn clear-exit` from this keyboard, or restart — the boot guard clears the selection at login.")
	}
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
  vpn use-exit <node>   Route this machine's traffic — and every container on
                        it — out through <node>. THIS CHANGES THE DEFAULT
                        ROUTE. It pins the control plane and every attached
                        network outside the tunnel, arms a dead-man's switch
                        before touching anything, confirms the real public
                        egress IP afterwards, and reverts if it cannot.
      --expect-egress   the public IP the gate should present (exact match).
                        Without it, confirmation is that the IP changed.
      --exclude         extra comma-separated IPs/CIDRs to keep outside
      --deadman         unconfirmed selections revert after this (default 2m)
      --confirm-timeout how long to keep trying to confirm (default 45s)
      --persist-across-reboot
                        skip the boot guard, letting the selection survive a
                        reboot. Read what it prints before using it.
      --plan            print the gate, the exclusions and the confirmation
                        that would run, and change nothing

  vpn clear-exit        Undo the above: clear the selection, remove the
                        exclusions, remove the boot guard, and report the
                        egress IP that results.
`, "\n")
