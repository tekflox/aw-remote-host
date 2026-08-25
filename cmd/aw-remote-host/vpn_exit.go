package main

import (
	"context"
	"flag"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/ops"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// Phase 2 of the vpn module: `vpn use-exit <node>` and `vpn clear-exit`.
//
// The ordering in runVPNUseExit is the deliverable, not the `tailscale set`
// call in the middle of it. Read it as a sequence and every step is there to
// close one way of ending up with a machine that has no internet and no way
// to be told to stop:
//
//	measure egress BEFORE      -> or there is nothing to compare against
//	arm the dead-man's switch  -> BEFORE anything changes, so every later
//	                              failure, including this process being
//	                              killed, still ends with the route restored
//	pin the exclusions         -> control plane first, then every attached
//	                              network; refuse if the control plane cannot
//	                              even be resolved
//	move the route
//	confirm through the NEW route
//	revert on anything unconfirmed, and only THEN stand the switch down
//
// The failure this defends against is not hypothetical. On this project's own
// bare-metal, days before this was written, a leftover policy-routing rule
// sent a container's egress into a dead gateway; it had no internet for two
// days, silently, and only surfaced when a deploy failed.

const (
	// defaultDeadmanTimeout is the proven value from the manual run on
	// 2026-08-25: `setsid nohup sh -c 'sleep 120; tailscale set --exit-node='`.
	defaultDeadmanTimeout = 120 * time.Second
	// defaultConfirmTimeout is how long confirmation may take before the
	// attempt is abandoned. Comfortably inside the dead-man's window, so the
	// tool's own revert normally runs first and the switch is the backstop —
	// not the other way round, which would revert a switch mid-confirmation
	// and report a confusing failure for a gate that was about to work.
	defaultConfirmTimeout = 45 * time.Second
	// confirmPollInterval spaces the confirmation attempts. tailscale takes a
	// moment to install the route and for the first packets to find the gate;
	// a single immediate check would fail on a gate that works.
	confirmPollInterval = 5 * time.Second
)

// privilegedRunner prefixes every command with `sudo -n` when this process is
// not root. Same bargain as bootstrap/vpn/install.sh: `sudo -n` never prompts,
// so a host with neither root nor a NOPASSWD entry fails immediately and
// loudly instead of hanging on a password prompt nobody is watching.
type privilegedRunner struct {
	inner vpn.Runner
	sudo  bool
}

func (p privilegedRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !p.sudo {
		return p.inner.Run(ctx, name, args...)
	}
	return p.inner.Run(ctx, "sudo", append([]string{"-n", name}, args...)...)
}

// commandPrefix is how the same command has to be spelled inside the
// dead-man's switch's shell script and inside the boot-guard unit, where
// there is no Runner to wrap it.
func (p privilegedRunner) commandPrefix(absolutePath string) string {
	if p.sudo {
		return "sudo -n " + absolutePath
	}
	return absolutePath
}

func runVPNUseExit(args []string) error {
	fs := flag.NewFlagSet("vpn use-exit", flag.ContinueOnError)
	controlPlane := fs.String("control-plane", defaultControlPlane, "control plane base URL — its address is pinned outside the tunnel and its reachability is part of the confirmation")
	expectEgress := fs.String("expect-egress", "", "the public IP the exit gate should present. Given, confirmation is an exact match; omitted, confirmation is that the public IP CHANGED, which is the only evidence available without it")
	excludeRaw := fs.String("exclude", "", "extra comma-separated IPv4 addresses or CIDRs to keep outside the tunnel, on top of the control plane and every network this host is already attached to")
	deadman := fs.Duration("deadman", defaultDeadmanTimeout, "how long before an unconfirmed selection reverts itself")
	confirmTimeout := fs.Duration("confirm-timeout", defaultConfirmTimeout, "how long to keep trying to confirm egress before giving up and reverting")
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
	if *deadman <= *confirmTimeout {
		return fmt.Errorf("--deadman (%s) must be longer than --confirm-timeout (%s), or the switch fires while the selection is still being confirmed", *deadman, *confirmTimeout)
	}

	ctx := context.Background()
	elig := vpn.Resolve(vpn.Probe())
	reportEligibility(elig)
	if !elig.CanEnroll {
		return fmt.Errorf("this host cannot select an exit node — see the reason above")
	}
	if elig.Host.OS != "linux" {
		return fmt.Errorf("selecting an exit node changes this machine's default route, and the route exclusions that keep it manageable while that is true are implemented with `ip rule`, which is Linux-only. %s is deliberately not claimed rather than half-supported", elig.Host.OS)
	}
	if elig.Host.TailscalePath == "" {
		return fmt.Errorf("tailscale is not installed on this host — run `aw-remote-host vpn --login-server=...` first")
	}

	runner := privilegedRunner{inner: ops.DefaultRunner, sudo: elig.Host.UID != 0}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("`ip` is not on PATH, and the route exclusions cannot be installed without it: %w", err)
	}

	status, err := vpn.FetchStatus(ctx, ops.DefaultRunner)
	if err != nil {
		return err
	}
	if !status.Running() {
		return fmt.Errorf("this node is not up in the mesh (BackendState=%s) — there is nothing to route through", status.BackendState)
	}
	peer, err := vpn.ResolveExitPeer(status, wanted)
	if err != nil {
		return err
	}
	peerIP := firstMeshV4(peer.IPs)

	locals := vpn.LocalPrefixes()
	exclusionPlan, err := vpn.PlanExclusions(*controlPlane, locals, splitList(*excludeRaw), vpn.DefaultResolver)
	if err != nil {
		return err
	}

	fmt.Printf("vpn: exit gate %s (%s), path %s\n", peer.Name, peerIP, peer.PathDescription())
	fmt.Println("vpn: these prefixes stay OUTSIDE the tunnel:")
	for _, e := range exclusionPlan.Exclusions {
		fmt.Printf("vpn:   %-20s %s\n", e.Prefix, e.Reason)
	}

	if *plan {
		fmt.Printf("[plan] would arm a dead-man's switch for %s BEFORE changing anything, reverting with `tailscale set --exit-node=` if this run does not confirm egress\n", *deadman)
		fmt.Printf("[plan] would run: ip rule add to <each prefix above> lookup main priority 5260\n")
		fmt.Printf("[plan] would run: tailscale set --exit-node=%s --exit-node-allow-lan-access=true --accept-dns=false\n", peerIP)
		fmt.Printf("[plan] would then fetch this host's real public IP and %s, reverting immediately if it does not\n", expectationSentence(*expectEgress))
		if !*persist {
			fmt.Printf("[plan] would install the %s boot guard, so a reboot clears the selection rather than coming back up with the route moved and no exclusions\n", vpn.BootGuardUnit)
		}
		return nil
	}

	// Baseline. Without it there is nothing to compare against, so a switch
	// could not be confirmed at all — unless the caller stated what the gate
	// should present, in which case the "after" measurement stands alone.
	baseline := ""
	if egress, err := vpn.PublicIP(ctx); err == nil {
		baseline = egress.IP
		fmt.Printf("vpn: egress before the switch: %s (via %s)\n", egress.IP, egress.Via)
	} else if *expectEgress == "" {
		return fmt.Errorf("could not measure this host's public IP before the switch, and no --expect-egress was given, so the switch could not be confirmed either way: %w", err)
	} else {
		fmt.Printf("vpn: WARNING — could not measure egress before the switch (%v); confirmation will rest entirely on --expect-egress %s\n", err, *expectEgress)
	}

	// ARM FIRST. Everything below this line can fail, hang, or be killed, and
	// the route still comes back.
	armed, err := vpn.Arm(vpn.ArmSpec{
		After:         *deadman,
		ExitNode:      peer.Name,
		TailscalePath: runner.commandPrefix(elig.Host.TailscalePath),
		IPPath:        runner.commandPrefix(ipPath),
	})
	if err != nil {
		return fmt.Errorf("refusing to touch the default route because the dead-man's switch could not be armed: %w", err)
	}
	fmt.Printf("vpn: dead-man's switch ARMED (pid %d) — this selection reverts itself at %s unless this run confirms it\n", armed.PID, armed.ExpiresAt)

	if err := vpn.ApplyExclusions(ctx, runner, exclusionPlan.Exclusions); err != nil {
		revertAfterFailure(ctx, runner, "the route exclusions could not be installed")
		return err
	}
	if err := vpn.SetExitNode(ctx, runner, peerIP); err != nil {
		revertAfterFailure(ctx, runner, "the exit node could not be selected")
		return err
	}
	fmt.Printf("vpn: default route now points at %s — confirming egress (up to %s)...\n", peer.Name, *confirmTimeout)

	result := confirmWithRetries(ctx, runner, baseline, *expectEgress, *controlPlane, *confirmTimeout)
	fmt.Println(indent(result.Describe()))

	if !result.OK {
		fmt.Println("vpn: REVERTING — an exit node that cannot be confirmed is the failure this command exists to prevent, not a partial success.")
		if err := revert(ctx, runner); err != nil {
			fmt.Printf("vpn: the revert itself FAILED (%v). The dead-man's switch is still armed and fires at %s; leaving it armed on purpose.\n", err, armed.ExpiresAt)
			return fmt.Errorf("exit node %s could not be confirmed and the revert failed: %s", peer.Name, result.Reason)
		}
		if _, err := vpn.Disarm(); err != nil {
			fmt.Printf("vpn: NOTE — the route was reverted but the dead-man's switch could not be stood down (%v). It will fire harmlessly.\n", err)
		}
		return fmt.Errorf("exit node %s was NOT confirmed and has been reverted: %s", peer.Name, result.Reason)
	}

	// Confirmed. Only now is it safe to stand the switch down.
	if _, err := vpn.Disarm(); err != nil {
		// Do not treat this as success-with-a-note: a switch that cannot be
		// stood down WILL revert a working selection, and the operator needs
		// to know that before they walk away.
		return fmt.Errorf("egress was confirmed, but the dead-man's switch could not be stood down (%w) — it will revert this selection at %s", err, armed.ExpiresAt)
	}
	fmt.Println("vpn: egress confirmed through the new route; dead-man's switch stood down.")

	if *persist {
		fmt.Printf("vpn: WARNING — --persist-across-reboot: the %s boot guard was NOT installed. A tailscale exit-node selection survives a reboot but `ip rule` exclusions do NOT, so if this machine reboots it comes back with its default route on the mesh and NOTHING keeping %s outside it.\n",
			vpn.BootGuardUnit, exclusionPlan.ControlPlaneHost)
		if err := vpn.RemoveBootGuard(ctx, runner); err != nil {
			fmt.Printf("vpn: NOTE — could not remove a previously installed boot guard: %v\n", err)
		}
	} else if err := vpn.InstallBootGuard(ctx, runner, elig.Host.TailscalePath, ipPath); err != nil {
		fmt.Printf("vpn: NOTE — the selection is live but the boot guard could not be installed (%v). A reboot would come back with the route moved and no exclusions; run `aw-remote-host vpn clear-exit` before rebooting this host.\n", err)
	} else {
		fmt.Printf("vpn: boot guard %s installed — a reboot clears this selection, which is deliberate: the exclusions do not survive a reboot, so the selection must not either.\n", vpn.BootGuardUnit)
	}

	return saveExitState(peer.Name, peerIP, exclusionPlan)
}

func runVPNClearExit(args []string) error {
	fs := flag.NewFlagSet("vpn clear-exit", flag.ContinueOnError)
	plan := fs.Bool("plan", false, "print what would be undone, and change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	host := vpn.Probe()
	if host.TailscalePath == "" {
		return fmt.Errorf("tailscale is not installed on this host, so there is no exit-node selection to clear")
	}
	runner := privilegedRunner{inner: ops.DefaultRunner, sudo: host.UID != 0}

	if *plan {
		fmt.Println("[plan] would stand down any armed dead-man's switch")
		fmt.Println("[plan] would run: tailscale set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false")
		fmt.Println("[plan] would remove every ip rule at priority 5260 (the route exclusions)")
		fmt.Printf("[plan] would remove the %s boot guard\n", vpn.BootGuardUnit)
		return nil
	}

	// Stand the switch down first. Clearing the exit node is the same action
	// the switch would take, so leaving it armed would only mean a redundant
	// revert firing minutes later against whatever the operator does next.
	if stood, err := vpn.Disarm(); err != nil {
		fmt.Printf("vpn: NOTE — could not stand down the dead-man's switch: %v\n", err)
	} else if stood {
		fmt.Println("vpn: dead-man's switch stood down")
	}

	if err := revert(ctx, runner); err != nil {
		return err
	}
	if err := vpn.RemoveBootGuard(ctx, runner); err != nil {
		fmt.Printf("vpn: NOTE — could not remove the boot guard: %v\n", err)
	}

	// Say where traffic goes now, measured rather than assumed — the same
	// standard the selection is held to.
	if egress, err := vpn.PublicIP(ctx); err == nil {
		fmt.Printf("vpn: exit node cleared — egress is now %s (via %s)\n", egress.IP, egress.Via)
	} else {
		fmt.Printf("vpn: exit node cleared, but this host still cannot reach the internet: %v\n", err)
	}

	statePath, err := state.DefaultPath()
	if err != nil {
		return err
	}
	st, err := state.Load(statePath)
	if err != nil {
		return err
	}
	if st.VPN != nil {
		st.VPN.ExitNode = ""
		st.VPN.ExitNodeIP = ""
		st.VPN.ExitSelectedAt = ""
		st.VPN.ExitExclusions = nil
		if err := state.Save(statePath, st); err != nil {
			return fmt.Errorf("exit node cleared, but could not update local state: %w", err)
		}
	}
	return nil
}

// revert puts the machine back the way it was: no exit node, no exclusions.
// Order matters — clear the selection first, so that if removing the
// exclusions fails the machine is already off the tunnel rather than on it
// with half its pins gone.
func revert(ctx context.Context, r vpn.Runner) error {
	if err := vpn.SetExitNode(ctx, r, ""); err != nil {
		return fmt.Errorf("clear the exit-node selection: %w", err)
	}
	removed, err := vpn.ClearExclusions(ctx, r)
	if err != nil {
		return fmt.Errorf("remove the route exclusions: %w", err)
	}
	if removed > 0 {
		fmt.Printf("vpn: removed %d route exclusion(s)\n", removed)
	}
	return nil
}

// revertAfterFailure is the best-effort cleanup for a failure that happened
// mid-change. It never masks the original error and never leaves the operator
// thinking the machine is clean when it is not — if the cleanup fails too,
// the dead-man's switch is deliberately left armed to finish the job.
func revertAfterFailure(ctx context.Context, r vpn.Runner, what string) {
	fmt.Printf("vpn: %s — undoing what was already applied\n", what)
	if err := revert(ctx, r); err != nil {
		fmt.Printf("vpn: the cleanup failed too (%v). The dead-man's switch is still armed and will finish the job; NOT standing it down.\n", err)
		return
	}
	if _, err := vpn.Disarm(); err != nil {
		fmt.Printf("vpn: NOTE — cleanup succeeded but the dead-man's switch could not be stood down (%v). It will fire harmlessly.\n", err)
	}
}

// confirmWithRetries keeps checking until the deadline. A single immediate
// check would fail on a perfectly good gate: tailscale needs a moment to
// install the route and the first packets have to find their way through DERP
// or a direct path that may not be up yet. Retrying is not optimism — a
// failure here reverts, so a false negative costs a working feature.
func confirmWithRetries(ctx context.Context, r vpn.Runner, baseline, expected, controlPlane string, timeout time.Duration) vpn.ConfirmResult {
	deadline := time.Now().Add(timeout)
	var last vpn.ConfirmResult
	for attempt := 1; ; attempt++ {
		last = vpn.ConfirmEgress(ctx, r, baseline, expected, controlPlane)
		if last.OK || time.Now().After(deadline) {
			return last
		}
		fmt.Printf("vpn:   attempt %d not confirmed yet (%s) — retrying\n", attempt, last.Reason)
		time.Sleep(confirmPollInterval)
	}
}

func saveExitState(node, ip string, plan vpn.ExclusionPlan) error {
	statePath, err := state.DefaultPath()
	if err != nil {
		return err
	}
	st, err := state.Load(statePath)
	if err != nil {
		return err
	}
	if st.VPN == nil {
		// Enrolled by the control plane rather than by this binary — record
		// what is known rather than dropping the selection on the floor.
		st.VPN = &state.VPNState{}
	}
	st.VPN.ExitNode = node
	st.VPN.ExitNodeIP = ip
	st.VPN.ExitSelectedAt = time.Now().UTC().Format(time.RFC3339)
	st.VPN.ExitExclusions = nil
	for _, e := range plan.Exclusions {
		st.VPN.ExitExclusions = append(st.VPN.ExitExclusions, e.Prefix)
	}
	if err := state.Save(statePath, st); err != nil {
		return fmt.Errorf("exit node is live and confirmed, but could not persist vpn state: %w", err)
	}
	return nil
}

func firstMeshV4(ips []string) string {
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			return ip
		}
	}
	return ""
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

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		fmt.Fprintf(&b, "vpn:   %s\n", line)
	}
	return strings.TrimRight(b.String(), "\n")
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
	runner := privilegedRunner{inner: ops.DefaultRunner, sudo: host.UID != 0}

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
		fmt.Printf("vpn: WARNING — the %s boot guard is NOT installed. An exit-node selection survives a reboot; the ip-rule exclusions above do not. This host would come back up with its default route on the mesh and nothing keeping the control plane outside it.\n", vpn.BootGuardUnit)
	}
	if recorded := recordedExit(st); recorded != "" && gate.name != "" && gate.name != recorded {
		fmt.Printf("vpn: NOTE — local state records exit node %q, but %q is what is actually in force.\n", recorded, gate.name)
	}
	if len(live) == 0 {
		fmt.Println("vpn: WARNING — an exit node is in force and there are NO route exclusions. The control plane is inside the tunnel; if the gate stops forwarding, this host is unmanageable. Run `aw-remote-host vpn clear-exit`, or re-select the gate with `vpn use-exit`, which installs them.")
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
			return exitGate{name: p.Name, label: fmt.Sprintf("%s (%s)", p.Name, firstMeshV4(p.IPs))}
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
