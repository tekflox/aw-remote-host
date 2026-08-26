// Phase 2 of the vpn module as a library: selecting an exit gate, which moves
// THIS HOST'S CONTAINERS onto the mesh — and never the host itself — and
// clearing it again.
//
// THE INVARIANT, which was inverted on 2026-08-26 after the first real apply
// took a Mac off the internet:
//
//   - the CONTAINERS' public IP MUST change. That is the feature.
//   - the HOST's public IP MUST NOT change. That is a hard assertion, and a
//     host whose address moved is a FAILED APPLY that reverts, however healthy
//     the container's egress looks.
//   - the confirmation checks BOTH, because either alone is a half-measure:
//     container-changed-only hides a host that moved too, host-unchanged-only
//     proves nothing happened at all.
//
// The ordering in UseExit is the deliverable, not the `tailscale set` call in
// the middle of it. Read it as a sequence and every step is there to close one
// way of ending up with a machine that has no internet and no way to be told
// to stop:
//
//	measure BOTH egresses      -> the host's, which must hold, and the
//	                              containers', which must move. Same function
//	                              measures the "after", or the pair proves
//	                              nothing
//	arm the dead-man's switch  -> BEFORE anything changes, so every later
//	                              failure, including this process being
//	                              killed, still ends with the routes restored
//	install the rules          -> host bypass FIRST, so the machine's own
//	                              egress is claimed before tailscale's
//	                              catch-all exists; then the mesh-preserve
//	                              rule, the exclusions, and the container
//	                              networks last
//	select the gate
//	confirm BOTH halves
//	revert on anything unconfirmed, and only THEN stand the switch down
//
// With the host untouched, the dead-man's switch is no longer the only thing
// between this and a bricked machine — remote management cannot be lost by an
// apply that behaves. It is kept because an apply that MISbehaves is exactly
// what it is for, and its job is now to clean up rules rather than to rescue a
// host.
//
// The failure this defends against is not hypothetical. On this project's own
// bare-metal, days before this was written, a leftover policy-routing rule
// sent a container's egress into a dead gateway; it had no internet for two
// days, silently, and only surfaced when a deploy failed.
//
// WHY THIS IS A PACKAGE AND NOT THE `vpn use-exit` COMMAND'S OWN BODY, which
// is where it was born: there are now two ways to ask for it — a human typing
// the command, and the control plane sending `vpn_use_exit` over the /link
// tunnel — and the sequence above IS the safety mechanism. Two copies of it
// would drift, and the copy that drifted would be the one that strands a
// machine. bootstrap/lib/vpn.sh's header makes the same argument one level
// down about exit eligibility, for the same reason.
package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// ErrScopeRefused marks the refusals that are about WHAT THIS VERB IS FOR
// rather than about whether a request was well formed, so a caller can tell
// "this tool will not do this at all" apart from "this host could not".
//
// The refusal it stands for used to be unconditional. Between 2026-08-26 and
// this change, `vpn use-exit` refused every host outright, because the shape
// it had moved THIS MACHINE's default route (`ip rule ... lookup 52`, applied
// `from all`) and took a Mac off the internet on the first real apply. That
// refusal is lifted here for exactly one path — the container-scoped one, in
// which the host bypass at priority 5265 holds the machine's own egress still
// and only container networks are routed. It stands, unchanged, everywhere a
// host's route would still move: on darwin, where there is no container
// network out here to key a rule on, and on any host with no container
// runtime, where the only thing left to route would be the machine.
//
// ClearExit is deliberately NOT gated by any of this. It is the way OFF a
// gate, and an undo that refuses is one that fails exactly when it is most
// needed — including for the hosts that took a selection before this landed.
var ErrScopeRefused = errors.New("this host cannot have its containers routed without routing the host itself")

// ScopeRefusal reports why this host cannot be routed container-scoped, or ""
// when it can. Two halves, cheapest first:
//
//   - the STATIC half, from the OS alone: darwin's containers live inside a VM
//     whose traffic is already NATed by the time macOS sees it, so there is
//     nothing out here to key a rule on. No probe changes that.
//   - the LIVE half, from the machine: is there a container runtime that
//     answers, and does it define a network with an IPv4 subnet? A host with
//     none cannot host a routed container, and the honest answer is to say so
//     rather than to fall back to routing the machine.
//
// The layers above call this before they build a spec, so their caller gets
// the reason instead of a generic failure from somewhere deep in the sequence.
func ScopeRefusal(ctx context.Context, r Runner) string {
	host := Probe()
	platform, err := platformForOS(host.OS)
	if err != nil {
		return err.Error()
	}
	if refusal := platform.containerScopeRefusal(); refusal != "" {
		return refusal
	}
	// The same privilege bargain the rest of the sequence makes. A container
	// runtime routinely refuses an unprivileged caller, and reporting "no
	// runtime" for what is really "no permission" would send an operator to
	// install something they already have.
	privileged := PrivilegedRunner{Inner: r, Sudo: host.OS != "darwin" && host.UID != 0}
	runtime, err := DetectContainerRuntime(ctx, privileged)
	if err != nil {
		return err.Error()
	}
	networks, err := ContainerNetworks(ctx, privileged, runtime)
	if err != nil {
		return err.Error()
	}
	if len(networks) == 0 {
		return fmt.Sprintf("%s answers on this host but defines no network with an IPv4 subnet, so there is no container traffic to route. %s", runtime.Name, NoContainerNetworkRefusal)
	}
	return ""
}

const (
	// DefaultDeadmanTimeout is the proven value from the manual run on
	// 2026-08-25: `setsid nohup sh -c 'sleep 120; tailscale set --exit-node='`.
	DefaultDeadmanTimeout = 120 * time.Second
	// DefaultConfirmTimeout is how long confirmation may take before the
	// attempt is abandoned. Comfortably inside the dead-man's window, so the
	// tool's own revert normally runs first and the switch is the backstop —
	// not the other way round, which would revert a switch mid-confirmation
	// and report a confusing failure for a gate that was about to work.
	DefaultConfirmTimeout = 45 * time.Second
	// confirmPollInterval spaces the confirmation attempts. tailscale takes a
	// moment to install the route and for the first packets to find the gate;
	// a single immediate check would fail on a gate that works.
	confirmPollInterval = 5 * time.Second
)

// PrivilegedRunner prefixes every command with `sudo -n` when this process is
// not root. Same bargain as bootstrap/vpn/install.sh: `sudo -n` never prompts,
// so a host with neither root nor a NOPASSWD entry fails immediately and
// loudly instead of hanging on a password prompt nobody is watching.
type PrivilegedRunner struct {
	Inner Runner
	Sudo  bool
}

func (p PrivilegedRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !p.Sudo {
		return p.Inner.Run(ctx, name, args...)
	}
	return p.Inner.Run(ctx, "sudo", append([]string{"-n", name}, args...)...)
}

// CommandPrefix is how the same command has to be spelled inside the
// dead-man's switch's shell script and inside the boot-guard unit, where
// there is no Runner to wrap it.
func (p PrivilegedRunner) CommandPrefix(absolutePath string) string {
	if p.Sudo {
		return "sudo -n " + absolutePath
	}
	return absolutePath
}

// Progress carries the running commentary out to whoever asked for the switch
// — printed with a `vpn:` prefix by the CLI, forwarded as link events by the
// `vpn_use_exit` verb. level is "info", "warning" or "error".
//
// It exists so that moving this sequence out of the command did not turn its
// narration into a silent black box. On a command that changes the default
// route, "what has happened so far" is not decoration: it is what tells an
// operator watching a hung run whether the route has already moved.
type Progress func(level, message string)

func (p Progress) emit(level, format string, args ...any) {
	if p == nil {
		return
	}
	p(level, fmt.Sprintf(format, args...))
}

// UseExitSpec is one request to route this machine out through a gate.
type UseExitSpec struct {
	// Runner is the UNPRIVILEGED runner used to read state (`tailscale
	// status`). The privileged one is derived from it, so a caller cannot
	// accidentally supply one and not the other.
	Runner Runner
	// ControlPlane is pinned outside the tunnel and its reachability is part
	// of the confirmation. Never defaulted here — see PlanUseExit.
	ControlPlane string
	// Node is a peer name, mesh name or mesh IP.
	Node string
	// ExpectEgress is the public IP the gate should present. Given,
	// confirmation is an exact match; omitted, confirmation is that the
	// public IP CHANGED, which is the only evidence available without it.
	ExpectEgress string
	// Exclude is the operator's own extra list of IPv4 addresses/CIDRs to
	// keep outside the tunnel.
	Exclude []string
	// Deadman is how long before an unconfirmed selection reverts itself,
	// ConfirmTimeout how long to keep trying before giving up and reverting.
	// Zero means the default.
	Deadman        time.Duration
	ConfirmTimeout time.Duration
	// PersistAcrossReboot skips the boot guard, leaving the selection to
	// survive a reboot. The exclusions do NOT survive one, so this is the
	// dangerous option and it is opt-in.
	PersistAcrossReboot bool
}

func (s UseExitSpec) withDefaults() UseExitSpec {
	if s.Deadman <= 0 {
		s.Deadman = DefaultDeadmanTimeout
	}
	if s.ConfirmTimeout <= 0 {
		s.ConfirmTimeout = DefaultConfirmTimeout
	}
	return s
}

// UseExitPlan is everything resolved before a single thing is changed: which
// gate, what stays outside the tunnel, and what this host is allowed to do.
// Producing one is READ-ONLY, which is what makes a --plan/dry-run mode an
// honest preview rather than a second code path.
type UseExitPlan struct {
	Eligibility Eligibility
	Gate        Peer
	GateIP      string
	Exclusions  ExclusionPlan
	// Manageability is a written warning when the management path is NOT
	// pinned outside the tunnel, and "" when it is. On darwin it is always
	// set — see darwinExit.planExclusions. A caller that ignores it reports
	// the Linux guarantee on a machine that does not have it.
	Manageability string
	// Narration is what --plan should print for the commands this platform
	// would really run, so the preview cannot drift from the implementation.
	Narration []string
	// Refusal is why applying this plan is refused, and "" when it is not.
	// Carried on the plan so a preview cannot be mistaken for an actionable
	// confirmation: planning stays available even on a host that is refused,
	// because it changes nothing by construction and it is the only way to
	// read what that host really resolves to.
	Refusal string

	// Runtime, Networks and ProbeNetwork are the container half of the plan:
	// which engine answered, every network it defines with an IPv4 subnet, and
	// the one the egress probe will run on. All three are reported because a
	// gate that routes the wrong networks and a gate that routes none look
	// identical from the confirmation alone.
	Runtime      ContainerRuntime
	Networks     []ContainerNetwork
	ProbeNetwork string
	// Routes is exactly what will be installed — the container rules and the
	// exclusions together. --plan prints it, ApplyRoutes consumes it, and
	// there is no second derivation in between that could disagree.
	Routes RoutePlan

	platform exitPlatform
	runner   PrivilegedRunner
}

// PlanUseExit resolves the gate and the exclusions, and refuses anything this
// host cannot safely be asked to do — without changing anything.
//
// The refusals are ordered by how early they can be known, so a host that was
// never a candidate never gets as far as a DNS lookup.
func PlanUseExit(ctx context.Context, spec UseExitSpec) (*UseExitPlan, error) {
	spec = spec.withDefaults()
	if spec.Deadman <= spec.ConfirmTimeout {
		return nil, fmt.Errorf("the dead-man's timeout (%s) must be longer than the confirmation timeout (%s), or the switch fires while the selection is still being confirmed", spec.Deadman, spec.ConfirmTimeout)
	}
	if strings.TrimSpace(spec.ControlPlane) == "" {
		return nil, fmt.Errorf("no control plane given, and its address is not an optional exclusion: pinning the management path outside the tunnel is the one thing standing between a bad exit gate and a machine that needs a physical visit")
	}
	if spec.Runner == nil {
		return nil, fmt.Errorf("no runner given")
	}

	elig := Resolve(Probe())
	if !elig.CanSelectExit {
		return nil, fmt.Errorf("this host cannot select an exit node: %s", elig.SelectExitRefusal)
	}

	platform, err := platformFor(elig.Host)
	if err != nil {
		return nil, err
	}
	// The live half of the privilege question, and the last refusal that is
	// free: everything after this point is either a read of the mesh or a
	// change to the machine.
	runner, err := platform.preflight(ctx, elig.Host, spec.Runner)
	if err != nil {
		return nil, err
	}

	status, err := FetchStatus(ctx, spec.Runner)
	if err != nil {
		return nil, err
	}
	if !status.Running() {
		return nil, fmt.Errorf("this node is not up in the mesh (BackendState=%s) — there is nothing to route through", status.BackendState)
	}
	peer, err := ResolveExitPeer(status, spec.Node)
	if err != nil {
		return nil, err
	}

	// The STATIC half of the scope refusal, ahead of planExclusions because a
	// platform that can never route containers must answer with THAT rather
	// than with whatever its exclusion planner objects to first. On darwin,
	// `--exclude` raises its own error, and a Mac told "--exclude cannot be
	// honoured here" is a Mac whose owner drops the flag and tries again.
	if refusal := platform.containerScopeRefusal(); refusal != "" {
		return &UseExitPlan{
			Eligibility: elig,
			Gate:        peer,
			GateIP:      FirstMeshV4(peer.IPs),
			Narration:   platform.planNarration(FirstMeshV4(peer.IPs)),
			Refusal:     refusal,
			platform:    platform,
			runner:      runner,
		}, nil
	}

	exclusions, err := platform.planExclusions(spec.ControlPlane, spec.Exclude, DefaultResolver)
	if err != nil {
		return nil, err
	}

	plan := &UseExitPlan{
		Eligibility:   elig,
		Gate:          peer,
		GateIP:        FirstMeshV4(peer.IPs),
		Exclusions:    exclusions,
		Manageability: platform.manageability(exclusions.ControlPlaneHost),
		Narration:     platform.planNarration(FirstMeshV4(peer.IPs)),
		platform:      platform,
		runner:        runner,
	}

	// The LIVE half. Discovered from the runtime rather than from the interface
	// table, and keyed on the network's CIDR rather than on any container's own
	// address — containers.go's header has the outage that each of those two
	// choices is a reaction to.
	//
	// A refusal here is carried on the plan rather than raised as an error, so
	// a --plan on a refused host still prints WHY, next to the exclusion set
	// that host really resolves to. UseExit turns the same field into a hard
	// stop.
	plan.Runtime, err = DetectContainerRuntime(ctx, runner)
	if err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.Networks, err = ContainerNetworks(ctx, runner, plan.Runtime)
	if err != nil {
		return nil, err
	}
	if len(plan.Networks) == 0 {
		plan.Refusal = fmt.Sprintf("%s answers on this host but defines no network with an IPv4 subnet, so there is no container traffic to route. %s", plan.Runtime.Name, NoContainerNetworkRefusal)
		return plan, nil
	}
	plan.ProbeNetwork = PickProbeNetwork(plan.Runtime, plan.Networks)
	for _, subnet := range ContainerSubnets(plan.Networks) {
		plan.Routes.Containers = append(plan.Routes.Containers, ContainerRoute{
			Prefix:   subnet,
			Networks: NetworksFor(plan.Networks, subnet),
		})
	}
	plan.Routes.Exclusions = exclusions.Exclusions
	return plan, nil
}

// UseExitResult is what a switch attempt measured, whether it worked or not.
//
// The before/after pair is the point of the whole feature and is populated on
// the failure paths too: "it did not work" is worth much more next to the two
// addresses that prove it.
type UseExitResult struct {
	Gate       string      `json:"gate"`
	GateIP     string      `json:"gate_ip"`
	Exclusions []Exclusion `json:"exclusions"`
	// Containers is which prefixes were routed, and which networks they are.
	// A confirmed gate that routed the wrong networks is a real outcome and
	// this is the only place it is visible.
	Containers []ContainerRoute `json:"containers"`
	Runtime    string           `json:"runtime,omitempty"`

	// THE HOST HALF. These two are supposed to be the SAME address, and
	// HostHeld is the assertion. EgressBefore/EgressAfter keep their names
	// from when this host was the thing being routed, because every consumer
	// already reads them as "this machine's egress" and that is still exactly
	// what they are — what changed is that they are now expected to match.
	EgressBefore    string `json:"egress_before"`
	EgressBeforeVia string `json:"egress_before_via"`
	EgressAfter     string `json:"egress_after"`
	EgressAfterVia  string `json:"egress_after_via"`
	// HostHeld is the proof the machine was left alone. HostMoved is the
	// failed apply — a host whose address moved must revert even when the
	// containers look perfect, and a caller must be able to tell that from a
	// gate that merely did not work.
	HostHeld  bool `json:"host_held"`
	HostMoved bool `json:"host_moved"`

	// THE CONTAINER HALF. These two are supposed to DIFFER, from each other
	// and from the host's address. Their divergence from EgressAfter is the
	// evidence the gate worked.
	ContainerEgressBefore ContainerEgressResult `json:"container_egress_before"`
	ContainerEgressAfter  ContainerEgressResult `json:"container_egress_after"`

	Expected string `json:"expected_egress,omitempty"`

	DefaultDevice  string `json:"default_device"`
	ControlPlaneOK bool   `json:"control_plane_ok"`

	Confirmed bool   `json:"confirmed"`
	Reverted  bool   `json:"reverted"`
	Reason    string `json:"reason,omitempty"`
	// Manageability is UseExitPlan.Manageability, carried out to the caller.
	// Empty means the management path IS pinned outside the tunnel; a
	// sentence means it is not, and why. It rides on the result rather than
	// only on the progress stream because a control plane that stores this
	// reply is the reader most likely to have missed the narration.
	Manageability string `json:"manageability,omitempty"`

	DeadmanExpiresAt string `json:"deadman_expires_at,omitempty"`
	// DeadmanStillArmed is true when the switch was deliberately left armed
	// because the tool's own cleanup failed. It means a revert is still
	// coming, and saying so is the difference between a caller waiting for
	// it and a caller assuming the machine is settled.
	DeadmanStillArmed bool   `json:"deadman_still_armed"`
	BootGuard         string `json:"boot_guard,omitempty"`
}

// UseExit points this machine's default route at a gate, and reverts if it
// cannot prove that worked.
//
// The result is returned alongside any error rather than instead of it: a
// failed switch that has already been reverted is a normal, safe outcome, and
// the caller still wants the evidence.
func UseExit(ctx context.Context, spec UseExitSpec, progress Progress) (UseExitResult, error) {
	spec = spec.withDefaults()

	plan, err := PlanUseExit(ctx, spec)
	if err != nil {
		return UseExitResult{}, err
	}
	// The innermost of the layers that refuse a host whose route would have to
	// move — the /link verb and the CLI each refuse earlier and with a better
	// message for their own caller, but they are all reachable past, and a
	// refusal that lives only in them is one a future caller walks around.
	// Nothing has been measured, armed or moved at this point: PlanUseExit is
	// read-only by construction, which is the same property that lets --plan
	// keep working on a host that is refused.
	if plan.Refusal != "" {
		progress.emit("error", plan.Refusal)
		return UseExitResult{Reason: plan.Refusal}, fmt.Errorf("%w: %s", ErrScopeRefused, plan.Refusal)
	}

	res := UseExitResult{
		Gate:          plan.Gate.Name,
		GateIP:        plan.GateIP,
		Exclusions:    plan.Exclusions.Exclusions,
		Containers:    plan.Routes.Containers,
		Runtime:       plan.Runtime.Name,
		Expected:      spec.ExpectEgress,
		Manageability: plan.Manageability,
	}
	runner := plan.runner

	progress.emit("info", "exit gate %s (%s), path %s", plan.Gate.Name, plan.GateIP, plan.Gate.PathDescription())
	progress.emit("info", "these CONTAINER networks move onto the gate — and nothing else does:")
	for _, c := range plan.Routes.Containers {
		progress.emit("info", fmt.Sprintf("  %-20s %s", c.Prefix, strings.Join(c.Networks, ", ")))
	}
	progress.emit("info", "this MACHINE's own egress is pinned to the main routing table and must not change.")
	if len(plan.Exclusions.Exclusions) > 0 {
		progress.emit("info", "these prefixes stay OUTSIDE the tunnel, for the containers too:")
		for _, e := range plan.Exclusions.Exclusions {
			progress.emit("info", fmt.Sprintf("  %-20s %s", e.Prefix, e.Reason))
		}
	}
	if plan.Manageability != "" {
		progress.emit("warning", plan.Manageability)
	}

	// TWO baselines, and the host's is the one that is not optional.
	//
	// The host's address is what the confirmation asserts held, so without it
	// there is no way to prove the machine was left alone — and "the container
	// moved" on its own is precisely the half-measure the corrected invariant
	// rules out. --expect-egress cannot stand in for it either: it says what
	// the CONTAINER should present and says nothing about the host.
	egress, err := PublicIP(ctx)
	if err != nil {
		return res, fmt.Errorf("could not measure this host's own public IP before the change, so there would be no way to prove afterwards that the machine's egress did not move — refusing to touch anything: %w", err)
	}
	res.EgressBefore = egress.IP
	res.EgressBeforeVia = egress.Via
	progress.emit("info", "host egress before (must NOT change): %s (via %s)", egress.IP, egress.Via)

	// The container's baseline is measured the same way it will be measured
	// afterwards, by the same function, on the same network. A before and an
	// after produced by two different methods would prove nothing.
	res.ContainerEgressBefore = MeasureContainerEgress(ctx, runner, plan.Runtime, plan.ProbeNetwork)
	if res.ContainerEgressBefore.IP != "" {
		progress.emit("info", "container egress before (MUST change): %s (via %s, on network %s)", res.ContainerEgressBefore.IP, res.ContainerEgressBefore.Via, res.ContainerEgressBefore.Network)
	} else if spec.ExpectEgress == "" {
		return res, fmt.Errorf("could not measure container egress before the change (%s), and no expected egress was given, so the result could not be confirmed either way", res.ContainerEgressBefore.Error)
	} else {
		progress.emit("warning", "could not measure container egress before the change (%s); confirmation will rest entirely on the expected egress %s", res.ContainerEgressBefore.Error, spec.ExpectEgress)
	}

	// ARM FIRST. Everything below this line can fail, hang, or be killed, and
	// the route still comes back.
	armed, err := Arm(ArmSpec{
		After:           spec.Deadman,
		ExitNode:        plan.Gate.Name,
		TailscalePath:   runner.CommandPrefix(plan.Eligibility.Host.TailscalePath),
		ExclusionRevert: plan.platform.revertExclusionsScript(runner),
	})
	if err != nil {
		return res, fmt.Errorf("refusing to touch the default route because the dead-man's switch could not be armed: %w", err)
	}
	res.DeadmanExpiresAt = armed.ExpiresAt
	progress.emit("info", "dead-man's switch ARMED (pid %d) — this selection reverts itself at %s unless this run confirms it", armed.PID, armed.ExpiresAt)

	// The rules go in BEFORE the selection, and ApplyRoutes puts the host
	// bypass in first within that. By the time `tailscale set` installs its own
	// `from all lookup 52` at priority 5270, this machine's own traffic has
	// already been claimed by `from all lookup main` at 5265 — so there is no
	// window, not even a momentary one, in which the host could take the gate.
	if err := plan.platform.applyRoutes(ctx, runner, plan.Routes); err != nil {
		res.Reverted, res.DeadmanStillArmed = revertAfterFailure(ctx, runner, plan.platform, "the routing rules could not be installed", progress)
		return res, err
	}
	if err := SetExitNode(ctx, runner, plan.GateIP); err != nil {
		res.Reverted, res.DeadmanStillArmed = revertAfterFailure(ctx, runner, plan.platform, "the exit node could not be selected", progress)
		return res, err
	}
	progress.emit("info", "container networks now point at %s — confirming BOTH halves (up to %s): that container egress moved, and that this machine's did not...", plan.Gate.Name, spec.ConfirmTimeout)

	confirm := confirmWithRetries(ctx, runner, confirmSpec{
		platform:     plan.platform,
		runtime:      plan.Runtime,
		network:      plan.ProbeNetwork,
		hostBefore:   res.EgressBefore,
		container:    res.ContainerEgressBefore,
		expected:     spec.ExpectEgress,
		controlPlane: spec.ControlPlane,
	}, spec.ConfirmTimeout, progress)
	res.EgressAfter = confirm.HostAfter
	res.EgressAfterVia = confirm.HostAfterVia
	res.HostHeld = confirm.HostHeld
	res.HostMoved = confirm.HostMoved
	res.ContainerEgressAfter = confirm.ContainerAfter
	res.DefaultDevice = confirm.DefaultDevice
	res.ControlPlaneOK = confirm.ControlPlaneOK
	res.Confirmed = confirm.OK
	res.Reason = confirm.Reason
	for _, line := range strings.Split(strings.TrimRight(confirm.Describe(), "\n"), "\n") {
		progress.emit("info", "  %s", line)
	}

	if !confirm.OK {
		if confirm.HostMoved {
			// Named separately because it is not the same event. A gate that
			// does not forward is a feature failing; a host whose address
			// moved is this machine having been changed in the one way it must
			// never be, and whoever is watching needs to read that sentence
			// rather than infer it from two addresses.
			progress.emit("error", "REVERTING — THIS MACHINE'S OWN EGRESS MOVED. That is a failed apply regardless of what the containers are doing, and it is the exact failure this verb was rewritten to make impossible.")
		}
		progress.emit("warning", "REVERTING — an exit node that cannot be confirmed is the failure this command exists to prevent, not a partial success.")
		if err := revert(ctx, runner, plan.platform, progress); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("error", "the revert itself FAILED (%v). The dead-man's switch is still armed and fires at %s; leaving it armed on purpose.", err, armed.ExpiresAt)
			return res, fmt.Errorf("exit node %s could not be confirmed and the revert failed: %s", plan.Gate.Name, confirm.Reason)
		}
		res.Reverted = true
		if _, err := Disarm(); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("warning", "the route was reverted but the dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
		}
		return res, fmt.Errorf("exit node %s was NOT confirmed and has been reverted: %s", plan.Gate.Name, confirm.Reason)
	}

	// Confirmed. Only now is it safe to stand the switch down.
	if _, err := Disarm(); err != nil {
		// Do not treat this as success-with-a-note: a switch that cannot be
		// stood down WILL revert a working selection, and the operator needs
		// to know that before they walk away.
		res.DeadmanStillArmed = true
		return res, fmt.Errorf("egress was confirmed, but the dead-man's switch could not be stood down (%w) — it will revert this selection at %s", err, armed.ExpiresAt)
	}
	progress.emit("info", "egress confirmed through the new route; dead-man's switch stood down.")

	if spec.PersistAcrossReboot {
		res.BootGuard = "skipped"
		progress.emit("warning", "persist-across-reboot: the %s boot guard was NOT installed. A tailscale exit-node selection survives a reboot, but nothing re-confirms it on the way back up, so this machine can come back with its default route on a gate that has since stopped forwarding and with %s inside the tunnel.",
			plan.platform.bootGuardName(), plan.Exclusions.ControlPlaneHost)
		if err := plan.platform.removeBootGuard(ctx, runner); err != nil {
			progress.emit("warning", "could not remove a previously installed boot guard: %v", err)
		}
	} else if err := plan.platform.installBootGuard(ctx, runner, plan.Eligibility.Host.TailscalePath); err != nil {
		res.BootGuard = "failed: " + err.Error()
		progress.emit("warning", "the selection is live but the boot guard could not be installed (%v). A reboot would come back with the route still moved and nothing having re-confirmed it; clear the exit gate before rebooting this host.", err)
	} else {
		res.BootGuard = "installed"
		progress.emit("info", "boot guard %s installed — a restart clears this selection, which is deliberate: a reboot has to stay a way out of a gate that stopped forwarding.", plan.platform.bootGuardName())
	}

	return res, saveExitState(plan.Gate.Name, plan.GateIP, plan.Exclusions)
}

// ClearExitSpec is a request to undo a selection.
type ClearExitSpec struct {
	Runner Runner
}

// ClearExitResult reports what was undone, and — measured, not assumed —
// where traffic goes now.
type ClearExitResult struct {
	// ExclusionsRemoved counts every rule removed at every priority this
	// module owns, not only the `to ... lookup main` exclusions the name comes
	// from. The name and its JSON key are kept because the control plane and
	// the UI already read them, and renaming a field to be tidier is not worth
	// a screen that silently shows nothing.
	ExclusionsRemoved int    `json:"exclusions_removed"`
	DeadmanStoodDown  bool   `json:"deadman_stood_down"`
	Egress            string `json:"egress"`
	EgressVia         string `json:"egress_via"`
	// EgressError is set when the host still cannot reach the internet after
	// the clear. Reported rather than swallowed: "cleared, and still broken"
	// must not render as "cleared".
	EgressError string `json:"egress_error,omitempty"`
	// ContainerEgress is the other half of the undo. Clearing a gate is
	// supposed to bring the two addresses back together, so reporting only the
	// host's would leave the one question this verb is asked — did my
	// containers come back — answered by inference.
	ContainerEgress ContainerEgressResult `json:"container_egress"`
}

// ClearExit clears the selection, removes the exclusions and the boot guard,
// and reports the egress IP that results.
func ClearExit(ctx context.Context, spec ClearExitSpec, progress Progress) (ClearExitResult, error) {
	var res ClearExitResult
	if spec.Runner == nil {
		return res, fmt.Errorf("no runner given")
	}
	host := Probe()
	if host.TailscalePath == "" {
		return res, fmt.Errorf("tailscale is not installed on this host, so there is no exit-node selection to clear")
	}
	platform, err := platformFor(host)
	if err != nil {
		return res, err
	}
	// The undo path deliberately does NOT run platform.preflight. Preflight
	// refuses a machine that may not write preferences, and refusing here
	// would mean the one command that puts the route back is the one that
	// declines to run — the failure would surface as an error from
	// SetExitNode instead, which is where it belongs.
	runner := PrivilegedRunner{Inner: spec.Runner, Sudo: host.OS != "darwin" && host.UID != 0}

	// Stand the switch down first. Clearing the exit node is the same action
	// the switch would take, so leaving it armed would only mean a redundant
	// revert firing minutes later against whatever the operator does next.
	if stood, err := Disarm(); err != nil {
		progress.emit("warning", "could not stand down the dead-man's switch: %v", err)
	} else if stood {
		res.DeadmanStoodDown = true
		progress.emit("info", "dead-man's switch stood down")
	}

	removed, err := revertCounting(ctx, runner, platform, progress)
	res.ExclusionsRemoved = removed
	if err != nil {
		return res, err
	}
	if err := platform.removeBootGuard(ctx, runner); err != nil {
		progress.emit("warning", "could not remove the boot guard: %v", err)
	}

	// Say where traffic goes now, measured rather than assumed — the same
	// standard the selection is held to, and for both halves, because "the
	// host is fine" was never the question a clear is asked.
	if egress, err := PublicIP(ctx); err == nil {
		res.Egress = egress.IP
		res.EgressVia = egress.Via
		progress.emit("info", "exit node cleared — host egress is now %s (via %s)", egress.IP, egress.Via)
	} else {
		res.EgressError = err.Error()
		progress.emit("warning", "exit node cleared, but this host still cannot reach the internet: %v", err)
	}
	// Best-effort, and never a reason to fail the undo: a host that has since
	// lost its container runtime still needs its rules taken off.
	if runtime, err := DetectContainerRuntime(ctx, runner); err == nil {
		networks, _ := ContainerNetworks(ctx, runner, runtime)
		res.ContainerEgress = MeasureContainerEgress(ctx, runner, runtime, PickProbeNetwork(runtime, networks))
		if res.ContainerEgress.IP != "" {
			progress.emit("info", "container egress is now %s (via %s, on network %s) — with no gate in force this should match the host's", res.ContainerEgress.IP, res.ContainerEgress.Via, res.ContainerEgress.Network)
		} else {
			progress.emit("warning", "the gate is cleared but container egress could not be measured: %s", res.ContainerEgress.Error)
		}
	} else {
		res.ContainerEgress = ContainerEgressResult{Error: err.Error()}
	}

	return res, clearExitState()
}

// revert puts the machine back the way it was: no exit node, no exclusions.
// Order matters — clear the selection first, so that if removing the
// exclusions fails the machine is already off the tunnel rather than on it
// with half its pins gone.
func revert(ctx context.Context, r Runner, plat exitPlatform, progress Progress) error {
	_, err := revertCounting(ctx, r, plat, progress)
	return err
}

func revertCounting(ctx context.Context, r Runner, plat exitPlatform, progress Progress) (int, error) {
	if err := SetExitNode(ctx, r, ""); err != nil {
		return 0, fmt.Errorf("clear the exit-node selection: %w", err)
	}
	removed, err := plat.clearExclusions(ctx, r)
	if err != nil {
		return removed, fmt.Errorf("remove the route exclusions: %w", err)
	}
	if removed > 0 {
		progress.emit("info", "removed %d route exclusion(s)", removed)
	}
	return removed, nil
}

// revertAfterFailure is the best-effort cleanup for a failure that happened
// mid-change. It never masks the original error and never leaves the operator
// thinking the machine is clean when it is not — if the cleanup fails too,
// the dead-man's switch is deliberately left armed to finish the job.
//
// Returns (reverted, deadmanStillArmed) so the caller can report both rather
// than only printing them.
func revertAfterFailure(ctx context.Context, r Runner, plat exitPlatform, what string, progress Progress) (bool, bool) {
	progress.emit("warning", "%s — undoing what was already applied", what)
	if err := revert(ctx, r, plat, progress); err != nil {
		progress.emit("error", "the cleanup failed too (%v). The dead-man's switch is still armed and will finish the job; NOT standing it down.", err)
		return false, true
	}
	if _, err := Disarm(); err != nil {
		progress.emit("warning", "cleanup succeeded but the dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
		return true, true
	}
	return true, false
}

// confirmWithRetries keeps checking until the deadline. A single immediate
// check would fail on a perfectly good gate: tailscale needs a moment to
// install the route and the first packets have to find their way through DERP
// or a direct path that may not be up yet. Retrying is not optimism — a
// failure here reverts, so a false negative costs a working feature.
func confirmWithRetries(ctx context.Context, r Runner, spec confirmSpec, timeout time.Duration, progress Progress) ConfirmResult {
	deadline := time.Now().Add(timeout)
	var last ConfirmResult
	for attempt := 1; ; attempt++ {
		last = confirmContainerScoped(ctx, r, spec)
		if last.OK || time.Now().After(deadline) {
			return last
		}
		// A host whose address moved does not get retried. Retrying is for a
		// gate that has not finished coming up; this is a machine that is
		// already in the state the whole sequence exists to prevent, and every
		// extra second spent optimistically re-measuring is a second it stays
		// there.
		if last.HostMoved {
			return last
		}
		progress.emit("info", "  attempt %d not confirmed yet (%s) — retrying", attempt, last.Reason)
		time.Sleep(confirmPollInterval)
	}
}

func saveExitState(node, ip string, plan ExclusionPlan) error {
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

func clearExitState() error {
	statePath, err := state.DefaultPath()
	if err != nil {
		return err
	}
	st, err := state.Load(statePath)
	if err != nil {
		return err
	}
	if st.VPN == nil {
		return nil
	}
	st.VPN.ExitNode = ""
	st.VPN.ExitNodeIP = ""
	st.VPN.ExitSelectedAt = ""
	st.VPN.ExitExclusions = nil
	if err := state.Save(statePath, st); err != nil {
		return fmt.Errorf("exit node cleared, but could not update local state: %w", err)
	}
	return nil
}

// FirstMeshV4 returns a peer's first IPv4 mesh address. `tailscale set
// --exit-node` is given the address rather than the name: a name has to be
// re-resolved by tailscale against MagicDNS, and MagicDNS is off here.
func FirstMeshV4(ips []string) string {
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			return ip
		}
	}
	return ""
}
