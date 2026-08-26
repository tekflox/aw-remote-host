// Phase 2 of the vpn module as a library: selecting an exit gate, which moves
// this machine's default route onto the mesh, and clearing it again.
//
// The ordering in UseExit is the deliverable, not the `tailscale set` call in
// the middle of it. Read it as a sequence and every step is there to close one
// way of ending up with a machine that has no internet and no way to be told
// to stop:
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

// HostRouteScopeRefusal is why selecting a gate refuses today, and it is
// deliberately UNCONDITIONAL — not a check on which host is asking.
//
// The invariant this feature was built on was backwards. Everything below
// moves THIS MACHINE's default route (`ip rule ... lookup 52`, applied `from
// all`), so the host and its containers both leave through the gate. What was
// actually wanted is the containers' egress moving and the HOST's public IP
// staying exactly where it is — the host address is now the thing that must
// NOT change, and a host whose IP moved is a failed apply however good the
// container's egress looks.
//
// The cost of the old shape is not theoretical: it took a Mac off the internet
// on the first real apply, and the same verb is reachable against a bare metal
// running production (agents-platform-multitenant, aw-backend, ~15
// aw-custom-*), where moving the host route is destructive. So until the
// per-container-network rules exist, the honest behaviour is to refuse rather
// than to keep offering a destructive action with a dead-man's switch behind
// it. Routing the whole machine is not a degraded mode of this feature; under
// the corrected invariant it IS the bug.
//
// ClearExit is deliberately NOT gated by this. It is the way OFF a gate, and
// an undo that refuses is one that fails exactly when it is most needed —
// including for the hosts that took a selection before this refusal landed.
const HostRouteScopeRefusal = "`vpn use-exit` moves this MACHINE's default route, and every container on it, out through the gate — but the only egress that should move is the containers'. The host's own public IP must not change. Until container-scoped routing exists this verb refuses, rather than keep offering a change that can take a production machine off the internet. `vpn clear-exit` still works, so a host already on a gate can be taken off one."

// ErrHostRouteScope is HostRouteScopeRefusal as an error, so a caller can tell
// "this tool will not do this at all" apart from "this host could not".
var ErrHostRouteScope = errors.New(HostRouteScopeRefusal)

// hostRouteScopeRefused is the switch the refusal hangs on, and it stays true
// until UseExit routes container networks instead of the machine.
//
// A var rather than a bare unconditional return so the sequence beneath it
// stays reachable from its own tests. That ordering — measure, arm, pin, move,
// confirm, revert — is the safety mechanism, and it is what the
// container-scoped rewrite will inherit; letting it sit unexercised behind a
// refusal for however long that takes is how a rewrite starts from a sequence
// nobody has run in months. Tests flip it with withHostRouteScopeAllowed.
var hostRouteScopeRefused = true

// HostScopeRefused reports whether selecting a gate is refused outright. The
// layers above ask before they build a spec, so their caller gets the reason
// instead of a generic failure from somewhere deep in the sequence.
func HostScopeRefused() bool { return hostRouteScopeRefused }

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
	// Refusal is HostRouteScopeRefusal, carried on the plan so that a preview
	// cannot be mistaken for an actionable confirmation. Planning stays
	// available while the refusal stands — it changes nothing by construction,
	// and it is the only way to see what this host's exclusion set really
	// resolves to, which is the input to re-deriving that set for the
	// container-scoped model. But every consumer of a plan gets told, in the
	// same sentence UseExit would fail with, that applying it is refused.
	Refusal string

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

	exclusions, err := platform.planExclusions(spec.ControlPlane, spec.Exclude, DefaultResolver)
	if err != nil {
		return nil, err
	}

	return &UseExitPlan{
		Eligibility:   elig,
		Gate:          peer,
		GateIP:        FirstMeshV4(peer.IPs),
		Exclusions:    exclusions,
		Manageability: platform.manageability(exclusions.ControlPlaneHost),
		Narration:     platform.planNarration(FirstMeshV4(peer.IPs)),
		Refusal:       HostRouteScopeRefusal,
		platform:      platform,
		runner:        runner,
	}, nil
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

	EgressBefore    string `json:"egress_before"`
	EgressBeforeVia string `json:"egress_before_via"`
	EgressAfter     string `json:"egress_after"`
	EgressAfterVia  string `json:"egress_after_via"`
	Expected        string `json:"expected_egress,omitempty"`

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
	// BEFORE the plan, and before anything is measured, armed or moved. This
	// is the innermost of the layers that refuse this today — the /link verb,
	// the CLI and the control plane each refuse earlier and with a better
	// message for their own caller, but they are all reachable past, and a
	// refusal that lives only in them is one a future caller walks around.
	// Costing nothing (no DNS, no tailscale call, no probe) is the point: the
	// cheapest possible answer to a request that must not be served.
	if hostRouteScopeRefused {
		progress.emit("error", HostRouteScopeRefusal)
		return UseExitResult{Reason: HostRouteScopeRefusal}, ErrHostRouteScope
	}

	spec = spec.withDefaults()

	plan, err := PlanUseExit(ctx, spec)
	if err != nil {
		return UseExitResult{}, err
	}
	res := UseExitResult{
		Gate:          plan.Gate.Name,
		GateIP:        plan.GateIP,
		Exclusions:    plan.Exclusions.Exclusions,
		Expected:      spec.ExpectEgress,
		Manageability: plan.Manageability,
	}
	runner := plan.runner

	progress.emit("info", "exit gate %s (%s), path %s", plan.Gate.Name, plan.GateIP, plan.Gate.PathDescription())
	if len(plan.Exclusions.Exclusions) > 0 {
		progress.emit("info", "these prefixes stay OUTSIDE the tunnel:")
		for _, e := range plan.Exclusions.Exclusions {
			progress.emit("info", fmt.Sprintf("  %-20s %s", e.Prefix, e.Reason))
		}
	}
	if plan.Manageability != "" {
		progress.emit("warning", plan.Manageability)
	}

	// Baseline. Without it there is nothing to compare against, so a switch
	// could not be confirmed at all — unless the caller stated what the gate
	// should present, in which case the "after" measurement stands alone.
	if egress, err := PublicIP(ctx); err == nil {
		res.EgressBefore = egress.IP
		res.EgressBeforeVia = egress.Via
		progress.emit("info", "egress before the switch: %s (via %s)", egress.IP, egress.Via)
	} else if spec.ExpectEgress == "" {
		return res, fmt.Errorf("could not measure this host's public IP before the switch, and no expected egress was given, so the switch could not be confirmed either way: %w", err)
	} else {
		progress.emit("warning", "could not measure egress before the switch (%v); confirmation will rest entirely on the expected egress %s", err, spec.ExpectEgress)
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

	if err := plan.platform.applyExclusions(ctx, runner, plan.Exclusions.Exclusions); err != nil {
		res.Reverted, res.DeadmanStillArmed = revertAfterFailure(ctx, runner, plan.platform, "the route exclusions could not be installed", progress)
		return res, err
	}
	if err := SetExitNode(ctx, runner, plan.GateIP); err != nil {
		res.Reverted, res.DeadmanStillArmed = revertAfterFailure(ctx, runner, plan.platform, "the exit node could not be selected", progress)
		return res, err
	}
	progress.emit("info", "default route now points at %s — confirming egress (up to %s)...", plan.Gate.Name, spec.ConfirmTimeout)

	confirm := confirmWithRetries(ctx, runner, plan.platform, res.EgressBefore, spec.ExpectEgress, spec.ControlPlane, spec.ConfirmTimeout, progress)
	res.EgressAfter = confirm.Observed
	res.EgressAfterVia = confirm.ObservedVia
	res.DefaultDevice = confirm.DefaultDevice
	res.ControlPlaneOK = confirm.ControlPlaneOK
	res.Confirmed = confirm.OK
	res.Reason = confirm.Reason
	for _, line := range strings.Split(strings.TrimRight(confirm.Describe(), "\n"), "\n") {
		progress.emit("info", "  %s", line)
	}

	if !confirm.OK {
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
	ExclusionsRemoved int    `json:"exclusions_removed"`
	DeadmanStoodDown  bool   `json:"deadman_stood_down"`
	Egress            string `json:"egress"`
	EgressVia         string `json:"egress_via"`
	// EgressError is set when the host still cannot reach the internet after
	// the clear. Reported rather than swallowed: "cleared, and still broken"
	// must not render as "cleared".
	EgressError string `json:"egress_error,omitempty"`
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
	// standard the selection is held to.
	if egress, err := PublicIP(ctx); err == nil {
		res.Egress = egress.IP
		res.EgressVia = egress.Via
		progress.emit("info", "exit node cleared — egress is now %s (via %s)", egress.IP, egress.Via)
	} else {
		res.EgressError = err.Error()
		progress.emit("warning", "exit node cleared, but this host still cannot reach the internet: %v", err)
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
func confirmWithRetries(ctx context.Context, r Runner, plat exitPlatform, baseline, expected, controlPlane string, timeout time.Duration, progress Progress) ConfirmResult {
	deadline := time.Now().Add(timeout)
	var last ConfirmResult
	for attempt := 1; ; attempt++ {
		last = confirmEgress(ctx, r, plat, baseline, expected, controlPlane)
		if last.OK || time.Now().After(deadline) {
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
