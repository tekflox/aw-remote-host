// Routing ONE container on this host out through an EXTERNAL WireGuard tunnel
// that this host already terminates — as opposed to a mesh exit gate, which is
// usexit.go's job and is not touched by anything in this file.
//
// WHY THIS EXISTS AS A SECOND PATH AT ALL. The `aw` workspace runs inside a
// container (`e91aacf5a3a3`, the `aw-remote-host` container on the production
// bare metal) which has neither `ip`, `wg` nor `tailscale` in its image and no
// container runtime of its own. It therefore cannot select a mesh gate for
// itself: platformFor (usexit_platform.go) refuses a host with no `ip`, and
// ScopeRefusal refuses a host with no runtime to scope. Both refusals are
// correct and neither is worth weakening. Measured 2026-09-02 inside that
// container: /usr/sbin/ip, /sbin/ip, /usr/bin/ip, wg, wg-quick, tailscale and
// tailscaled are all absent and `dpkg -l` is empty.
//
// What IS true is that the machine hosting it — the bare metal — already
// terminates the GL.iNet tunnel as `aw-vpn-hub`, and that hub already
// maintains a complete routing table (200: `default via 10.8.0.2 dev wg0`
// plus direct routes for the local docker bridges so container-to-container
// traffic never enters the tunnel — repos/aw-stack/scripts/vpn-hub-entrypoint.sh).
// The whole engine is already up. The only thing missing was a SOURCE pointed
// at it. So the apply runs on the host that OWNS the tunnel, and names the
// container it is moving. This is the first place in this codebase where an
// apply for host A executes on host B, and that is deliberate: host B is the
// only one that can write the rule.
//
// THE INVARIANT IS UNCHANGED, and this path does not need an exception to it:
//
//   - the routed CONTAINER's public IP MUST change. That is the feature.
//   - the HOST's public IP MUST NOT change. Asserted after every apply, and a
//     host whose address moved is a failed apply that reverts.
//   - the rule is anchored on a /32 belonging to the workload, never on a
//     network CIDR. Measured on the production bare metal 2026-09-02:
//     172.18.0.0/16 also carries aw-backend, aw-caddy, aw-headscale, aw-derper,
//     aw-sandbox and agents-platform-multitenant. A /16 rule would put the
//     entire production stack on a residential line. mustBeSingleHost turns
//     that into a refusal rather than a warning.
//
// The discriminant that keeps a physical machine from ever being routed by
// this path is structural rather than heuristic: the rule's source is an
// address enumerated FROM THE CONTAINER RUNTIME. A machine that is not running
// the named container produces no such address and is refused. There is no
// input to this file that widens into `from all`.
//
// THE RULE DOES NOT SURVIVE ON ITS OWN, and that is measured, not feared. On
// this bare metal `systemd-networkd` is restarted by the daily unattended apt
// upgrade (apt-daily-upgrade.service ran 2026-09-02 06:48:11; networkd
// restarted 06:48:54, 06:49:10 and 06:49:45) and it flushes every routing
// policy rule it does not own — tailscaled logs `somebody (likely
// systemd-networkd) deleted ip rules; restoring Tailscale's` and puts its own
// back. The hub's own client rules at priority 100-107 were NOT put back,
// because the hub installs them once at boot and then sleeps, which is why
// they are missing from a container that has been up 15 hours with
// RestartCount 0. Anything installed once here has a life expectancy shorter
// than a day. Reassert (below) is therefore part of the feature and not a
// nicety, and it is what the link daemon calls on a timer.
package vpn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// ExternalRouteTable is the routing table an external tunnel's default route
// is expected to live in. 200 is aw-vpn-hub's, and it is a default rather than
// a constant because a second external provider needs a second table — tables
// scale by replication here, not by multiplexing (vpn-concentrator.md §6).
const ExternalRouteTable = 200

// ExternalRoutePriority is where this path's `ip rule` sits.
//
// The neighbourhood is crowded and picking blind would silently shadow
// something. Measured on the production bare metal: tailscale owns 5210-5270
// (5210 main, 5230 default, 5250 unreachable, 5270 lookup 52) and usexit.go
// uses 5259-5265 inside that band. aw-vpn-hub uses 100-107 for its own wg
// clients. 5399 is below tailscale's whole range and far above the hub's, so
// it is evaluated after tailscale's fwmark rules have had their say — which is
// what keeps a tailscale-marked packet out of this table — and before the
// 32766 main lookup that would otherwise send the container out the host's
// own uplink.
const ExternalRoutePriority = 5399

// ExternalRouteSpec is one request to move a single container's egress onto an
// external tunnel this host terminates.
type ExternalRouteSpec struct {
	// Container names the container whose egress moves, by name or id, as the
	// local runtime knows it. Required: it is also the discriminant, because
	// resolving it is what produces an address that cannot be this machine.
	Container string
	// Table is the routing table carrying the tunnel's default route.
	// Defaults to ExternalRouteTable.
	Table int
	// Priority is the ip rule priority. Defaults to ExternalRoutePriority.
	Priority int
	// ExpectEgress, when set, makes confirmation an exact match instead of
	// merely "the address changed".
	ExpectEgress string
	// Deadman is how long an unconfirmed apply has before it reverts itself.
	Deadman time.Duration
	// ConfirmTimeout is how long to keep trying to confirm. Must stay inside
	// Deadman, and withDefaults enforces that rather than trusting a caller.
	ConfirmTimeout time.Duration
	// ControlPlane is the base URL whose addresses are held outside the
	// tunnel. Defaults to the daemon's own control plane.
	ControlPlane string

	// Runner is how every shellout is made. Required and never defaulted:
	// this package cannot build one (the base shellout lives in internal/ops,
	// which imports this package) and PrivilegedRunner's zero value has a nil
	// Inner that panics on first use. Same field, same reason, as UseExitSpec.
	Runner Runner
	// Runtime lets a caller that has already detected the container engine
	// avoid paying for the probe again. Zero value means "detect it".
	Runtime ContainerRuntime
}

func (s ExternalRouteSpec) withDefaults() ExternalRouteSpec {
	if s.Table == 0 {
		s.Table = ExternalRouteTable
	}
	if s.Priority == 0 {
		s.Priority = ExternalRoutePriority
	}
	if s.Deadman <= 0 {
		s.Deadman = 120 * time.Second
	}
	if s.ConfirmTimeout <= 0 {
		s.ConfirmTimeout = 45 * time.Second
	}
	// A confirmation window that outlives the switch it is racing would let a
	// selection revert while this run still believes it is confirming, and the
	// run would then report a success that no longer exists.
	if s.ConfirmTimeout >= s.Deadman {
		s.ConfirmTimeout = s.Deadman - 15*time.Second
		if s.ConfirmTimeout < 5*time.Second {
			s.ConfirmTimeout = 5 * time.Second
		}
	}
	return s
}

// ExternalRoutePlan is everything resolved before anything is changed.
// Producing one is read-only, which is what makes the plan mode an honest
// preview rather than a second code path that might disagree.
type ExternalRoutePlan struct {
	Container   string   `json:"container"`
	ContainerID string   `json:"container_id"`
	SourceIP    string   `json:"source_ip"`
	Table       int      `json:"table"`
	Priority    int      `json:"priority"`
	Runtime     string   `json:"runtime"`
	TunnelVia   string   `json:"tunnel_via"`
	TunnelDev   string   `json:"tunnel_dev"`
	Exclusions  []string `json:"exclusions"`
	MainGateway string   `json:"main_gateway"`
	MainDev     string   `json:"main_dev"`
	Refusal     string   `json:"refusal,omitempty"`
}

// Rule is the exact `ip rule` this plan installs, as a printable string. Used
// in the narration and in the dead-man's revert script, so that the thing
// removed is spelled the same way as the thing added.
func (p ExternalRoutePlan) ruleArgs(verb string) []string {
	return []string{"rule", verb, "from", p.SourceIP + "/32", "lookup", strconv.Itoa(p.Table), "priority", strconv.Itoa(p.Priority)}
}

// excludeArgs is one DNS/control-plane exclusion, expressed inside the tunnel
// table so it wins over that table's own default.
//
// `onlink` is not optional here and it is not cargo cult. The production bare
// metal carries 65.109.66.88/32 on enp41s0 with `default via 65.109.66.65
// proto static onlink` — a Hetzner-style layout where the gateway is not
// inside any interface subnet. Without onlink the kernel answers `Error:
// Nexthop has invalid gateway.` and the exclusion silently never installs,
// which was measured on the first attempt at exactly this.
func (p ExternalRoutePlan) excludeArgs(verb, prefix string) []string {
	args := []string{"route", verb, prefix, "via", p.MainGateway, "dev", p.MainDev}
	if verb == "add" {
		args = append(args, "onlink")
	}
	return append(args, "table", strconv.Itoa(p.Table))
}

// ExternalRouteResult is what one apply measured, whether it worked or not.
// The before/after pairs are populated on the failure paths too: "it did not
// work" is worth much more next to the four addresses that prove it.
type ExternalRouteResult struct {
	Plan ExternalRoutePlan `json:"plan"`

	HostBefore string `json:"host_before"`
	HostAfter  string `json:"host_after,omitempty"`
	HostHeld   bool   `json:"host_held"`
	HostMoved  bool   `json:"host_moved"`

	ContainerBefore string `json:"container_before,omitempty"`
	ContainerAfter  string `json:"container_after,omitempty"`

	Confirmed bool   `json:"confirmed"`
	Reverted  bool   `json:"reverted"`
	Reason    string `json:"reason,omitempty"`

	DeadmanExpiresAt  string `json:"deadman_expires_at,omitempty"`
	DeadmanStillArmed bool   `json:"deadman_still_armed"`
}

// PlanExternalRoute resolves the container, the table and the exclusions, and
// refuses anything this host cannot safely be asked to do — changing nothing.
//
// The refusals are ordered by how early they can be known, so a host that was
// never a candidate never gets as far as running a probe container.
func PlanExternalRoute(ctx context.Context, spec ExternalRouteSpec) (*ExternalRoutePlan, error) {
	spec = spec.withDefaults()
	plan := &ExternalRoutePlan{
		Container: spec.Container,
		Table:     spec.Table,
		Priority:  spec.Priority,
	}
	if strings.TrimSpace(spec.Container) == "" {
		return nil, fmt.Errorf("container is required: it names the workload whose egress moves, and resolving it is also what proves the rule cannot match this machine")
	}
	runner := spec.Runner
	if runner == nil {
		// Deliberately an error and not a default. This package cannot
		// construct a working runner on its own — the base shellout lives in
		// internal/ops, which imports this package — and PrivilegedRunner's
		// zero value has a nil Inner that panics on first use. A caller that
		// forgot to supply one has to be told, not handed something that dies
		// halfway through a route change.
		return nil, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	// `ip` first, because without it nothing below can be written and the
	// honest failure is "this host cannot do this at all".
	if _, err := runner.Run(ctx, "ip", "-V"); err != nil {
		plan.Refusal = "this host has no usable `ip` command, so it cannot write a routing policy rule for anything"
		return plan, nil
	}

	rt := spec.Runtime
	if !rt.Present() {
		detected, err := DetectContainerRuntime(ctx, runner)
		if err != nil || !detected.Present() {
			plan.Refusal = NoContainerRuntimeRefusal
			return plan, nil
		}
		rt = detected
	}
	plan.Runtime = rt.Name

	id, ip, err := resolveContainerSource(ctx, runner, rt, spec.Container)
	if err != nil {
		// A container that cannot be resolved is a REFUSAL and never a guess.
		// The IP this rule keys on is Docker IPAM and moves whenever the
		// container is recreated; substituting a remembered or assumed address
		// would eventually point the rule at whatever moved into that slot.
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.ContainerID, plan.SourceIP = id, ip

	if err := mustBeSingleHost(ip); err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	if err := mustNotBeThisHost(ctx, runner, ip); err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}

	via, dev, err := tableDefault(ctx, runner, spec.Table)
	if err != nil {
		// Pointing a rule at an empty table does not fall through to main —
		// it black-holes the container. Refusing is the difference between
		// "the tunnel is not up" and "the workspace lost the internet".
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.TunnelVia, plan.TunnelDev = via, dev

	gw, mdev, err := mainDefault(ctx, runner)
	if err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.MainGateway, plan.MainDev = gw, mdev

	plan.Exclusions = planExternalExclusions(ctx, runner, rt, id, spec.ControlPlane)
	return plan, nil
}

// ExternalRoute moves one container's egress onto the external tunnel, and
// reverts if it cannot prove that worked.
//
// The sequence is deliberately the same shape as UseExit's, for the same
// reasons, in the same order: measure both addresses, arm the dead-man's
// switch, pin the exclusions, install the rule, confirm BOTH halves, revert
// anything unconfirmed. The result is returned alongside any error rather than
// instead of it — a failed apply that has already reverted is a normal, safe
// outcome and the caller still wants the evidence.
func ExternalRoute(ctx context.Context, spec ExternalRouteSpec, progress Progress) (ExternalRouteResult, error) {
	spec = spec.withDefaults()
	runner := spec.Runner
	if runner == nil {
		// Deliberately an error and not a default. This package cannot
		// construct a working runner on its own — the base shellout lives in
		// internal/ops, which imports this package — and PrivilegedRunner's
		// zero value has a nil Inner that panics on first use. A caller that
		// forgot to supply one has to be told, not handed something that dies
		// halfway through a route change.
		return ExternalRouteResult{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	plan, err := PlanExternalRoute(ctx, spec)
	if err != nil {
		return ExternalRouteResult{}, err
	}
	res := ExternalRouteResult{Plan: *plan}
	if plan.Refusal != "" {
		progress.emit("error", plan.Refusal)
		res.Reason = plan.Refusal
		return res, fmt.Errorf("%w: %s", ErrScopeRefused, plan.Refusal)
	}

	progress.emit("info", "routing container %s (%s) out through %s via %s, table %d",
		plan.Container, plan.SourceIP, plan.TunnelDev, plan.TunnelVia, plan.Table)
	progress.emit("info", "the rule is anchored on %s/32 — a single host address that belongs to that container and cannot be this machine.", plan.SourceIP)
	for _, ex := range plan.Exclusions {
		progress.emit("info", "  %s stays OUTSIDE the tunnel", ex)
	}

	// TWO baselines, and the host's is the one that is not optional: it is
	// what the confirmation asserts held, and without it there is no way to
	// prove afterwards that the machine was left alone.
	host, err := PublicIP(ctx)
	if err != nil {
		return res, fmt.Errorf("could not measure this host's own public IP before the change, so there would be no way to prove afterwards that the machine's egress did not move — refusing to touch anything: %w", err)
	}
	res.HostBefore = host.IP
	progress.emit("info", "host egress before (must NOT change): %s", host.IP)

	before := measureNetnsEgress(ctx, runner, plan.Runtime, plan.ContainerID)
	res.ContainerBefore = before.IP
	if before.IP == "" && spec.ExpectEgress == "" {
		return res, fmt.Errorf("could not measure the container's egress before the change (%s), and no expected egress was given, so the result could not be confirmed either way", before.Error)
	}
	progress.emit("info", "container egress before (MUST change): %s", before.IP)

	// ARM FIRST. Everything below this line can fail, hang or be killed, and
	// the container still comes back.
	armed, err := Arm(ArmSpec{
		After:           spec.Deadman,
		ExitNode:        fmt.Sprintf("external tunnel %s for container %s", plan.TunnelDev, plan.Container),
		ExclusionRevert: externalRevertScript(runner, *plan),
	})
	if err != nil {
		return res, fmt.Errorf("refusing to install the rule because the dead-man's switch could not be armed: %w", err)
	}
	res.DeadmanExpiresAt = armed.ExpiresAt
	progress.emit("info", "dead-man's switch ARMED (pid %d) — this route reverts itself at %s unless this run confirms it", armed.PID, armed.ExpiresAt)

	// Exclusions BEFORE the rule, so there is no window in which the container
	// is on the tunnel with its resolvers inside it.
	if err := applyExternalRoute(ctx, runner, *plan); err != nil {
		res.Reverted, res.DeadmanStillArmed = revertExternalAfterFailure(ctx, runner, *plan, progress)
		return res, err
	}

	progress.emit("info", "rule installed — confirming BOTH halves (up to %s): that the container's egress moved, and that this machine's did not...", spec.ConfirmTimeout)
	confirm := confirmExternal(ctx, runner, *plan, externalConfirmSpec{
		hostBefore:      res.HostBefore,
		containerBefore: res.ContainerBefore,
		expected:        spec.ExpectEgress,
	}, spec.ConfirmTimeout, progress)

	res.HostAfter, res.HostHeld, res.HostMoved = confirm.hostAfter, confirm.hostHeld, confirm.hostMoved
	res.ContainerAfter = confirm.containerAfter
	res.Confirmed, res.Reason = confirm.ok, confirm.reason

	if !confirm.ok {
		if confirm.hostMoved {
			// Named separately because it is not the same event. A tunnel that
			// does not forward is a feature failing; a host whose address moved
			// is this machine having been changed in the one way it must never
			// be, and whoever is watching needs to read that sentence rather
			// than infer it from two addresses.
			progress.emit("error", "REVERTING — THIS MACHINE'S OWN EGRESS MOVED. That is a failed apply regardless of what the container is doing, and it is the exact failure this path was built to make impossible.")
		}
		progress.emit("warning", "REVERTING — a route that cannot be confirmed is the failure this sequence exists to prevent, not a partial success.")
		if err := revertExternalRoute(ctx, runner, *plan, progress); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("error", "the revert itself FAILED (%v). The dead-man's switch is still armed and fires at %s; leaving it armed on purpose.", err, armed.ExpiresAt)
			return res, fmt.Errorf("the external route could not be confirmed and the revert failed: %s", confirm.reason)
		}
		res.Reverted = true
		if _, err := Disarm(); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("warning", "the route was reverted but the dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
		}
		return res, fmt.Errorf("the external route was NOT confirmed and has been reverted: %s", confirm.reason)
	}

	if _, err := Disarm(); err != nil {
		res.DeadmanStillArmed = true
		return res, fmt.Errorf("egress was confirmed, but the dead-man's switch could not be stood down (%w) — it will revert this route at %s", err, armed.ExpiresAt)
	}
	progress.emit("info", "container egress confirmed as %s with the host held at %s; dead-man's switch stood down.", res.ContainerAfter, res.HostAfter)

	// Persisted LAST and only on success, because this record is what Reassert
	// re-applies on a timer. A record written for an apply that did not
	// confirm would be re-asserted forever.
	return res, saveExternalRouteState(*plan)
}

// ExternalUnroute removes the rule and the exclusions and reports where the
// container's traffic goes now.
//
// Deliberately NOT gated by any of the refusals above, for the same reason
// ClearExit is not: it is the way OFF the tunnel, and an undo that refuses is
// one that fails exactly when it is most needed.
func ExternalUnroute(ctx context.Context, spec ExternalRouteSpec, progress Progress) (ExternalRouteResult, error) {
	spec = spec.withDefaults()
	runner := spec.Runner
	if runner == nil {
		// Deliberately an error and not a default. This package cannot
		// construct a working runner on its own — the base shellout lives in
		// internal/ops, which imports this package — and PrivilegedRunner's
		// zero value has a nil Inner that panics on first use. A caller that
		// forgot to supply one has to be told, not handed something that dies
		// halfway through a route change.
		return ExternalRouteResult{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	// Undo what was RECORDED, not what a fresh plan would produce. The
	// container's IP moves whenever it is recreated, so re-planning here would
	// compute a rule that was never installed and leave the real one behind.
	plan, err := loadExternalRouteState()
	if err != nil || plan == nil {
		progress.emit("info", "no external route is recorded on this host; nothing to undo")
		return ExternalRouteResult{Reverted: true}, nil
	}
	res := ExternalRouteResult{Plan: *plan}

	if err := revertExternalRoute(ctx, runner, *plan, progress); err != nil {
		return res, err
	}
	res.Reverted = true
	if _, err := Disarm(); err != nil {
		progress.emit("warning", "the route was removed but a dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
	}
	if err := clearExternalRouteState(); err != nil {
		return res, err
	}

	after := measureNetnsEgress(ctx, runner, plan.Runtime, plan.ContainerID)
	res.ContainerAfter = after.IP
	if host, err := PublicIP(ctx); err == nil {
		res.HostAfter = host.IP
	}
	progress.emit("info", "external route removed — container egress is now %s", after.IP)
	return res, nil
}

// Reassert puts back whatever a rule flush took away, and is a no-op when
// nothing is recorded or nothing is missing.
//
// This is not defensive programming for a hypothetical. On the production bare
// metal `systemd-networkd` is restarted by the daily unattended apt upgrade and
// flushes every routing policy rule it does not own; the hub's own rules at
// priority 100-107 are missing right now for exactly that reason, on a
// container that has been up 15 hours without restarting. Routes inside table
// 200 survived that flush and the rules did not, so this checks both but
// expects to be replacing the rule.
//
// It returns what it had to put back, so a caller can log a flush having
// happened rather than silently papering over it.
func Reassert(ctx context.Context, r Runner) ([]string, error) {
	plan, err := loadExternalRouteState()
	if err != nil || plan == nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("no command runner was supplied to re-assert the external route for %s", plan.Container)
	}
	restored, updated, gone, err := reassertPlan(ctx, r, *plan)
	if err != nil {
		return restored, err
	}
	switch {
	case gone:
		// The container this record was built for no longer exists. reassertPlan
		// already took the rule and its exclusions out; clearing the record is
		// what keeps the NEXT pass from doing this same work forever, and — the
		// part that actually matters — keeps a stale record from ever being
		// re-read as if it still described something real.
		if cerr := clearExternalRouteState(); cerr != nil {
			return restored, fmt.Errorf("container %s no longer resolves, and the stale external-route record could not be cleared: %w", plan.Container, cerr)
		}
	case updated != nil:
		// Same container, a new address. Persisted via state.Update
		// (load-modify-save) so this write cannot clobber whatever else the
		// daemon recorded between the read above and now — see state.Update's
		// own comment for the race this replaced.
		if serr := saveExternalRouteState(*updated); serr != nil {
			return restored, fmt.Errorf("resolved a new address (%s) for %s but could not persist it: %w", updated.SourceIP, plan.Container, serr)
		}
	}
	return restored, nil
}

// reassertPlan is Reassert with the state read (and the state write) already
// factored out, which is what makes the behaviour testable without a state
// file on the machine running `go test`: it only ever talks to Runner.
//
// It re-resolves the container by its recorded ContainerID through the
// runtime on EVERY pass, not only when the rule is missing — the same lookup
// PlanExternalRoute used to build this record in the first place. That is the
// actual fix here, not a defensive extra: a rule that matches the RECORDED
// SourceIP can be sitting untouched in the kernel while that address now
// belongs to a different container than the one this record was built for,
// because Docker handed the old address to whatever it started next.
// ruleInstalled alone cannot see that — it only proves a rule for the old
// address still exists, never that the old address still means what the
// record says it does. One inspect per ReassertInterval pass is the cost of closing that,
// and ReassertInterval's own comment already treats a cheap check on a short
// interval as the entire point of this loop.
//
// It returns, instead of writing anything itself: what it had to restore,
// the updated plan when the address moved (nil when it didn't), and whether
// the container is gone. Reassert turns that into exactly one state write.
func reassertPlan(ctx context.Context, r Runner, plan ExternalRoutePlan) (restored []string, updated *ExternalRoutePlan, gone bool, err error) {
	rt := ContainerRuntime{Name: plan.Runtime}
	_, ip, resolveErr := resolveContainerSource(ctx, r, rt, plan.ContainerID)
	if resolveErr != nil {
		// The container this rule was built for no longer resolves under the
		// id that was recorded — recreated, or removed outright. Putting the
		// rule back, or leaving it in place, would keep a /32 pointed at an
		// address any other container on this Docker network is free to
		// receive next, silently handing it this tunnel. Take the rule and its
		// exclusions out; there is nothing left here to reassert.
		if ok, rerr := ruleInstalled(ctx, r, plan); rerr == nil && ok {
			if _, err := r.Run(ctx, "ip", plan.ruleArgs("del")...); err != nil {
				return restored, nil, false, fmt.Errorf("container %s (%s) no longer resolves (%v), and the orphaned rule for %s could not be removed: %w", plan.Container, plan.ContainerID, resolveErr, plan.SourceIP, err)
			}
			restored = append(restored, "removed orphaned rule from "+plan.SourceIP+"/32 ("+plan.Container+" no longer exists)")
		}
		for _, prefix := range plan.Exclusions {
			ok, rerr := routeInstalled(ctx, r, plan, prefix)
			if rerr != nil || !ok {
				continue
			}
			if _, err := r.Run(ctx, "ip", plan.excludeArgs("del", prefix)...); err != nil {
				return restored, nil, false, fmt.Errorf("container %s no longer resolves, and the orphaned exclusion %s could not be removed: %w", plan.Container, prefix, err)
			}
			restored = append(restored, "removed orphaned exclusion "+prefix)
		}
		return restored, nil, true, nil
	}

	if ip != plan.SourceIP {
		// Same container id, a new IPAM address — a network reconnect, or a
		// recreate that happened to keep the id. PlanExternalRoute proves this
		// invariant on the initial apply; a reassert re-resolving to a new
		// address has to prove it again before installing anything, or a
		// container that migrated to host networking would route the host
		// itself — exactly the failure this invariant exists to prevent.
		if err := mustNotBeThisHost(ctx, r, ip); err != nil {
			return restored, nil, false, fmt.Errorf("refusing to re-assert %s at its new address: %w", plan.Container, err)
		}
		// The old rule, if it is still there, now matches whoever inherited
		// that address, not this container, so it has to come out before the
		// new one goes in; there must be no window with both installed.
		if ok, rerr := ruleInstalled(ctx, r, plan); rerr == nil && ok {
			if _, err := r.Run(ctx, "ip", plan.ruleArgs("del")...); err != nil {
				return restored, nil, false, fmt.Errorf("could not remove the stale rule for %s before re-asserting the new address %s: %w", plan.SourceIP, ip, err)
			}
		}
		next := plan
		next.SourceIP = ip
		restored = append(restored, "container "+plan.Container+" moved to "+ip+" — record updated")
		plan = next
		updated = &next
	}

	present, perr := ruleInstalled(ctx, r, plan)
	if perr != nil {
		return restored, updated, false, perr
	}
	if !present {
		if _, err := r.Run(ctx, "ip", plan.ruleArgs("add")...); err != nil {
			return restored, updated, false, fmt.Errorf("could not re-assert the external route rule for %s: %w", plan.Container, err)
		}
		restored = append(restored, "ip rule from "+plan.SourceIP+"/32")
	}
	for _, prefix := range plan.Exclusions {
		ok, err := routeInstalled(ctx, r, plan, prefix)
		if err != nil || ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.excludeArgs("add", prefix)...); err != nil {
			return restored, updated, false, fmt.Errorf("could not re-assert the exclusion %s: %w", prefix, err)
		}
		restored = append(restored, "exclusion "+prefix)
	}
	return restored, updated, false, nil
}

// ReassertInterval is how often the daemon re-checks the rule.
//
// The flush this defends against is rare — daily, when the unattended apt
// upgrade restarts systemd-networkd — but the check is two `ip show` reads and
// the failure it catches is silent: a flushed rule does not break the
// container, it quietly puts it back on the host's own egress, so nothing
// anywhere reports an error and the feature is simply not in force any more.
// A cheap check on a short interval is the only thing that turns that back
// into something observable.
const ReassertInterval = 30 * time.Second

// ReassertLoop re-asserts the recorded external route until ctx is cancelled,
// reporting each time it actually had to put something back.
//
// It runs one pass immediately: a host coming back from a reboot has an empty
// rule table and a state file that still records a route, and waiting a full
// interval to notice would be a gap for no reason. Errors are reported and
// never fatal — the same bargain firewall.SelfHeal makes at the same point in
// startup, and for the same reason: a self-heal that could not run must not
// stop this process from linking at all.
func ReassertLoop(ctx context.Context, r Runner, report func(restored []string, err error)) {
	pass := func() {
		restored, err := Reassert(ctx, r)
		if report != nil && (len(restored) > 0 || err != nil) {
			report(restored, err)
		}
	}
	pass()
	ticker := time.NewTicker(ReassertInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass()
		}
	}
}

// --- resolution -------------------------------------------------------------

// resolveContainerSource turns a container name into (id, single IPv4).
//
// It asks the RUNTIME rather than accepting an address from a caller, and that
// is the load-bearing part of this whole file: an address that came out of
// `inspect` belongs to a container that exists on this host right now. The
// correlation that makes this usable from a control plane was measured on
// 2026-09-02 — the hostname host A reports for itself (`e91aacf5a3a3`) IS the
// container id host B knows it by — so a caller can name the host it means and
// never has to send an IP that might have been recycled.
func resolveContainerSource(ctx context.Context, r Runner, rt ContainerRuntime, name string) (string, string, error) {
	const format = "{{.Id}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"
	out, err := r.Run(ctx, rt.Name, "inspect", "-f", format, name)
	if err != nil {
		return "", "", fmt.Errorf("container %q could not be resolved on this host (%s inspect: %v) — refusing to guess an address, because this rule keys on runtime IPAM that moves whenever a container is recreated", name, rt.Name, err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 {
		return "", "", fmt.Errorf("container %q exists but reports no IPv4 address, so there is nothing to anchor a rule on", name)
	}
	id := fields[0]
	var ips []string
	for _, f := range fields[1:] {
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			ips = append(ips, f)
		}
	}
	switch len(ips) {
	case 0:
		return "", "", fmt.Errorf("container %q exists but reports no IPv4 address, so there is nothing to anchor a rule on", name)
	case 1:
		return id, ips[0], nil
	default:
		// Routing one of several attachments would move some of that
		// container's traffic and not the rest, which is worse than not doing
		// it: the egress would depend on which network a given connection
		// happened to use.
		return "", "", fmt.Errorf("container %q is attached to %d networks (%s) and this path routes exactly one source address — refusing rather than picking one and moving only part of its traffic", name, len(ips), strings.Join(ips, ", "))
	}
}

// mustBeSingleHost is the /16 guard, as an assertion rather than a comment.
//
// Measured on the production bare metal 2026-09-02: 172.18.0.0/16 carries
// aw-backend, aw-caddy, aw-headscale, aw-derper, aw-sandbox and
// agents-platform-multitenant alongside the workspace's own container. A rule
// written `from 172.18.0.0/16` would put all of production on a residential
// line in one command, so the only address shape this file accepts is a single
// host.
func mustBeSingleHost(ip string) error {
	if strings.Contains(ip, "/") {
		return fmt.Errorf("refusing the source %q: this path installs a /32 rule and nothing wider, because the container networks on this host are shared with production services that must not be routed", ip)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("refusing the source %q: it is not a single IPv4 address", ip)
	}
	return nil
}

// mustNotBeThisHost proves the rule excludes the machine, rather than assuming
// it. A container address that is also one of this host's own addresses would
// route the host, which is the failure the invariant exists to prevent.
func mustNotBeThisHost(ctx context.Context, r Runner, ip string) error {
	out, err := r.Run(ctx, "ip", "-4", "-o", "addr", "show")
	if err != nil {
		return fmt.Errorf("could not enumerate this host's own addresses, so it could not be proven that %s is not one of them — refusing: %w", ip, err)
	}
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, ip+"/") || f == ip {
				return fmt.Errorf("refusing to route %s: it is one of THIS MACHINE's own addresses, and moving it would move the host's egress — the exact failure this feature was rewritten to make impossible", ip)
			}
		}
	}
	return nil
}

// tableDefault reads the default route out of the tunnel's table, and refuses
// an empty one. An `ip rule` pointing at a table with no default does not fall
// through to main; it black-holes every packet that matches.
func tableDefault(ctx context.Context, r Runner, table int) (via, dev string, err error) {
	out, err := r.Run(ctx, "ip", "route", "show", "table", strconv.Itoa(table))
	if err != nil {
		return "", "", fmt.Errorf("routing table %d could not be read, so it cannot be proven to carry a working default route: %w", table, err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "via":
				via = f[i+1]
			case "dev":
				dev = f[i+1]
			}
		}
		if dev != "" {
			return via, dev, nil
		}
	}
	return "", "", fmt.Errorf("routing table %d carries no default route, so a rule pointing at it would black-hole the container instead of tunnelling it — refusing. On this host that table belongs to aw-vpn-hub; check that the hub is up", table)
}

// mainDefault is where the exclusions are sent instead of into the tunnel.
func mainDefault(ctx context.Context, r Runner) (gw, dev string, err error) {
	out, err := r.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return "", "", fmt.Errorf("could not read this host's own default route, which is where the exclusions have to point: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "via":
				gw = f[i+1]
			case "dev":
				dev = f[i+1]
			}
		}
		if gw != "" && dev != "" {
			return gw, dev, nil
		}
	}
	return "", "", fmt.Errorf("this host has no default route with both a gateway and a device, so there is nowhere to send the exclusions")
}

// planExternalExclusions is the answer to the one defect this path actually
// has, and it was measured rather than predicted: with the rule in place ICMP
// passes, TCP passes, and UDP/53 does not — `nslookup` answers ";; connection
// timed out; no servers could be reached" because the query enters the tunnel
// and dies on the far side. Untreated, "the workspace leaves via the hub"
// becomes "the workspace has no DNS", which is indistinguishable from a total
// outage to whoever is using it.
//
// The fix is the same shape usexit.go already uses to hold the control plane
// outside the tunnel: /32 routes inside the tunnel's own table, pointing back
// at the main gateway, which beat that table's default.
//
// The list is MEASURED, never invented, and from two places because a
// container on a user-defined network does not see the real resolvers at all:
//
//   - the container's own /etc/resolv.conf. On the default bridge this is the
//     real uplink list (measured: 185.12.64.1, 185.12.64.2).
//   - this host's uplink resolvers. On a user-defined network the container
//     sees only Docker's embedded resolver at 127.0.0.11, which is loopback
//     inside its netns — but dockerd forwards those queries from that same
//     netns, so the packets still carry the container's source address and
//     still need the exclusion. Measured on aw-remote-host (172.18.0.4),
//     whose resolv.conf shows 127.0.0.11 and nothing else.
//
// Loopback and link-local are dropped: a /32 exclusion for 127.0.0.11 would be
// meaningless and a route for it on the main gateway would be wrong.
func planExternalExclusions(ctx context.Context, r Runner, rt ContainerRuntime, containerID, controlPlane string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
			return
		}
		prefix := ip + "/32"
		if seen[prefix] {
			return
		}
		seen[prefix] = true
		out = append(out, prefix)
	}

	if cat, err := r.Run(ctx, rt.Name, "exec", containerID, "cat", "/etc/resolv.conf"); err == nil {
		for _, ip := range parseNameservers(cat) {
			add(ip)
		}
	}
	if cat, err := r.Run(ctx, "cat", "/run/systemd/resolve/resolv.conf"); err == nil {
		for _, ip := range parseNameservers(cat) {
			add(ip)
		}
	}
	if cat, err := r.Run(ctx, "cat", "/etc/resolv.conf"); err == nil {
		for _, ip := range parseNameservers(cat) {
			add(ip)
		}
	}
	// The control plane rides the same reasoning as usexit.go's: the
	// management path that must survive is the one this link is on.
	for _, ip := range resolveControlPlaneIPs(ctx, controlPlane) {
		add(ip)
	}
	return out
}

func parseNameservers(resolvConf string) []string {
	var out []string
	for _, line := range strings.Split(resolvConf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// resolveControlPlaneIPs is best-effort by design: a control plane that cannot
// be resolved right now is a reason to say so, not a reason to refuse to route
// — the dead-man's switch is what covers the case where the pin was wrong.
func resolveControlPlaneIPs(ctx context.Context, base string) []string {
	host := strings.TrimSpace(base)
	if host == "" {
		return nil
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

// --- apply / revert ---------------------------------------------------------

func applyExternalRoute(ctx context.Context, r Runner, plan ExternalRoutePlan) error {
	for _, prefix := range plan.Exclusions {
		if ok, err := routeInstalled(ctx, r, plan, prefix); err == nil && ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.excludeArgs("add", prefix)...); err != nil {
			return fmt.Errorf("could not hold %s outside the tunnel, and routing the container without that would leave it without DNS: %w", prefix, err)
		}
	}
	// Idempotent on purpose: `ip rule add` happily installs a duplicate, and a
	// second identical rule is invisible in every symptom but impossible to
	// remove with one `del`.
	if ok, err := ruleInstalled(ctx, r, plan); err == nil && ok {
		return nil
	}
	if _, err := r.Run(ctx, "ip", plan.ruleArgs("add")...); err != nil {
		return fmt.Errorf("could not install the routing policy rule for %s: %w", plan.SourceIP, err)
	}
	return nil
}

// revertExternalRoute removes the rule FIRST. Order matters for the same
// reason it does in usexit.go's revert: if removing the exclusions then fails,
// the container is already off the tunnel rather than on it with half its pins
// gone.
func revertExternalRoute(ctx context.Context, r Runner, plan ExternalRoutePlan, progress Progress) error {
	var firstErr error
	// Loop rather than a single del: a flush-and-reassert race can leave two
	// identical rules, and one `del` would remove only one of them.
	for i := 0; i < 8; i++ {
		ok, err := ruleInstalled(ctx, r, plan)
		if err != nil || !ok {
			break
		}
		if _, err := r.Run(ctx, "ip", plan.ruleArgs("del")...); err != nil {
			firstErr = fmt.Errorf("could not remove the routing policy rule for %s: %w", plan.SourceIP, err)
			break
		}
	}
	for _, prefix := range plan.Exclusions {
		if ok, err := routeInstalled(ctx, r, plan, prefix); err == nil && !ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.excludeArgs("del", prefix)...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("could not remove the exclusion %s: %w", prefix, err)
		}
	}
	if firstErr == nil {
		progress.emit("info", "rule and exclusions removed; %s is back on this host's own egress", plan.Container)
	}
	return firstErr
}

func revertExternalAfterFailure(ctx context.Context, r Runner, plan ExternalRoutePlan, progress Progress) (reverted, stillArmed bool) {
	if err := revertExternalRoute(ctx, r, plan, progress); err != nil {
		progress.emit("error", "cleanup after a failed apply did not complete (%v) — leaving the dead-man's switch armed on purpose", err)
		return false, true
	}
	if _, err := Disarm(); err != nil {
		return true, true
	}
	return true, false
}

// externalRevertScript is the shell the dead-man's switch runs. Same contract
// as the tailscale one it sits beside: POSIX sh, every path already absolute,
// every privilege prefix already applied, and no reference to this binary —
// a self-referential revert dies with any update or partial write of the very
// tool that armed it.
func externalRevertScript(r Runner, plan ExternalRoutePlan) string {
	prefix := ""
	if p, ok := r.(PrivilegedRunner); ok {
		prefix = strings.TrimSuffix(p.CommandPrefix("ip"), "ip")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%sip %s || true\n", prefix, strings.Join(plan.ruleArgs("del"), " "))
	for _, ex := range plan.Exclusions {
		fmt.Fprintf(&b, "%sip %s || true\n", prefix, strings.Join(plan.excludeArgs("del", ex), " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func ruleInstalled(ctx context.Context, r Runner, plan ExternalRoutePlan) (bool, error) {
	out, err := r.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return false, fmt.Errorf("could not read this host's routing policy rules: %w", err)
	}
	want := plan.SourceIP
	table := strconv.Itoa(plan.Table)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// `ip rule show` prints "5399:\tfrom 172.18.0.4 lookup 200" — the /32
		// is dropped from a single-host source, so match the bare address.
		if strings.TrimSuffix(f[0], ":") == strconv.Itoa(plan.Priority) &&
			f[1] == "from" && strings.TrimSuffix(f[2], "/32") == want &&
			f[len(f)-1] == table {
			return true, nil
		}
	}
	return false, nil
}

func routeInstalled(ctx context.Context, r Runner, plan ExternalRoutePlan, prefix string) (bool, error) {
	out, err := r.Run(ctx, "ip", "route", "show", "table", strconv.Itoa(plan.Table))
	if err != nil {
		return false, err
	}
	bare := strings.TrimSuffix(prefix, "/32")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == prefix || f[0] == bare) {
			return true, nil
		}
	}
	return false, nil
}

// --- confirmation -----------------------------------------------------------

type externalConfirmSpec struct {
	hostBefore      string
	containerBefore string
	expected        string
}

type externalConfirmation struct {
	hostAfter      string
	hostHeld       bool
	hostMoved      bool
	containerAfter string
	ok             bool
	reason         string
}

// confirmExternal asserts BOTH halves, and keeps trying until the window runs
// out because a fresh tunnel takes a few seconds to carry its first flow.
func confirmExternal(ctx context.Context, r Runner, plan ExternalRoutePlan, spec externalConfirmSpec, window time.Duration, progress Progress) externalConfirmation {
	deadline := time.Now().Add(window)
	var last externalConfirmation
	for attempt := 1; ; attempt++ {
		last = externalConfirmOnce(ctx, r, plan, spec)
		if last.ok || last.hostMoved || time.Now().After(deadline) {
			return last
		}
		progress.emit("info", "  attempt %d: %s — retrying", attempt, last.reason)
		select {
		case <-ctx.Done():
			return last
		case <-time.After(3 * time.Second):
		}
	}
}

func externalConfirmOnce(ctx context.Context, r Runner, plan ExternalRoutePlan, spec externalConfirmSpec) externalConfirmation {
	var c externalConfirmation

	// The host's address is checked FIRST and a move short-circuits the rest:
	// a container egress that looks right is meaningless if the machine came
	// with it.
	host, err := PublicIP(ctx)
	if err != nil {
		c.reason = fmt.Sprintf("this host's own public IP could not be re-measured (%v), so it cannot be proven the machine stayed put", err)
		return c
	}
	c.hostAfter = host.IP
	c.hostHeld = host.IP == spec.hostBefore
	c.hostMoved = !c.hostHeld
	if c.hostMoved {
		c.reason = fmt.Sprintf("THIS MACHINE's egress moved from %s to %s", spec.hostBefore, host.IP)
		return c
	}

	got := measureNetnsEgress(ctx, r, plan.Runtime, plan.ContainerID)
	c.containerAfter = got.IP
	if got.IP == "" {
		c.reason = fmt.Sprintf("the container's egress could not be measured through the new route (%s)", got.Error)
		return c
	}
	if spec.expected != "" {
		if got.IP != spec.expected {
			c.reason = fmt.Sprintf("the container is leaving via %s, not the expected %s", got.IP, spec.expected)
			return c
		}
		c.ok = true
		return c
	}
	if spec.containerBefore != "" && got.IP == spec.containerBefore {
		c.reason = fmt.Sprintf("the container is still leaving via %s — the rule is installed but nothing moved", got.IP)
		return c
	}
	c.ok = true
	return c
}

// measureNetnsEgress asks what the routed container's own egress is, by
// running the probe INSIDE that container's network namespace.
//
// This is the part that makes the confirmation exact rather than
// approximate. MeasureContainerEgress (containers.go) probes a NETWORK, so its
// probe gets a fresh address that this /32 rule does not match — it would
// faithfully report the host's egress no matter how well the rule worked.
// `--network container:<id>` shares the target's namespace and therefore its
// source address, so the probe is matched by the very rule being confirmed.
// Verified on the production bare metal 2026-09-02 against aw-remote-host.
//
// The container itself is never required to contain curl, wget or anything
// else, which matters here: the container this exists for has no `ip` and an
// empty dpkg database.
func measureNetnsEgress(ctx context.Context, r Runner, runtime, containerID string) ContainerEgressResult {
	res := ContainerEgressResult{Runtime: runtime, Network: "container:" + containerID}
	if runtime == "" || containerID == "" {
		res.Error = NoContainerRuntimeRefusal
		return res
	}
	args := []string{"run", "--rm", "--network", "container:" + containerID,
		"--entrypoint", "sh", ContainerProbeImage, "-c", containerEgressScript()}
	out, err := r.Run(ctx, runtime, args...)
	if err != nil {
		res.Error = fmt.Sprintf("probe container in the target's network namespace failed: %v: %s", err, strings.TrimSpace(out))
		return res
	}
	// Parsed by containers.go's own parser, not by a second one written here.
	// containerEgressScript emits a MARKED line ("AW_EGRESS <url> <ip>") so that
	// a page body which happens to contain an address cannot be mistaken for
	// the answer; a hand-rolled "first line that parses as an IP" reader
	// silently disagrees with that format, which is exactly what it did on the
	// first real run against this bare metal.
	via, ip := parseContainerEgress(out)
	if ip == "" {
		res.Error = "the probe ran but printed no address: " + strings.TrimSpace(out)
		return res
	}
	res.IP, res.Via = ip, via
	return res
}

// --- state ------------------------------------------------------------------

func saveExternalRouteState(plan ExternalRoutePlan) error {
	return mutateExternalRouteState(func(v *state.VPNState) {
		v.ExternalRoute = &state.ExternalRouteState{
			Container:   plan.Container,
			ContainerID: plan.ContainerID,
			SourceIP:    plan.SourceIP,
			Table:       plan.Table,
			Priority:    plan.Priority,
			Runtime:     plan.Runtime,
			TunnelDev:   plan.TunnelDev,
			MainGateway: plan.MainGateway,
			MainDev:     plan.MainDev,
			Exclusions:  plan.Exclusions,
			RoutedAt:    time.Now().UTC().Format(time.RFC3339),
		}
	})
}

func clearExternalRouteState() error {
	return mutateExternalRouteState(func(v *state.VPNState) { v.ExternalRoute = nil })
}

// mutateExternalRouteState goes through state.Update so the read and the write
// are one operation against the file. A load-modify-save spelled out here
// would be the same race the daemon already lost once — see state.Update's
// comment for the measurement.
func mutateExternalRouteState(apply func(*state.VPNState)) error {
	path, err := state.DefaultPath()
	if err != nil {
		return err
	}
	return state.Update(path, func(st *state.State) {
		if st.VPN == nil {
			st.VPN = &state.VPNState{}
		}
		apply(st.VPN)
	})
}

// loadExternalRouteState returns the recorded route, or nil when there is
// none. A missing or unreadable state file is "nothing recorded" rather than
// an error: Reassert runs on a timer and must not turn a fresh host into a log
// full of failures.
func loadExternalRouteState() (*ExternalRoutePlan, error) {
	path, err := state.DefaultPath()
	if err != nil {
		return nil, nil
	}
	st, err := state.Load(path)
	if err != nil || st.VPN == nil || st.VPN.ExternalRoute == nil {
		return nil, nil
	}
	e := st.VPN.ExternalRoute
	return &ExternalRoutePlan{
		Container:   e.Container,
		ContainerID: e.ContainerID,
		SourceIP:    e.SourceIP,
		Table:       e.Table,
		Priority:    e.Priority,
		Runtime:     e.Runtime,
		TunnelDev:   e.TunnelDev,
		MainGateway: e.MainGateway,
		MainDev:     e.MainDev,
		Exclusions:  e.Exclusions,
	}, nil
}
