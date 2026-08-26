// The vpn_use_exit / vpn_clear_exit verbs — move THIS host's default route
// onto a mesh exit gate, and move it back, triggered over the /link tunnel
// instead of by a human typing `aw-remote-host vpn use-exit`.
//
// This file decides WHEN the sequence may run and WHAT to say about the
// outcome. The sequence itself — measure egress, arm the dead-man's switch,
// pin the exclusions, move the route, confirm through the NEW route, revert
// anything unconfirmed — is internal/vpn's UseExit, the same function the CLI
// calls. That is deliberate and it is the whole reason the sequence was moved
// out of cmd/: it is the safety mechanism, and a second copy of it reachable
// only from the control plane would be the copy nobody exercises by hand and
// the one that strands a machine.
//
// THE OBVIOUS OBJECTION, answered: this verb arrives over the very tunnel it
// is about to put at risk. If the gate does not forward, the reply to this
// call cannot come back. That is survivable here and only here, because of
// the order internal/vpn/usexit.go runs in — the dead-man's switch is armed
// BEFORE the route moves, so a caller that never hears back still gets its
// host back, and the control plane's exclusion is pinned outside the tunnel
// so the tunnel itself normally survives. Proven on a lab node on 2026-08-25
// by killing the tool with SIGKILL mid-switch: exclusions gone, selection
// cleared, internet back in ~20s. A verb without that ordering behind it
// would have no business existing.
//
// Deliberately NOT in workspaceLifecycleVerbs (ops.go), for the same reason
// vpn_status is not: this needs tailscale and `ip`, never podman, and a
// lean-linked host is exactly the kind of machine most likely to be on the
// mesh.
package ops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// useExit / clearExit are internal/vpn's entry points, indirected so a test
// can exercise this verb's real argument handling, refusals and reply shape
// without moving the default route of whatever machine runs `go test`.
var (
	useExit   = vpn.UseExit
	clearExit = vpn.ClearExit
)

// VPNUseExit routes this host — and every container on it — out through a
// mesh peer, and reverts if it cannot prove that worked.
//
// args:
//
//	node            (string, required) the gate: a peer name, mesh name or
//	                mesh IP. Refused unless that peer OFFERS an exit route
//	                and is online — see vpn.ResolveExitPeer, which is where
//	                "advertised but not approved by headscale" is told apart
//	                from "never advertised at all", because the two need
//	                different people to fix them.
//	control_plane   (string, optional) base URL whose address is pinned
//	                outside the tunnel and whose reachability is part of the
//	                confirmation. Defaults to the control plane this daemon
//	                already answers to, which is the honest choice: the
//	                management path that must survive is the one this link
//	                is riding on, not whichever URL a caller names.
//	expect_egress   (string, optional) the public IP the gate should present.
//	                Given, confirmation is an exact match; omitted,
//	                confirmation is that the public IP CHANGED.
//	exclude         ([]string, optional) extra IPv4 addresses/CIDRs to keep
//	                outside the tunnel.
//	deadman_s       (number, optional) seconds before an unconfirmed
//	                selection reverts itself. Default 120.
//	confirm_s       (number, optional) seconds to keep trying to confirm.
//	                Default 45, and it must stay inside deadman_s.
//	persist_across_reboot (bool, optional) skip the boot guard. The `ip rule`
//	                exclusions do not survive a reboot and a tailscale
//	                selection does, so this is the dangerous option.
//	plan            (bool, optional) resolve the gate and the exclusions,
//	                report them, and change NOTHING.
//
// Like vpn_bootstrap, a host that CANNOT do this answers
// {"refused": true, "refusal": "<complete sentence>"} with a nil error: "this
// machine is not able to" and "this machine could not be asked" must not
// arrive in the same shape, or a screen cannot tell them apart.
func (h *Handler) VPNUseExit(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	node := strings.TrimSpace(stringArg(args, "node"))
	if node == "" {
		return nil, fmt.Errorf("node is required: it names the mesh peer whose exit route this host's default route should be moved onto")
	}
	controlPlane := strings.TrimSpace(stringArg(args, "control_plane"))
	if controlPlane == "" {
		controlPlane = strings.TrimSpace(h.Opts.ControlPlane)
	}

	elig := probeEligibility()
	payload := eligibilityPayload(elig)
	if refusal := exitSelectionRefusal(elig); refusal != "" {
		emit("warning", "vpn", "not selecting an exit gate — "+refusal)
		return map[string]any{
			"eligibility": payload,
			"applied":     false,
			"changed":     false,
			"refused":     true,
			"refusal":     refusal,
		}, nil
	}

	spec := vpn.UseExitSpec{
		Runner:              h.runner(),
		ControlPlane:        controlPlane,
		Node:                node,
		ExpectEgress:        strings.TrimSpace(stringArg(args, "expect_egress")),
		Exclude:             stringsArg(args, "exclude"),
		Deadman:             secondsArg(args, "deadman_s", vpn.DefaultDeadmanTimeout),
		ConfirmTimeout:      secondsArg(args, "confirm_s", vpn.DefaultConfirmTimeout),
		PersistAcrossReboot: boolArg(args, "persist_across_reboot", false),
	}

	if boolArg(args, "plan", false) {
		plan, err := vpn.PlanUseExit(ctx, spec)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"eligibility":        payload,
			"applied":            false,
			"changed":            false,
			"refused":            false,
			"plan":               true,
			"gate":               plan.Gate.Name,
			"gate_ip":            plan.GateIP,
			"gate_path":          plan.Gate.PathDescription(),
			"exclusions":         exclusionPayload(plan.Exclusions.Exclusions),
			"control_plane":      controlPlane,
			"control_plane_ips":  plan.Exclusions.ControlPlaneIPs,
			"control_plane_host": plan.Exclusions.ControlPlaneHost,
		}, nil
	}

	res, err := useExit(ctx, spec, linkProgress(emit))
	out := useExitPayload(payload, res)
	if err != nil {
		// NOT a verb-level error. The route has already been put back by the
		// time this returns (or the dead-man's switch is about to do it, and
		// deadman_still_armed says so), and the before/after addresses in the
		// payload are the evidence for why it did not stick. Collapsing that
		// into a bare error would throw away the only part a human can act on.
		out["error"] = err.Error()
		emit("error", "vpn", err.Error())
		return out, nil
	}
	return out, nil
}

// VPNClearExit puts the default route back: clear the selection, remove the
// exclusions, remove the boot guard, and report the egress IP that results.
//
// It takes no arguments. There is deliberately no "clear only if the gate is
// X" — this is the undo path, and an undo that can refuse on a precondition
// is an undo that fails exactly when it is most needed.
func (h *Handler) VPNClearExit(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	payload := eligibilityPayload(probeEligibility())

	res, err := clearExit(ctx, vpn.ClearExitSpec{Runner: h.runner()}, linkProgress(emit))
	out := map[string]any{
		"eligibility":        payload,
		"cleared":            err == nil,
		"exclusions_removed": res.ExclusionsRemoved,
		"deadman_stood_down": res.DeadmanStoodDown,
		"egress":             res.Egress,
		"egress_via":         res.EgressVia,
	}
	if res.EgressError != "" {
		out["egress_error"] = res.EgressError
	}
	if err != nil {
		out["error"] = err.Error()
		emit("error", "vpn", err.Error())
	}
	return out, nil
}

// exitSelectionRefusal is the "this host cannot be asked to do this at all"
// gate, checked before anything is resolved so a refusal costs no DNS lookup
// and no tailscale call.
//
// It is narrower than the errors PlanUseExit raises on purpose: only the
// verdicts that are about THIS MACHINE'S capabilities belong in a refusal.
// "no peer by that name" or "the control plane will not resolve" are caller
// or environment problems and stay errors, the same split vpn_bootstrap makes
// between a refusal and a missing login_server.
func exitSelectionRefusal(e vpn.Eligibility) string {
	if !e.CanEnroll {
		return e.EnrollRefusal
	}
	if e.Host.OS != "linux" {
		return fmt.Sprintf("selecting an exit gate changes this machine's default route, and the route exclusions that keep it manageable while that is true are implemented with `ip rule`, which is Linux-only. %s is deliberately not claimed rather than half-supported.", e.Host.OS)
	}
	if e.Host.TailscalePath == "" {
		return "tailscale is not installed on this host, so there is no mesh to route through — enrol it first."
	}
	return ""
}

// linkProgress forwards internal/vpn's narration to the control plane as link
// events. It matters more here than on the CLI: this is a route change being
// watched from somewhere else entirely, and the events are the only thing
// telling a waiting operator whether the route has moved yet.
func linkProgress(emit Emit) vpn.Progress {
	return func(level, message string) {
		emit(level, "vpn", message)
	}
}

func useExitPayload(eligibility map[string]any, res vpn.UseExitResult) map[string]any {
	return map[string]any{
		"eligibility": eligibility,
		"refused":     false,
		// `applied` is the honest verb-level answer: the gate is in force
		// only if egress was CONFIRMED through the new route. An interface
		// being up has never been enough here.
		"applied":    res.Confirmed,
		"changed":    res.Confirmed,
		"confirmed":  res.Confirmed,
		"reverted":   res.Reverted,
		"reason":     res.Reason,
		"gate":       res.Gate,
		"gate_ip":    res.GateIP,
		"exclusions": exclusionPayload(res.Exclusions),
		// The pair the whole feature exists to show. Empty means NOT
		// MEASURED, never "unchanged" — the caller must render an absent
		// address as unknown rather than reusing the last one it saw.
		"egress_before":       res.EgressBefore,
		"egress_before_via":   res.EgressBeforeVia,
		"egress_after":        res.EgressAfter,
		"egress_after_via":    res.EgressAfterVia,
		"expect_egress":       res.Expected,
		"default_device":      res.DefaultDevice,
		"control_plane_ok":    res.ControlPlaneOK,
		"deadman_expires_at":  res.DeadmanExpiresAt,
		"deadman_still_armed": res.DeadmanStillArmed,
		"boot_guard":          res.BootGuard,
	}
}

func exclusionPayload(ex []vpn.Exclusion) []map[string]any {
	out := make([]map[string]any, 0, len(ex))
	for _, e := range ex {
		out = append(out, map[string]any{"prefix": e.Prefix, "reason": e.Reason})
	}
	return out
}

// stringsArg reads a list of strings out of a JSON-decoded argument. Both
// []any (what encoding/json produces) and []string (what a Go caller passes)
// are accepted; anything else is ignored rather than erroring, matching how
// every other arg helper here degrades to its default.
func stringsArg(args map[string]any, key string) []string {
	switch v := args[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// secondsArg reads a duration given in seconds. Seconds rather than a Go
// duration string because this arrives as JSON from a web UI, where a number
// is unambiguous and "2m0s" is a parsing problem waiting to happen.
func secondsArg(args map[string]any, key string, def time.Duration) time.Duration {
	if s := floatArg(args, key, 0); s > 0 {
		return time.Duration(s * float64(time.Second))
	}
	return def
}

// VPNPublicIP measures the address this host actually leaves the internet
// from, right now. Read-only: it changes nothing and needs no privilege.
//
// It exists as its own verb rather than as a field on vpn_status because
// vpn_status is asked of EVERY host in an account at once, in parallel, on
// every render of the Networking screen — and this is an outbound HTTPS
// request that takes up to 8s against a host whose network is broken, which
// is exactly the host whose row is most interesting. Bolting it onto the
// status fan-out would make the whole screen wait for the worst-behaved
// machine on the account.
//
// The honesty contract is the monolith's `public_ip()` (agentic-workspace,
// src/api/vpn_manager.py), and it is the reason this verb is worth having at
// all: a lookup that fails returns {"ip": "", "error": "<why>"} and NEVER a
// remembered address. A screen showing yesterday's egress IP as if it were
// today's is worse than a screen showing none — this whole feature exists so
// somebody can trust that number after flipping a route.
//
// vpn.PublicIP does the measuring, on a FRESH connection with keep-alives
// disabled. That is not a detail: a pooled connection opened before the route
// moved answers over the old path and reports a change that never happened,
// which is the specific way this kind of check lies.
func (h *Handler) VPNPublicIP(ctx context.Context) (map[string]any, error) {
	egress, err := vpn.PublicIP(ctx)
	if err != nil {
		return map[string]any{"ip": "", "via": "", "error": err.Error()}, nil
	}
	return map[string]any{"ip": egress.IP, "via": egress.Via}, nil
}
