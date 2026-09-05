// The vpn_external_route / vpn_external_unroute verbs — move ONE container on
// this host onto an external WireGuard tunnel this host already terminates,
// and move it back, triggered over the /link tunnel.
//
// This is the WRITE side that ops_vpn_external.go (external_tunnels on
// vpn_status) is the read side of. It is deliberately named apart from the
// vpn_external_up/down pair (ops_vpn_external_up.go): those DIAL a tunnel,
// this one only points a source at a tunnel that is already up. Conflating the
// two in one verb name would make an operator reading a run log unable to tell
// which of the two happened.
//
// It is also distinct from vpn_use_exit (ops_vpn_exit.go), which routes ALL of
// this host's containers onto a MESH gate. Nothing in this file touches
// usexit.go, containers.go or exit.go; the sequence it runs is
// internal/vpn.ExternalRoute, which is a sibling of UseExit rather than a
// caller of it.
//
// A CORRECTION, 2026-09-05. This header used to say that the container needing
// this (`aw-remote-host`/`e91aacf5a3a3`, where the `aw` workspace's siblings
// live) had no `ip`, no `wg` and no container runtime of its own, with an
// empty dpkg database, and that the apply therefore had to run on the machine
// hosting it. That was measured on 2026-09-02 and was true then. It is not
// true now: the image was rebuilt from this repo's own Dockerfile and the
// container recreated, and it carries /usr/sbin/ip, /usr/bin/wg,
// /usr/bin/wg-quick, /usr/sbin/openvpn, /usr/bin/podman and /usr/bin/tailscale.
//
// So the SAME-NETNS case — this verb answered by the very host being routed,
// which also owns the runtime and the tunnel — is now the simple case and the
// normal one. The cross-host case still works and is still supported (the
// caller names host A by the hostname A reports for itself, which IS the
// container id B knows it by), but it is the difficult case rather than the
// reason this verb exists here.
//
// Deliberately NOT in workspaceLifecycleVerbs (ops.go), for the same reason
// vpn_status is not: this needs a container runtime and an `ip` binary, never
// podman-the-workspace-runtime, and refusing it on a lean-linked host would be
// refusing it on the wrong grounds.
package ops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// externalRoute / externalUnroute are internal/vpn's entry points, indirected
// so a test can exercise this verb's argument handling, refusals and reply
// shape without moving the routing of whatever machine runs `go test` — the
// same reason useExit is indirected in ops_vpn_exit.go.
var (
	externalRoute   = vpn.ExternalRoute
	externalUnroute = vpn.ExternalUnroute
	planExternal    = vpn.PlanExternalRoute
)

// VPNExternalRoute points one container's egress at an external tunnel this
// host terminates, and reverts if it cannot prove that worked.
//
// args:
//
//	container   (string, required) the container whose egress moves, by name
//	            or id as THIS host's runtime knows it. Resolving it is also
//	            the safety property: the rule's source comes out of the
//	            runtime, so a machine that is not running it is refused and
//	            there is no input that widens into `from all`.
//	table       (number, optional) the routing table carrying the tunnel's
//	            default route. Default 200 (aw-vpn-hub's). A table with no
//	            default route is REFUSED rather than used, because a rule
//	            pointing at an empty table black-holes the container instead
//	            of falling through to main.
//	priority    (number, optional) the ip rule priority. Default 5399, which
//	            sits below tailscale's 5210-5270 band and above the hub's
//	            100-107.
//	expect_egress (string, optional) the public IP the tunnel should present.
//	            Given, confirmation is an exact match; omitted, confirmation
//	            is that the container's address CHANGED and the host's did not.
//	deadman_s   (number, optional) seconds before an unconfirmed route
//	            reverts itself. Default 120.
//	confirm_s   (number, optional) seconds to keep trying to confirm.
//	            Default 45, and it is clamped to stay inside deadman_s.
//	control_plane (string, optional) base URL whose addresses are held outside
//	            the tunnel. Defaults to the one this daemon already answers to.
//	plan        (bool, optional) resolve everything, report it, change NOTHING.
//
// Like vpn_use_exit, a host that CANNOT do this answers
// {"refused": true, "refusal": "<complete sentence>"} with a nil error: "this
// machine is not able to" and "this machine could not be asked" must not
// arrive in the same shape, or a screen cannot tell them apart.
func (h *Handler) VPNExternalRoute(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	container := strings.TrimSpace(stringArg(args, "container"))
	if container == "" {
		return nil, fmt.Errorf("container is required: it names the workload whose egress moves, and resolving it against this host's runtime is what proves the rule cannot match the machine itself")
	}
	controlPlane := strings.TrimSpace(stringArg(args, "control_plane"))
	if controlPlane == "" {
		controlPlane = strings.TrimSpace(h.Opts.ControlPlane)
	}

	spec := vpn.ExternalRouteSpec{
		Container:      container,
		Runner:         h.externalRunner(),
		Table:          intArg(args, "table"),
		Priority:       intArg(args, "priority"),
		ExpectEgress:   strings.TrimSpace(stringArg(args, "expect_egress")),
		Deadman:        secondsArg(args, "deadman_s", 120*time.Second),
		ConfirmTimeout: secondsArg(args, "confirm_s", 45*time.Second),
		ControlPlane:   controlPlane,
	}

	if boolArg(args, "plan", false) {
		plan, err := planExternal(ctx, spec)
		if err != nil {
			return nil, err
		}
		if plan.Refusal != "" {
			return map[string]any{"refused": true, "refusal": plan.Refusal, "plan": plan}, nil
		}
		return map[string]any{"planned": true, "plan": plan}, nil
	}

	res, err := externalRoute(ctx, spec, linkProgress(emit))
	payload := externalRoutePayload(res)
	if err != nil {
		// A scope refusal is not a failure of this call: it is this tool
		// declining, and it has to read that way to whoever is looking at the
		// screen. Everything else stays an error.
		if errorsIsScopeRefused(err) {
			payload["refused"] = true
			payload["refusal"] = res.Reason
			return payload, nil
		}
		return payload, err
	}
	return payload, nil
}

// VPNExternalUnroute removes the recorded external route.
//
// It takes no container argument on purpose: it undoes what was RECORDED, not
// what a fresh resolve would produce. The container's address is runtime IPAM
// and moves whenever it is recreated, so re-deriving the rule here would
// compute one that was never installed and leave the real one in place.
func (h *Handler) VPNExternalUnroute(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	res, err := externalUnroute(ctx, vpn.ExternalRouteSpec{Runner: h.externalRunner()}, linkProgress(emit))
	payload := externalRoutePayload(res)
	if err != nil {
		return payload, err
	}
	return payload, nil
}

// externalRoutePayload is the reply shape, and it carries the before/after
// pairs on the failure paths too — "it did not work" is worth much more next
// to the four addresses that prove it, and a control plane that stores this
// reply is the reader most likely to have missed the narration.
func externalRoutePayload(res vpn.ExternalRouteResult) map[string]any {
	return map[string]any{
		"container":        res.Plan.Container,
		"source_ip":        res.Plan.SourceIP,
		"table":            res.Plan.Table,
		"priority":         res.Plan.Priority,
		"tunnel_dev":       res.Plan.TunnelDev,
		"exclusions":       res.Plan.Exclusions,
		"host_before":      res.HostBefore,
		"host_after":       res.HostAfter,
		"host_held":        res.HostHeld,
		"host_moved":       res.HostMoved,
		"container_before": res.ContainerBefore,
		"container_after":  res.ContainerAfter,
		"confirmed":        res.Confirmed,
		"reverted":         res.Reverted,
		"reason":           res.Reason,

		"deadman_expires_at":  res.DeadmanExpiresAt,
		"deadman_still_armed": res.DeadmanStillArmed,
	}
}

func errorsIsScopeRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), vpn.ErrScopeRefused.Error())
}

// externalRunner is the privileged shellout this path needs. Same bargain as
// every other privileged WireGuard/tailscale call in this package: `sudo -n`
// never prompts, so a host with neither root nor a NOPASSWD entry fails
// immediately and loudly instead of hanging on a password prompt nobody is
// watching. Never PrivilegedRunner's zero value — its Inner is nil and panics.
func (h *Handler) externalRunner() vpn.Runner {
	host := vpn.Probe()
	return vpn.PrivilegedRunner{Inner: h.runner(), Sudo: host.OS != "darwin" && host.UID != 0}
}

// intArg reads an optional numeric argument. JSON numbers arrive as float64
// over the link, so both forms are accepted rather than one of them silently
// reading as zero and taking a default the caller did not ask for.
func intArg(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
