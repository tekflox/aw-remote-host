// The vpn_advertise_exit verb — make THIS host offer itself as an exit gate,
// or stop offering.
//
// The half a mesh could not do. Advertising was only ever reachable at
// ENROLMENT (AW_VPN_ADVERTISE_EXIT on a bootstrap run), so a node already on
// the mesh had no way to start, and on 2026-08-26 this account's mesh had
// exactly one gate as a direct result: the only node anyone had thought to
// ask for at the moment it joined.
//
// THIS VERB IS ONLY HALF OF A GATE, deliberately, and the caller has to know
// it. A route this node advertises forwards nothing until a control-plane
// admin approves it — `offers_exit` in the reply is tailscale's own
// ExitNodeOption and is normally FALSE right after a successful advertise.
// That is not a failure and must not be reported as one; it is the control
// plane's turn. aw-backend's `offer_exit_gate` does both halves and withdraws
// this one if its own fails, because a node advertising a route nobody
// approved looks armed and forwards nothing — which is the exact silent
// failure the whole Networking screen exists to remove.
//
// UNLIKE vpn_use_exit, this is safe to arrive over the /link tunnel with no
// ceremony at all: it does not touch this machine's default route. That is
// measured either side of the change rather than asserted — see
// internal/vpn/advertise.go.
//
// Deliberately NOT in workspaceLifecycleVerbs (ops.go), same as every other
// vpn_* verb: it needs tailscale and sysctl, never podman, and a lean-linked
// laptop is exactly the kind of machine somebody wants to turn into a gate.
package ops

import (
	"context"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// advertiseExit is internal/vpn's entry point, indirected so a test can
// exercise this verb's argument handling and reply shape without touching the
// sysctls or the tailscale prefs of whatever machine runs `go test`.
var advertiseExit = vpn.Advertise

// VPNAdvertiseExit offers this host as an exit gate for the rest of the mesh,
// or withdraws the offer.
//
// args:
//
//	advertise  (bool, optional, default true) true to offer, false to stop.
//	           One verb rather than two because the states are exclusive and
//	           the caller always knows which it wants — and because a
//	           `vpn_withdraw_exit` would be a second copy of the same
//	           read-back and route-invariant checks.
//
// A host that CANNOT serve as a gate answers {"refused": true, "refusal":
// "<complete sentence>"} with a nil error — the same shape vpn_bootstrap and
// vpn_use_exit use, so a screen can tell "this machine is not able to" apart
// from "this machine could not be asked". Refusals are the host's own
// sentence; nothing above it composes a better one.
//
// `warning` is the third answer. A WSL2 distro may serve as a gate AND sends
// everything through another layer of Windows NAT it does not control, so
// permission travels with its price and the control plane shows the price
// before anyone commits to it.
func (h *Handler) VPNAdvertiseExit(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	on := boolArg(args, "advertise", true)

	elig := probeEligibility()
	payload := eligibilityPayload(elig)

	bin := lookupTailscale()
	if bin == "" {
		// Not "cannot be a gate" — "is not on the mesh at all". Naming the
		// difference is what stops a screen telling somebody to fix their
		// kernel when what they need is to enrol.
		return map[string]any{
			"eligibility": payload,
			"refused":     true,
			"refusal": "the tailscale CLI is not installed on this host, so there is nothing " +
				"here to advertise a route. Enrol it in the mesh first.",
		}, nil
	}
	runner := tailscaleRunner{inner: h.runner(), bin: bin}
	priv := vpn.PrivilegedRunner{Inner: runner, Sudo: elig.Host.UID != 0}

	res, err := advertiseExit(ctx, runner, priv, elig, on, func(level, message string) {
		emit(level, "vpn", message)
	})
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"eligibility": payload,
		"refused":     res.Refused,
		"refusal":     res.Refusal,
		"warning":     res.Warning,
		"advertising": res.Advertising,
		// Read back from tailscale, not inferred: advertised AND approved.
		// False here right after advertising is the normal, correct answer.
		"offers_exit":  res.OffersExit,
		"node_name":    res.NodeName,
		"login_server": res.LoginServer,
		"forwarding":   res.Forwarding,
		// Offering is not using. Both measurements travel out, and the
		// boolean is derived from them here rather than being a claim: two
		// empty strings mean "not measured", which is not evidence of a
		// change and is not reported as one.
		"default_route_before":    res.RouteBefore,
		"default_route_after":     res.RouteAfter,
		"default_route_unchanged": res.RouteUnchanged(),
	}
	return out, nil
}
