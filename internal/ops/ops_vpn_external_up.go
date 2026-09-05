// The vpn_external_up / vpn_external_down verbs — DIAL an external WireGuard
// tunnel on this host, and take it back down, triggered over the /link tunnel.
//
// Deliberately named apart from the vpn_external_route / vpn_external_unroute
// pair beside it, and the distinction is the whole point: these two bring a
// tunnel UP, those two point a container AT one that is already up. Conflating
// them in a verb name would make an operator reading a run log unable to tell
// which of the two happened, and they fail in completely different ways.
//
// The sequence that makes this safe — validate, discover, pre-pull, arm, dial,
// build the table, confirm, revert — lives in internal/vpn/externalup.go, not
// here, because the CLI (`aw-remote-host vpn external-up`) asks for exactly the
// same thing and two copies of that sequence would drift. What is left in this
// file is what a link verb adds on top of it: reading the arguments, forwarding
// the narration as link events, and the refusal shape.
//
// Deliberately NOT in workspaceLifecycleVerbs (ops.go), for the same reason
// vpn_external_route is not: this needs `ip`, `wg-quick` and a container
// runtime, never podman-the-workspace-runtime, and refusing it on a lean-linked
// host would be refusing it on the wrong grounds.
package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// externalUp / externalDown are internal/vpn's entry points, indirected so a
// test can exercise this verb's argument handling, refusals and reply shape
// without dialling a tunnel on whatever machine runs `go test` — the same
// reason externalRoute is indirected beside it.
var (
	externalUp     = vpn.ExternalUp
	externalDown   = vpn.ExternalDown
	planExternalUp = vpn.PlanExternalUp
)

// VPNExternalUp brings an external WireGuard tunnel up on this host from a
// STRUCTURED profile, and tears it back down if it cannot prove it works.
//
// args:
//
//	profile      (object, required unless profile_path is given) the VPN
//	             profile as typed fields — type, iface, private_key, address,
//	             dns, mtu and a peer block. There is deliberately no field
//	             that can carry PostUp, PostDown, PreUp, PreDown, Table or
//	             FwMark, and UNKNOWN KEYS ARE REJECTED rather than ignored:
//	             wg-quick runs PostUp as root, so a config accepted as text
//	             would be a remote root shell. The .conf this tool runs is
//	             SYNTHESIZED from these fields and never supplied.
//	profile_path (string, optional) a path to the same JSON on disk, 0600,
//	             for a caller that would rather not put a private key in a
//	             link message.
//	iface        (string, optional) the interface to bring up. Overrides the
//	             profile's own; both default to wg0.
//	table        (number, optional) the routing table this tunnel's default
//	             is built in. Default 200, the same table
//	             vpn_external_route points a container at, so the two agree
//	             without anyone passing the number twice.
//	deadman_s    (number, optional) seconds before an unconfirmed dial tears
//	             itself down and flushes the table. Default 120.
//	confirm_s    (number, optional) seconds to keep trying to confirm.
//	             Default 45, clamped to stay inside deadman_s.
//	plan         (bool, optional) resolve everything, report it, change
//	             NOTHING.
//
// Like vpn_use_exit and vpn_external_route, a host that CANNOT do this answers
// {"refused": true, "refusal": "<complete sentence>"} with a nil error: "this
// machine is not able to" and "this machine could not be asked" must not arrive
// in the same shape, or a screen cannot tell them apart.
//
// Nothing in the reply carries key material — see vpn.ExternalUpResult.Payload.
func (h *Handler) VPNExternalUp(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	profile, warning, err := externalProfileArg(args)
	if err != nil {
		return nil, err
	}

	spec := vpn.ExternalUpSpec{
		Profile:        profile,
		Iface:          strings.TrimSpace(stringArg(args, "iface")),
		Table:          intArg(args, "table"),
		Deadman:        secondsArg(args, "deadman_s", 120*time.Second),
		ConfirmTimeout: secondsArg(args, "confirm_s", 45*time.Second),
		Runner:         h.externalRunner(),
	}

	if boolArg(args, "plan", false) {
		plan, err := planExternalUp(ctx, spec)
		if err != nil {
			return nil, err
		}
		payload := map[string]any{"plan": plan, "warning": warning}
		if plan.Refusal != "" {
			payload["refused"] = true
			payload["refusal"] = plan.Refusal
			return payload, nil
		}
		payload["planned"] = true
		return payload, nil
	}

	if warning != "" {
		emit("warning", "vpn", warning)
	}
	res, err := externalUp(ctx, spec, linkProgress(emit))
	payload := res.Payload()
	if warning != "" {
		payload["warning"] = warning
	}
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

// VPNExternalDown takes the recorded external tunnel back down.
//
// iface/table are accepted but are a FALLBACK only, used when nothing is
// recorded — it undoes what was RECORDED, not what a fresh resolve would
// produce, for the same reason VPNExternalUnroute takes no container argument:
// the connected routes were discovered from a live table at dial time, so
// re-deriving them now would compute a set that was never installed and leave
// the real one behind.
func (h *Handler) VPNExternalDown(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	res, err := externalDown(ctx, vpn.ExternalUpSpec{
		Runner: h.externalRunner(),
		Iface:  strings.TrimSpace(stringArg(args, "iface")),
		Table:  intArg(args, "table"),
	}, linkProgress(emit))
	payload := res.Payload()
	if err != nil {
		return payload, err
	}
	return payload, nil
}

// externalProfileArg reads the profile from either shape a caller may send,
// and validates it the same way in both.
//
// It goes through vpn.ParseExternalProfile in BOTH cases rather than
// unmarshalling the map directly, because that function is where unknown keys
// are rejected — a second decode path here is exactly how the closed hole
// would quietly reopen.
func externalProfileArg(args map[string]any) (vpn.ExternalProfile, string, error) {
	if path := strings.TrimSpace(stringArg(args, "profile_path")); path != "" {
		return vpn.LoadExternalProfile(path)
	}
	raw, ok := args["profile"]
	if !ok || raw == nil {
		return vpn.ExternalProfile{}, "", fmt.Errorf("a profile is required: pass `profile` as an object of typed fields, or `profile_path` pointing at the same JSON on disk. This verb never accepts a wg-quick config as text — wg-quick runs PostUp as root, so the config it runs is synthesized here from fields that cannot express one")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return vpn.ExternalProfile{}, "", fmt.Errorf("the `profile` argument could not be read as JSON: %w", err)
	}
	p, err := vpn.ParseExternalProfile(encoded)
	return p, "", err
}
