// Firewall verbs — see internal/firewall for the actual iptables/nft work.
// Deliberately NOT in workspaceLifecycleVerbs (ops.go): those verbs need
// podman, which a lean-linked host never has; firewall management needs
// root, and works fine on exactly the lean hosts that most want it.
package ops

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tekflox/aw-remote-host/internal/firewall"
)

// parseFirewallRules round-trips args["rules"] (a JSON-decoded []any of
// map[string]any, the shape a cmd frame's generic args carries) through
// json.Marshal/Unmarshal into []firewall.Rule — simpler and less
// error-prone than hand-walking the map, and firewall.Rule's json tags
// already match aw-backend's FirewallRule field names exactly (Card A
// contract), so no field-by-field translation is needed.
func parseFirewallRules(raw any) ([]firewall.Rule, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal rules: %w", err)
	}
	var rules []firewall.Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	return rules, nil
}

// detectFirewallBackend is firewall.DetectBackend, indirected the same way
// proc_windows.go's pickShell is — so tests can inject a fixed backend
// instead of depending on whichever of nft/iptables (if either) happens to
// be on the PATH of whatever machine runs `go test`.
var detectFirewallBackend = firewall.DetectBackend

// lastAppliedRevision reads the self-heal cache's own record of the last
// revision this host actually applied — the only place that number lives,
// since neither iptables nor nft rule dumps carry an application-level
// revision counter.
func lastAppliedRevision() int {
	path, err := firewall.StatePath()
	if err != nil {
		return 0
	}
	p, err := firewall.Load(path)
	if err != nil || p == nil {
		return 0
	}
	return p.Revision
}

// FirewallApply pushes the FULL rule set (Card B instructions: full-state,
// never incremental) via the detected backend. args: "rules" ([]object,
// firewall.Rule shape), "lockdown" (bool), "revision" (int) — exactly the
// firewall_apply frame aw-backend's send_command_anywhere dispatch already
// sends (Card A contract, delivered and tested).
//
// Response shape is {backend, privileged, applied_revision} plus
// "privileged_reason" ONLY when privileged is false — aw-backend passes
// that key straight through into FirewallHostState.privileged_reason,
// which is what the console (Card D) shows the user to explain why a given
// host can't manage its own firewall (Product Owner refinement,
// 2026-08-24). A privileged=false response is a normal, successful reply,
// not an error — the daemon runs without root by design, so this is the
// expected case on most hosts, not a failure to escalate past.
func (h *Handler) FirewallApply(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	rules, err := parseFirewallRules(args["rules"])
	if err != nil {
		return nil, err
	}
	lockdown, _ := args["lockdown"].(bool)
	revision := int(floatArg(args, "revision", 0))

	backend := detectFirewallBackend(h.runner())
	name, privileged, reason, err := backend.Probe(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewall probe: %w", err)
	}
	if !privileged {
		emit("warning", "firewall", fmt.Sprintf("not applying — %s backend is not privileged: %s", name, reason))
		return map[string]any{
			"backend": name, "privileged": false,
			"applied_revision": lastAppliedRevision(), "privileged_reason": reason,
		}, nil
	}

	emit("info", "firewall", fmt.Sprintf("applying %d rule(s) via %s (lockdown=%v, revision=%d)", len(rules), name, lockdown, revision))
	if err := backend.Apply(ctx, rules, lockdown); err != nil {
		emit("error", "firewall", "apply failed: "+err.Error())
		return nil, fmt.Errorf("firewall apply: %w", err)
	}

	if path, perr := firewall.StatePath(); perr == nil {
		if err := firewall.Save(path, rules, lockdown, revision); err != nil {
			// Best-effort: the live rules ARE applied at this point, so this
			// only degrades self-heal-on-reboot, not the apply itself.
			emit("warning", "firewall", "applied but could not persist self-heal cache: "+err.Error())
		}
	}

	emit("info", "firewall", fmt.Sprintf("applied revision %d via %s", revision, name))
	return map[string]any{"backend": name, "privileged": true, "applied_revision": revision}, nil
}

// FirewallStatus reports this host's live backend/privilege/chain state
// without changing anything.
func (h *Handler) FirewallStatus(ctx context.Context) (map[string]any, error) {
	backend := detectFirewallBackend(h.runner())
	st, err := backend.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewall status: %w", err)
	}

	out := map[string]any{
		"backend": st.Backend, "privileged": st.Privileged,
		"applied_revision": lastAppliedRevision(), "chain": st.Chain,
	}
	if !st.Privileged {
		out["privileged_reason"] = st.PrivilegedReason
	}
	return out, nil
}
