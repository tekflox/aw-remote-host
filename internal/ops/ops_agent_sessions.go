package ops

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// warmLabel is the podman label agents-platform-runners' warm_pool.py stamps
// on every agent sandbox it creates (WARM_LABEL = "aw.warm" there). Filtering
// on the LABEL rather than the "aw-warm-" name prefix on purpose: the name is
// built by warm_container_name() and is free to change, while this label is
// the pool's own contract with the engine — it is what its own reap() and
// list_containers() filter on.
const warmLabel = "aw.warm=1"

// warmCurrentRunIDPath is written fresh by warm_pool.dispatch_turn() at the
// START of every turn dispatched into a sandbox.
//
// READ THE LIMIT BEFORE TRUSTING IT: nothing CLEARS this file when a turn
// ends, so it names the LAST run dispatched into that sandbox, not
// necessarily one still in flight. A sandbox lives for hours across many
// turns (6h TTL), so "has a run id" is not "is busy". It is reported anyway
// because it is the only per-turn identifier that exists on the host, and it
// turns an anonymous "3 sandboxes would die" into three run ids an operator
// can actually go and look up. The confirm gate that consumes this is
// deliberately a HUMAN decision for exactly that reason — see
// remote_host_driver.update_remote_host in aw-backend.
const warmCurrentRunIDPath = "/home/ubuntu/.aw-warm/current_run_id"

// AgentSession is one agent sandbox living on this host.
type AgentSession struct {
	Name      string `json:"name"`
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	CLI       string `json:"cli,omitempty"`
	// LastRunID is warmCurrentRunIDPath's content — see that constant's
	// comment for why this is "last dispatched", not "currently running".
	LastRunID string `json:"last_run_id,omitempty"`
	// NeverDispatched is the one thing about a sandbox this host CAN state as
	// fact: the turn file has never been written, so no turn has ever been
	// dispatched into it, so it cannot be running one now. That is a pure
	// idle pool container and destroying it costs nothing.
	//
	// Reported as its own field rather than inferred from an empty LastRunID,
	// because "the file is not there" and "this host could not read it" are
	// different answers and an empty string cannot tell them apart. Readers
	// that conflate the two turn an unreadable sandbox into an idle one — the
	// exact mistake that has cost this stack three separate outages.
	NeverDispatched bool `json:"never_dispatched"`
	// RunIDUnreadable says the probe itself failed. Neither idle nor busy:
	// unknown.
	RunIDUnreadable bool `json:"run_id_unreadable,omitempty"`
	Draining        bool `json:"draining"`
}

// AgentSessions inventories the agent sandboxes running on this host.
//
// It exists so a lifecycle verb that DESTROYS this host — the container-form
// image update, which recreates the outer container — can tell the operator
// what it is about to take down with it. On 2026-09-10 an image bump killed
// every sandbox on this host with no warning and no checkpoint; the run that
// ordered it was itself running in one of them.
//
// Reports only RUNNING sandboxes: a stopped one is garbage reap() has not
// collected yet and nothing is lost by recreating over it.
func (h *Handler) AgentSessions(ctx context.Context) (map[string]any, error) {
	out, err := h.runner().Run(ctx, "podman", "ps",
		"--filter", "label="+warmLabel,
		"--format", "json")
	if err != nil {
		// Deliberately an ERROR, not an empty list. "no sandboxes" and
		// "could not check" must never reach the confirm gate looking the
		// same — warm_pool.list_containers' own docstring makes the same
		// demand of its callers, for the same reason.
		return nil, err
	}

	var raw []struct {
		Names  []string          `json:"Names"`
		Labels map[string]string `json:"Labels"`
		State  string            `json:"State"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &raw); err != nil {
		return nil, err
	}

	sessions := make([]AgentSession, 0, len(raw))
	for _, c := range raw {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}
		s := AgentSession{
			Name:      name,
			AgentID:   c.Labels["aw.agent_id"],
			SessionID: c.Labels["aw.session_id"],
			CLI:       c.Labels["aw.cli"],
			Draining:  strings.Contains(name, "-draining-"),
		}
		// `cat ... || true` on purpose: a plain `cat` of a missing file exits
		// non-zero, which is indistinguishable from the exec itself failing.
		// Swallowing the missing-file case INSIDE the container leaves a
		// non-zero exit here meaning only one thing — this host could not ask.
		runID, err := h.runner().Run(ctx, "podman", "exec", name, "sh", "-c",
			"cat "+warmCurrentRunIDPath+" 2>/dev/null || true")
		switch {
		case err != nil:
			s.RunIDUnreadable = true
		case strings.TrimSpace(runID) == "":
			s.NeverDispatched = true
		default:
			s.LastRunID = strings.TrimSpace(runID)
		}
		sessions = append(sessions, s)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Name < sessions[j].Name })

	return map[string]any{
		"sessions": sessions,
		"count":    len(sessions),
	}, nil
}
