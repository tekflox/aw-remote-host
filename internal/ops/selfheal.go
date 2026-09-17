package ops

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SelfHealLoop periodically verifies the nested workspace runtime
// (postgres, redis, the workspace container) is genuinely alive — not just
// what `podman inspect` claims — and reconciles it via the same idempotent
// path Bootstrap() already uses (the one a human clicking "Install" in the
// console triggers), without waiting for the control plane to notice or a
// human to act.
//
// Why this exists (incident: crispal workspace host-link outage,
// 2026-09-17). A netavark/conmon failure left postgres, redis and the
// workspace container all in a "zombie" state: `podman inspect` reported
// State.Running=true for all three, for over three hours straight, while
// `podman exec` on any of them failed with "the container ... is not
// running" — the runtime's own process had actually died; podman's own
// bookkeeping never caught up. Nothing already running noticed on its own:
//
//   - The OUTER /link process's own heartbeat watchdog (entrypoint.sh) only
//     tracks THIS process's liveness, not the nested containers' — it kept
//     ticking the whole time, because /link itself never dropped.
//   - The control plane's health() dispatch DID correctly report unhealthy
//     (probeHealth's curl to HealthURL failed), but aw-backend only
//     auto-dispatches the "bootstrap" verb the FIRST time a workspace links
//     (row.status == "provisioning", see host_link.py's
//     _complete_registration). A zombie state on an already-"running"
//     workspace was reported forever, never repaired, until a human opened
//     the console and clicked Install — dispatching "bootstrap" by hand.
//
// This closes that gap from the host's own side, the same way the
// tailscaled supervisor and the VPN/firewall self-heal loops in
// cmd/aw-remote-host/commands.go already do for their own subsystems — no
// control-plane round trip required, and no human needed for the common
// case.
//
// SelfHealInterval is a backstop, not the primary signal: comfortably above
// HealthURL's own probe cadence and the control plane's own health-poll
// interval, so this only ever fires when nothing faster already caught it.
const SelfHealInterval = 5 * time.Minute

// zombieCheckContainers are checked with a genuine `podman exec <name>
// true` — NOT `podman inspect`, whose State.Running is exactly the field
// that lied for over three hours in the incident this loop exists to
// catch. Order matters for a reconcile pass (runModules brings them up
// postgres/redis-before-workspace anyway), not for the check itself.
var zombieCheckContainers = []string{PostgresContainer, RedisContainer, WorkspaceContainer}

// ZombieHealLoop runs until ctx is cancelled — start it once, in its own
// goroutine, after the first successful /link registration. Named
// distinctly from cmd/aw-remote-host's own bootstrapWorkspaceSelfHeal
// (which retries the INITIAL --with-workspace provision until it succeeds
// once, then returns): this loop runs for the lifetime of the process,
// after that initial provision is long done, watching for the runtime
// going quietly dead under it.
func (h *Handler) ZombieHealLoop(ctx context.Context, emit Emit) {
	if emit == nil {
		emit = noopEmit
	}
	ticker := time.NewTicker(SelfHealInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.selfHealTick(ctx, emit)
		}
	}
}

// selfHealTick is the loop body, split out so a test can call it directly
// without waiting on the ticker or a real 5-minute clock.
func (h *Handler) selfHealTick(ctx context.Context, emit Emit) {
	// A lean host — never provisioned with a local runtime at all — has
	// nothing to heal, and must never be silently provisioned by a loop
	// nobody asked to run bootstrap-workspace --with-workspace on it.
	if !h.localRuntimeProvisioned(ctx) {
		return
	}
	zombies := h.zombieContainers(ctx)
	if len(zombies) == 0 {
		return
	}
	emit("warning", "selfheal", fmt.Sprintf(
		"detected zombie container(s) %s — podman reports them running but they don't answer; reconciling",
		strings.Join(zombies, ", "),
	))
	if _, err := h.runModules(ctx, h.Opts, true, emit); err != nil {
		emit("error", "selfheal", "reconcile failed: "+err.Error())
		return
	}
	if still := h.zombieContainers(ctx); len(still) > 0 {
		emit("error", "selfheal", fmt.Sprintf(
			"still unhealthy after reconcile: %s — needs a human", strings.Join(still, ", "),
		))
		return
	}
	emit("info", "selfheal", "recovered — "+strings.Join(zombies, ", ")+" answering again")
}

// localRuntimeProvisioned is true when this host has EVER had a local
// runtime installed — WorkspaceContainer exists (`podman inspect`
// succeeds), whatever its CURRENT running state. Distinct from
// zombieContainers below on purpose: a container that was never created at
// all is a lean host working as designed, not something to heal.
func (h *Handler) localRuntimeProvisioned(ctx context.Context) bool {
	_, err := h.runner().Run(ctx, "podman", "inspect", WorkspaceContainer)
	return err == nil
}

// zombieContainers returns the names, among zombieCheckContainers, whose
// process is actually dead despite podman's own bookkeeping — proven with a
// real `podman exec <name> true`, not the `State.Running` field that lied
// throughout the incident this exists to catch.
func (h *Handler) zombieContainers(ctx context.Context) []string {
	var zombies []string
	for _, name := range zombieCheckContainers {
		if _, err := h.runner().Run(ctx, "podman", "exec", name, "true"); err != nil {
			zombies = append(zombies, name)
		}
	}
	return zombies
}
