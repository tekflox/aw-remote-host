package ops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Bounds for the podman calls that tear the workspace container down.
//
// Incident, 2026-11-06: Update ran `podman rm -f --ignore --depend
// aw-remote-host-workspace` with no deadline. That command took the workspace
// container's libpod shm lock and then went for the lock of a draining warm
// runner container, while `podman system service` held the runner's lock and
// wanted the workspace's. A classic lock-order inversion: both sides parked
// forever in futex_wait. Because Update holds the per-machine lifecycle lock
// (workspace_lock_unix.go) for the whole call, every later Update/Install click
// was rejected as "already in progress", and the placement reconciler's own
// podman calls piled up behind the same lock until the host went unhealthy.
// Killing the `rm` client (not the daemon) was enough to break it — so a
// deadline plus a retry is the whole cure, and these are the knobs for it.
var (
	// podmanStepTimeout bounds ONE teardown call. A healthy rm of a container
	// takes seconds; a call still running after this is wedged, not slow.
	podmanStepTimeout = 90 * time.Second
	// removeWorkspaceAttempts is how many times the final rm is tried when the
	// previous attempt was killed for hanging. Not retried on a real error —
	// that is a diagnosis for the operator, not something repetition fixes.
	removeWorkspaceAttempts = 3
	// lifecycleVerbTimeout bounds a whole update/reinstall/bootstrap, so the
	// lifecycle lock cannot be held forever by any step that has no deadline
	// of its own (the pull and bootstrap modules are long, but not unbounded).
	lifecycleVerbTimeout = 45 * time.Minute
	// warmRunnerPrefix names the ephemeral agent-runner containers that share
	// the workspace container's network namespace and therefore depend on it.
	warmRunnerPrefix = "aw-warm-"
)

// errStepTimeout marks a podman call that was killed for exceeding its own
// deadline while the surrounding operation was still live.
var errStepTimeout = errors.New("timed out")

// runBounded runs one command under its own deadline. A deadline hit while the
// caller's ctx is still live is reported as errStepTimeout so callers can tell
// "this call hung" (retry) from "the whole operation was cancelled" (stop).
func (h *Handler) runBounded(ctx context.Context, d time.Duration, name string, args ...string) (string, error) {
	stepCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	out, err := h.runner().Run(stepCtx, name, args...)
	if err != nil && ctx.Err() == nil && stepCtx.Err() != nil {
		return out, fmt.Errorf("%w after %s", errStepTimeout, d)
	}
	return out, err
}

// removeWorkspaceContainer removes the workspace container and the warm runner
// containers that depend on it, in an order and with deadlines that cannot
// wedge the lifecycle lock.
//
//  1. Each warm runner is removed on its own. `rm --depend` removes them as a
//     side effect too, but that is the call that holds two container locks at
//     once; removing them one at a time means no call ever holds the workspace
//     lock while waiting on a runner's. Failures here are warnings only — the
//     final rm still has --depend as the safety net.
//  2. The workspace container is removed with --depend under a deadline. A
//     call killed for hanging is retried (the kill releases the lock, so the
//     retry normally finds the daemon free); a call that fails outright is not.
func (h *Handler) removeWorkspaceContainer(ctx context.Context, emit Emit) error {
	if emit == nil {
		emit = noopEmit
	}
	out, err := h.runBounded(ctx, podmanStepTimeout, "podman", "ps", "-a",
		"--filter", "name="+warmRunnerPrefix, "--format", "{{.Names}}")
	if err != nil {
		emit("warning", "update", "could not list warm runner containers, relying on rm --depend: "+err.Error())
	} else {
		for _, name := range strings.Fields(out) {
			if !strings.HasPrefix(name, warmRunnerPrefix) {
				continue
			}
			if _, rmErr := h.runBounded(ctx, podmanStepTimeout, "podman", "rm", "-f", "--ignore", name); rmErr != nil {
				emit("warning", "update", "could not remove warm runner "+name+" individually: "+rmErr.Error())
			}
		}
	}

	var lastErr error
	for attempt := 1; attempt <= removeWorkspaceAttempts; attempt++ {
		out, err := h.runBounded(ctx, podmanStepTimeout, "podman", "rm", "-f", "--ignore", "--depend", WorkspaceContainer)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errStepTimeout) {
			return commandError("remove workspace container before update", err, out)
		}
		lastErr = err
		emit("warning", "update", fmt.Sprintf(
			"removing the workspace container hung (attempt %d/%d, %v); the stuck podman client was killed to release its lock",
			attempt, removeWorkspaceAttempts, err))
	}
	return commandError("remove workspace container before update", lastErr, "podman kept hanging (likely a libpod lock deadlock with a draining runner container)")
}
