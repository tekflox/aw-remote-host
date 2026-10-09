// workspace_logs is the read-only, dedicated verb for viewing the
// workspace container's own output. It is deliberately a SEPARATE verb
// from exec_start (which runs an arbitrary shell command) so a console/UI
// integration can be authorized to view logs without being authorized to
// run anything on this host — before this, the only way to watch a slow
// Update converge was `docker exec aw-remote-host podman logs
// aw-remote-host-workspace` on the bare-metal box itself.
//
// A one-shot tail (follow=false, the default) runs synchronously through
// the same h.runner() every other podman-backed verb in ops.go uses. A
// follow=true request instead reuses the exact job tracking exec_start/
// exec_status/exec_wait/exec_kill already provide (see ops_exec.go's
// startTrackedProcess) — no new transport, no new polling contract: a
// console calling workspace_logs with follow=true gets back
// {job_id, pid, started} exactly like exec_start, and polls
// exec_status(job_id) for the growing output or exec_kill(job_id) to stop
// following (the UI's "pause").
package ops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/instance"
)

const (
	defaultLogTail = 200
	maxLogTail     = 5000

	// workspaceLogSnapshotKeep bounds how many pre-update snapshots stay on
	// disk — one per Update, oldest dropped first. Enough to answer "what
	// did the previous boot do" without growing without bound on a host
	// that updates often.
	workspaceLogSnapshotKeep = 5

	// workspaceLogSnapshotPrefix names every snapshot file so pruning and
	// "find the latest one" can filter the directory without assuming it
	// holds nothing else.
	workspaceLogSnapshotPrefix = "boot-"
)

// WorkspaceLogs is the workspace_logs verb. args:
//
//	"tail"   (number, default 200, capped at 5000) — lines from the end.
//	         Ignored when "follow" is true; podman's own --follow already
//	         establishes where streaming starts from.
//	"follow" (bool, default false) — keep streaming as a background job,
//	         same shape as exec_start: returns {job_id, pid, started} and
//	         the caller polls exec_status(job_id) / stops it with
//	         exec_kill(job_id).
//	"since"  (string, optional) — passed straight through to podman's own
//	         `logs --since`.
//	"source" (string, default "live") — "live" reads the RUNNING container
//	         via podman; "previous" reads the snapshot captured just
//	         before the last Update recreated the container (see
//	         snapshotWorkspaceLogBeforeRecreate), which podman otherwise
//	         has no way to answer at all once the old container is gone.
func (h *Handler) WorkspaceLogs(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}

	source := stringArg(args, "source")
	if source == "" {
		source = "live"
	}
	switch source {
	case "previous":
		return previousWorkspaceLog()
	case "live":
		// fall through
	default:
		return nil, fmt.Errorf(`unknown source %q: use "live" or "previous"`, source)
	}

	podmanArgs, follow, timeout := workspaceLogsPodmanArgs(args)

	if !follow {
		out, err := h.runner().Run(ctx, "podman", podmanArgs...)
		if err != nil {
			return nil, commandError("podman logs "+WorkspaceContainer, err, out)
		}
		return map[string]any{"output": out, "follow": false}, nil
	}

	label := "podman " + strings.Join(podmanArgs, " ")
	return h.startTrackedProcess(label, "podman", podmanArgs, timeout, emit)
}

// workspaceLogsPodmanArgs builds the `podman logs` argv for WorkspaceLogs
// from its verb args, plus whether to follow and the timeout a follow job
// should run under. Pulled out as a pure function, with no process/runner
// involved, so the argv-building logic is unit-testable without podman
// needing to exist on the machine running the test.
func workspaceLogsPodmanArgs(args map[string]any) (podmanArgs []string, follow bool, timeout time.Duration) {
	tail := int(floatArg(args, "tail", float64(defaultLogTail)))
	if tail <= 0 {
		tail = defaultLogTail
	}
	if tail > maxLogTail {
		tail = maxLogTail
	}
	follow, _ = args["follow"].(bool)
	since := strings.TrimSpace(stringArg(args, "since"))

	podmanArgs = []string{"logs", "--timestamps", "--tail", strconv.Itoa(tail)}
	if since != "" {
		podmanArgs = append(podmanArgs, "--since", since)
	}
	if follow {
		podmanArgs = append(podmanArgs, "--follow")
	}
	podmanArgs = append(podmanArgs, WorkspaceContainer)

	// A one-shot tail has no reason to hold a job slot for the full
	// execHardTimeout (30min) — podman exits on its own the moment it has
	// written the requested lines, so this only bounds a podman that
	// hangs. A follow job gets the full ceiling: that is what lets a
	// console sit through an entire 20+ minute Update convergence without
	// the job being killed out from under it.
	timeout = 2 * time.Minute
	if follow {
		timeout = execHardTimeout
	}
	return podmanArgs, follow, timeout
}

// workspaceLogSnapshotDirFunc resolves the per-MACHINE directory snapshots
// of the workspace container's log are written to right before Update
// recreates the container. Per-machine (instance.MachineDir(), not a
// per-identity instance.Dir) because there is at most one workspace per
// machine regardless of how many lean --instance links share it — see the
// README's "Scope" section on named instances.
//
// A var, not a plain function, so tests can point it at a throwaway
// directory instead of this test process's own real $HOME — see
// useTempState in ops_test.go, which every Update test already calls.
var workspaceLogSnapshotDirFunc = func() (string, error) {
	machineDir, err := instance.MachineDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(machineDir, "workspace-logs"), nil
}

func workspaceLogSnapshotDir() (string, error) {
	return workspaceLogSnapshotDirFunc()
}

// snapshotWorkspaceLogBeforeRecreate saves the OUTGOING workspace
// container's full log to disk right before Update removes it. podman
// only ever has what the CURRENT container produced, so without this the
// one boot an operator most wants to read — the one that just finished,
// or hung — disappears the instant the new container exists.
//
// Best-effort and swallows its own errors (beyond an emitted warning): a
// failure saving yesterday's diagnostics must never block today's update.
func (h *Handler) snapshotWorkspaceLogBeforeRecreate(ctx context.Context, emit Emit) {
	dir, err := workspaceLogSnapshotDir()
	if err != nil {
		emit("warning", "update", "could not resolve workspace-logs snapshot dir: "+err.Error())
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		emit("warning", "update", "could not create workspace-logs snapshot dir: "+err.Error())
		return
	}
	out, err := h.runner().Run(ctx, "podman", "logs", "--timestamps", WorkspaceContainer)
	if err != nil {
		// Nothing ran yet (first bootstrap) or the container is already
		// gone — nothing worth saving, and not an error worth surfacing on
		// every single update.
		return
	}
	snapshotPath := filepath.Join(dir, workspaceLogSnapshotPrefix+time.Now().UTC().Format("20060102T150405Z")+".log")
	if err := os.WriteFile(snapshotPath, []byte(out), 0o644); err != nil {
		emit("warning", "update", "could not save the previous boot's workspace log: "+err.Error())
		return
	}
	pruneWorkspaceLogSnapshots(dir, workspaceLogSnapshotKeep)
	emit("info", "update", "saved the previous boot's workspace log to "+snapshotPath)
}

// pruneWorkspaceLogSnapshots keeps at most keep snapshot files in dir,
// oldest first dropped. Names sort lexically in chronological order because
// they're built from a zero-padded UTC timestamp.
func pruneWorkspaceLogSnapshots(dir string, keep int) {
	names := listWorkspaceLogSnapshots(dir)
	for len(names) > keep {
		os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

func listWorkspaceLogSnapshots(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), workspaceLogSnapshotPrefix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// previousWorkspaceLog returns the most recently saved snapshot — the
// workspace_logs verb's source="previous". Reads a plain file rather than
// shelling out, so it works even when podman itself is unreachable; only
// Dispatch's workspaceLifecycleVerbs gate (which workspace_logs is
// deliberately NOT exempt from — a lean host never ran a workspace in the
// first place, so it never has a snapshot either) decides whether this is
// reachable at all.
func previousWorkspaceLog() (map[string]any, error) {
	dir, err := workspaceLogSnapshotDir()
	if err != nil {
		return nil, err
	}
	names := listWorkspaceLogSnapshots(dir)
	if len(names) == 0 {
		return map[string]any{"found": false}, nil
	}
	latest := names[len(names)-1]
	data, err := os.ReadFile(filepath.Join(dir, latest))
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", latest, err)
	}
	return map[string]any{"found": true, "name": latest, "content": string(data)}, nil
}
