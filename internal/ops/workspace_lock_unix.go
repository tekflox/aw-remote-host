//go:build !windows

// Per-MACHINE mutual exclusion for the workspace-lifecycle verbs that
// RECREATE the workspace container (update/reinstall/bootstrap). The Windows
// twin lives in workspace_lock_windows.go and keeps the same signature.
//
// **The incident this closes.** Nothing serialized these verbs. Clicking
// aw-console's Workspace > Manage > Update twice — or ten times, which is
// exactly what an impatient user does when the first click shows no
// progress for a minute — ran N copies of Handler.Update concurrently over
// the same host directory and the same fixed container names. Confirmed
// live on this project's own host 2026-10-08 via `podman events`: two
// `aw-remote-host-workspace-update` seed containers created 14s apart
// (19:12:01, 19:12:15), then the workspace container recreated underneath
// the first update that was still running (19:12:30 died, 19:12:34 create).
// Three distinct ways that corrupts:
//
//  1. `podman rm -f <seed>` at the top of Update force-removes the seed
//     container the FIRST update is still `podman cp`-ing its source out
//     of. (Also fixed independently: the seed name is now unique per pass.)
//  2. Two `syncWorkspaceSource` passes interleave file writes into the same
//     live hostDir, so the workspace source tree ends up a mix of both.
//  3. Both reach `podman rm -f <workspace>` + recreate, so the second
//     recreate kills a container the first one had just brought up — which
//     is what makes a workspace boot, get killed mid-boot-reconcile, and
//     boot again. On this host each of those boots starts a 10-worker app
//     reconcile pass, so a double-click is not a wasted click, it is
//     minutes of thrash.
//
// **Why a FILE lock and not a mutex.** A `sync.Mutex` on Handler would be
// wrong twice over. The contended resources are the fixed names
// `WorkspaceContainer` / `WorkspaceContainer+"-update*"` and the host
// source dir, and `WorkspaceContainer` is a package-level constant, NOT
// instance-scoped (see ops.go) — so two `--instance` processes serving two
// tenant identities off this one machine collide on exactly the same
// container, and a process-local mutex cannot see across them. The lock
// therefore lives in `instance.MachineDir()`, the same per-MACHINE
// directory `updater.Dir()` uses for the self-updater, and for the same
// stated reason: one binary, one podman, one workspace container per box.
//
// **Why flock and not a PID file.** The user's requirement is that the lock
// be released when the holder finishes OR is aborted. `flock(2)` is held by
// the open file description and released by the KERNEL when the process
// exits for any reason — a clean return, a panic, SIGKILL, an OOM kill, or
// the service being restarted mid-update. That means there is no stale-lock
// state to detect, no liveness heuristic to get wrong, and no "remove the
// lockfile to recover" runbook step. A PID file would need all three, and
// would strand every later update behind a crashed one.
package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tekflox/aw-remote-host/internal/instance"
)

// workspaceLockFileName sits directly in MachineDir (not under a verb- or
// instance-scoped subdir) because its whole job is to be the SAME path for
// every caller on this machine.
const workspaceLockFileName = "workspace-lifecycle.lock"

// lockHolder is what a holder writes into the lockfile so a rejected caller
// can tell the user WHICH operation is in progress and since when, instead
// of a bare "busy". Best-effort payload: it is written after the lock is
// taken and read without the lock, so a reader can legitimately observe it
// empty (holder acquired but has not written yet) and must degrade to a
// generic message rather than failing.
type lockHolder struct {
	Verb      string  `json:"verb"`
	PID       int     `json:"pid"`
	StartedAt float64 `json:"started_at"`
}

// errWorkspaceBusy is returned when another lifecycle pass holds the lock.
// Callers surface its message verbatim — see Dispatch.
type errWorkspaceBusy struct{ msg string }

func (e *errWorkspaceBusy) Error() string { return e.msg }

// IsWorkspaceBusy reports whether err is a rejection from the
// workspace-lifecycle lock rather than a real failure of the operation. The
// console/link layer uses it to render this as "already running" instead of
// "update failed".
func IsWorkspaceBusy(err error) bool {
	var busy *errWorkspaceBusy
	return errors.As(err, &busy)
}

func workspaceLockPath() (string, error) {
	dir, err := instance.MachineDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create machine state dir: %w", err)
	}
	return filepath.Join(dir, workspaceLockFileName), nil
}

// describeHolder renders the current holder for a human. Returns "" when the
// payload is missing or unreadable — the caller then uses a generic phrase.
func describeHolder(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return ""
	}
	var h lockHolder
	if err := json.Unmarshal(raw, &h); err != nil || h.Verb == "" {
		return ""
	}
	if h.StartedAt <= 0 {
		return fmt.Sprintf("%q (pid %d)", h.Verb, h.PID)
	}
	elapsed := time.Since(time.Unix(0, int64(h.StartedAt*float64(time.Second)))).Round(time.Second)
	return fmt.Sprintf("%q (pid %d, running for %s)", h.Verb, h.PID, elapsed)
}

// acquireWorkspaceLock takes the per-machine workspace-lifecycle lock for
// verb. On success it returns a release func the caller MUST defer; it is
// idempotent, and skipping it only delays release until process exit (the
// kernel does it anyway).
//
// On contention it returns an *errWorkspaceBusy whose message names the
// operation already in flight, and emits it at "warning" on the verb's own
// phase so the console shows the user why their click did nothing instead
// of failing silently.
func acquireWorkspaceLock(verb string, emit Emit) (func(), error) {
	path, err := workspaceLockPath()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open workspace lifecycle lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// Read the holder BEFORE closing our own handle — closing is what
		// would release the lock if we had taken it, and here we have not,
		// so ordering is only about not leaking the fd on the error path.
		holder := describeHolder(path)
		_ = f.Close()
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("lock workspace lifecycle: %w", err)
		}
		what := "another workspace lifecycle operation"
		if holder != "" {
			what = holder
		}
		msg := fmt.Sprintf(
			"ignoring this %s request: %s is already in progress on this host. "+
				"Wait for it to finish — its progress is on the operation that "+
				"started it. The lock clears automatically when that operation "+
				"ends, including if it crashes or is killed.", verb, what)
		if emit != nil {
			emit("warning", verb, msg)
		}
		return nil, &errWorkspaceBusy{msg: msg}
	}

	// We hold it. Record who we are for the next caller's rejection
	// message. Truncate first: the previous holder's payload is still in
	// there and a shorter write would leave its tail behind.
	if err := f.Truncate(0); err == nil {
		if payload, mErr := json.Marshal(lockHolder{
			Verb:      verb,
			PID:       os.Getpid(),
			StartedAt: float64(time.Now().UnixNano()) / float64(time.Second),
		}); mErr == nil {
			_, _ = f.WriteAt(payload, 0)
		}
	}

	released := false
	return func() {
		if released {
			return
		}
		released = true
		// Closing the fd drops the flock. Blanking the payload first keeps
		// a later rejection from naming an operation that already ended.
		_ = f.Truncate(0)
		_ = f.Close()
	}, nil
}
