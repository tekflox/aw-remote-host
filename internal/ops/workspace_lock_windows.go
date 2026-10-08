//go:build windows

// Windows twin of workspace_lock_unix.go — see that file for the incident,
// the design, and why the lock is per-MACHINE rather than per-process.
//
// This is a deliberate no-op rather than a LockFileEx port. Every verb the
// lock guards (update/reinstall/bootstrap) drives the podman workspace
// container, and those are already refused on a host without the local
// workspace runtime — see workspaceLifecycleVerbs and
// workspaceRuntimeSupported in ops.go, which is false for GOOS=windows. So
// on Windows there is no concurrent workspace recreate to serialize: the
// verbs cannot run at all. Keeping the signature identical is what lets
// Dispatch stay a single portable switchboard, exactly as proc_windows.go
// does for the process-control primitives.
//
// If a Windows host ever grows a real workspace runtime, this must become a
// genuine LockFileEx implementation — the Unix file's reasoning about
// kernel-released locks applies there too (LockFileEx is also released on
// process termination), so it is a port, not a redesign.
package ops

// IsWorkspaceBusy always reports false here: acquireWorkspaceLock below
// never returns a contention error, so nothing can be busy.
func IsWorkspaceBusy(error) bool { return false }

func acquireWorkspaceLock(string, Emit) (func(), error) {
	return func() {}, nil
}
