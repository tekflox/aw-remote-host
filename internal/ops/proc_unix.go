//go:build !windows

// Process-control primitives for POSIX hosts. The Windows twin lives in
// proc_windows.go and must keep the same three signatures — ops_exec.go is
// written against them and compiles unchanged on both.
package ops

import (
	"os/exec"
	"syscall"
)

// workspaceRuntimeSupported gates the podman-backed lifecycle verbs (see
// workspaceLifecycleVerbs in ops.go). True here: a POSIX host may or may
// not have podman installed, and "may not" is already handled — a lean
// link just gets a podman-not-found error from the verb it tried.
const workspaceRuntimeSupported = true

// shellCommand returns the argv that runs a user-supplied command string
// through this host's shell. `sh` rather than `bash` deliberately: every
// POSIX host has it, and the commands the control plane sends are plain
// enough not to need bashisms.
func shellCommand(command string) (string, []string) {
	return "sh", []string{"-c", command}
}

// configureProcessGroup makes the child lead its own process group, so a
// shell that forks children can still be killed as a unit by
// killProcessTree below. Without it, killing the direct child leaves
// grandchildren holding the stdout/stderr pipe fds open and cmd.Wait()
// hangs past the deadline waiting for an EOF that never comes.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree force-kills pid and everything it spawned. The negative
// pid is what does the work — valid precisely because configureProcessGroup
// made the job's own pid double as its process-group id.
func killProcessTree(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
