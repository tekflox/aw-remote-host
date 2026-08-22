//go:build windows

// Process-control primitives for Windows hosts — the twin of proc_unix.go.
// These three functions are the ENTIRE reason ops_exec.go didn't compile for
// GOOS=windows: `syscall.SysProcAttr{Setpgid}` and `syscall.Kill` simply do
// not exist there. Everything else in this package (the fs_* verbs, the job
// bookkeeping) was already portable Go.
package ops

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
)

// workspaceRuntimeSupported gates the podman-backed lifecycle verbs (see
// workspaceLifecycleVerbs in ops.go). False here and not configurable:
// the workspace is a LINUX container image, so no amount of podman on a
// Windows host makes `restart`/`bootstrap`/`update` meaningful. A Windows
// host is always a lean link.
const workspaceRuntimeSupported = false

// createNewProcessGroup is Windows' CREATE_NEW_PROCESS_GROUP. Spelled out
// rather than pulled from golang.org/x/sys/windows so this repo keeps its
// two-dependency go.mod — the constant is part of the stable Win32 ABI and
// is never going to change.
const createNewProcessGroup = 0x00000200

// powerShell runs the command. cmd.exe would be lighter, but its quoting
// rules mangle anything with a quote or an ampersand in it, and the control
// plane sends whole command lines verbatim.
const powerShell = "powershell.exe"

// psExitPropagation is appended to every command because of a genuine
// PowerShell trap: with -Command, powershell.exe exits 0 even when the
// native program it just ran failed — the child's status lands in
// $LASTEXITCODE and is otherwise thrown away. Without this, every failing
// command on a Windows host would report exit_code 0 and read as success.
//
// The $null guard matters too: a command that is pure PowerShell (no native
// exe at all) never sets $LASTEXITCODE, and `exit $null` would force a 0
// over PowerShell's own non-zero status from a terminating error.
const psExitPropagation = "\nif ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }"

// shellCommand returns the argv that runs a user-supplied command string
// through this host's shell. -NoProfile keeps a user's $PROFILE from
// injecting output into the job's stdout; -NonInteractive makes a command
// that would have prompted fail fast instead of hanging until the timeout.
func shellCommand(command string) (string, []string) {
	return powerShell, []string{
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", command + psExitPropagation,
	}
}

// configureProcessGroup gives the child its own process group — the closest
// Windows equivalent of Setpgid, and what makes the taskkill /T below able
// to find the whole tree.
//
// HideWindow keeps a console window from flashing onto the desktop of
// whoever is logged in: this process normally runs from a Scheduled Task
// (see servicemgr/schtasks.go) with an interactive token, so without it
// every exec_start would visibly pop a window at the user.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup,
		HideWindow:    true,
	}
}

// killProcessTree force-kills pid and everything it spawned.
//
// Windows has no "signal the process group" call — the POSIX kill(-pid)
// trick has no equivalent. taskkill /T walks the parent/child tree from pid
// down and /F is the non-negotiable terminate, which together give the same
// guarantee configureProcessGroup's POSIX twin gets from a group SIGKILL.
func killProcessTree(pid int) error {
	out, err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("taskkill /T /F /PID %d: %w: %s", pid, err, out)
	}
	return nil
}
