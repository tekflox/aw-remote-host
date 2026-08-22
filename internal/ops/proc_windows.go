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
	"sync"
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

// The shell that runs a command. cmd.exe would be far lighter — measured at
// 0.24s startup against 13.6s for powershell.exe on a real Windows 10 host —
// but its quoting rules mangle anything containing a quote or an ampersand,
// and the control plane sends whole command lines verbatim. Correctness wins;
// pickShell below buys back what it can.
const (
	powerShell7 = "pwsh.exe"       // PowerShell 7+, dramatically faster to start
	powerShell5 = "powershell.exe" // Windows PowerShell 5.1, always present
)

// pickShell prefers pwsh when it is installed.
//
// Startup cost is the entire reason. Windows PowerShell 5.1 measured 13.6s
// per invocation on a real host (a Surface running Win10 Pro with Defender
// real-time scanning on), and exec_start pays that on EVERY command. pwsh
// starts in a fraction of it. Neither is present-by-default in the same
// sense — 5.1 always exists, pwsh only if someone installed it — so this
// probes once and caches.
//
// Cached rather than probed per command because LookPath walks PATH and
// stats each entry, and doing that per exec_start on an already-slow box
// adds latency to fix latency.
var pickShell = sync.OnceValue(func() string {
	if path, err := exec.LookPath(powerShell7); err == nil && path != "" {
		return powerShell7
	}
	return powerShell5
})

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
//
// Note what is NOT here: -ExecutionPolicy Bypass. It looks harmless and is
// the usual cargo-cult addition, but execution policy governs script FILES
// and this passes an inline -Command string, which no policy has ever
// blocked. It is not merely useless — on a real host it measured 23.9s of
// startup against 13.6s without it, so it was costing ~10 seconds on every
// single command to buy nothing.
func shellCommand(command string) (string, []string) {
	return pickShell(), []string{
		"-NoProfile",
		"-NonInteractive",
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
