//go:build !windows

package vpn

import (
	"errors"
	"os/exec"
	"syscall"
)

// startDetached starts cmd in a brand-new session.
//
// setsid is the whole point of the dead-man's switch (see deadman.go's
// header): the revert has to outlive the session that armed it, which is the
// session most likely to be killed by the route change it is guarding.
// SysProcAttr.Setsid gives exactly what `setsid nohup … &` gives — a new
// session and process group with no controlling terminal — without depending
// on a setsid binary being installed.
//
// The new process group is also what makes disarming exact: the child leads
// its own group, so killing -pid takes the sh and the sleep it is blocked in
// together.
func startDetached(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// killGroup kills the process GROUP led by pid. A process that has already
// gone is not an error — the switch may simply have fired.
func killGroup(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
