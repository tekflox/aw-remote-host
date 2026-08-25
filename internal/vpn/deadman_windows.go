//go:build windows

package vpn

import (
	"errors"
	"os/exec"
)

// Windows has no setsid and no process groups of the shape the dead-man's
// switch needs, and it does not need them: selecting an exit gate is refused
// on Windows well before this (the route exclusions are `ip rule`, which is
// Linux-only, and a Windows BYOD host runs its workspace inside the WSL2
// distro internal/wsl provisions — that distro is an ordinary Linux node and
// is where the mesh commands belong).
//
// These exist so the binary still cross-compiles for windows/amd64, which the
// release workflow builds. Refusing loudly here rather than silently doing
// something weaker is the same contract the rest of this package keeps: a
// switch that only pretends to be armed is worse than no switch, because the
// caller would go on to move the default route believing it had one.

var errNoDeadmanOnWindows = errors.New("the dead-man's switch needs a detached POSIX session, which Windows does not provide — exit-gate selection is Linux-only and belongs in this machine's WSL2 distro")

func startDetached(*exec.Cmd) error { return errNoDeadmanOnWindows }

func killGroup(int) error { return errNoDeadmanOnWindows }
