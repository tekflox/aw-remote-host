// Package diagdump arms a non-fatal SIGUSR1 goroutine dump.
//
// RODADA 10 D6 item 2 (Kanban page 3de5bf3b-9510-817c-9228-e0bb44e36468):
// once D5 lands and signals actually reach this process (see
// resilience:hosted-entrypoint-signal-and-hang-supervision — before that,
// PID 1 in the hosted container was a shell with no trap/exec, so nothing
// sent here ever arrived), the only built-in way to see every goroutine's
// stack is Go's default SIGQUIT handler. That handler ALSO aborts the
// process, which is wrong for a diagnostic: a dump nobody dares trigger
// against a host that might still be healthy is a dump nobody ever
// triggers. This package is the non-fatal alternative for SIGUSR1 —
// SIGQUIT's default behaviour is deliberately left untouched, so a genuinely
// wedged process can still be killed-with-evidence via SIGQUIT if that is
// ever wanted, while SIGUSR1 is safe to fire speculatively.
//
// Start (see diagdump_unix.go / diagdump_windows.go) is platform-split the
// same way internal/vpn's deadman switch is: SIGUSR1 doesn't exist on
// Windows, and the hosted container form this exists for is Linux-only
// anyway (a Windows BYOD host's workspace runs inside the WSL2 distro
// internal/wsl provisions, which is where this would need to be armed
// instead, same as deadman_windows.go's reasoning) — Start still needs to
// exist as a symbol so this builds for windows/amd64, which the release
// workflow does.
package diagdump

import (
	"runtime"

	"github.com/tekflox/aw-remote-host/internal/rlog"
)

// initialBufSize is generous enough for a normal process (a few dozen
// goroutines); dump grows the buffer instead of silently truncating
// whenever it isn't.
const (
	initialBufSize = 64 * 1024
	maxBufSize     = 8 * 1024 * 1024
)

// dump writes every goroutine's stack to the log, growing the buffer if the
// first attempt was too small rather than emitting a truncated dump that
// misleads a human at 4am into thinking a goroutine had nothing on its
// stack.
func dump() {
	size := initialBufSize
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < size || size >= maxBufSize {
			rlog.Printf("diagdump: SIGUSR1 — %d goroutine(s), dump follows:\n%s", runtime.NumGoroutine(), buf[:n])
			return
		}
		size *= 2
	}
}
