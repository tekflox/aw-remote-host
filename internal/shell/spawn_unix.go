//go:build !windows

// The POSIX half of DefaultSpawner: a real pty(4) via creack/pty. The
// Windows twin is conpty_windows.go, which has to build its terminal by
// hand because creack/pty's Windows files are stubs.
package shell

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/tekflox/aw-remote-host/internal/ops"
)

// execPTY is the production PTY — a real podman-exec or local shell process
// attached to a creack/pty master.
type execPTY struct {
	cmd *exec.Cmd
	f   *os.File
}

func (e *execPTY) Read(p []byte) (int, error)  { return e.f.Read(p) }
func (e *execPTY) Write(p []byte) (int, error) { return e.f.Write(p) }

func (e *execPTY) Resize(cols, rows uint16) error {
	return pty.Setsize(e.f, &pty.Winsize{Cols: cols, Rows: rows})
}

func (e *execPTY) Close() error {
	_ = e.f.Close()
	if e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
		_, _ = e.cmd.Process.Wait()
	}
	return nil
}

// interactiveShell is the command both targets run: detect bash with
// `command -v` (redirecting only the *probe's* output), then exec it WITHOUT
// redirecting the shell's own stderr — an interactive bash writes its prompt
// (PS1) and readline UI to stderr, so the old `exec bash 2>/dev/null` silently
// discarded the prompt and the session looked dead until you typed a command
// whose stdout happened to show. `exec` replaces the process but keeps fd
// redirections, which is exactly why that redirection leaked into the shell.
const interactiveShell = "command -v bash >/dev/null 2>&1 && exec bash || exec sh"

// startPTY runs an interactive shell on resolved — inside the workspace
// container via podman exec, or directly on this host.
//
// The host branch is NOT `podman exec` minus the podman: it is this process's
// own environment, so it inherits whatever aw-remote-host was started with.
// That makes TERM the one thing worth forcing — a shell spawned from a systemd
// unit or a container entrypoint has no TERM at all, and bash then falls back
// to `dumb`, which kills arrow keys, colour and every full-screen program
// (vim, top) the interactive shell exists for.
func startPTY(ctx context.Context, resolved string) (PTY, error) {
	var cmd *exec.Cmd
	if resolved == TargetHost {
		cmd = exec.CommandContext(ctx, "sh", "-c", interactiveShell)
		cmd.Env = withTerm(os.Environ())
	} else {
		cmd = exec.CommandContext(ctx, "podman", "exec", "-it", ops.WorkspaceContainer,
			"sh", "-c", interactiveShell)
	}

	f, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start pty (%s): %w", resolved, err)
	}
	return &execPTY{cmd: cmd, f: f}, nil
}

// withTerm returns env with a usable TERM, leaving an existing one alone.
func withTerm(env []string) []string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "TERM=") && kv != "TERM=" {
			return env
		}
	}
	return append(env, "TERM=xterm-256color")
}
