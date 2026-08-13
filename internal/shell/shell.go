// Package shell implements Phase 3's PTY channel — the host side of the
// pty_open/pty_input/pty_output/pty_resize/pty_close frames link.go's pump()
// dispatches (see that file's module docstring for the frame protocol,
// mirrored in aw-backend's src/api/routes/host_link.py). Each pty_open spawns
// an interactive shell and streams its stdout/stderr back as pty_output
// frames, keyed by the session id the browser/control-plane picked —
// multiple concurrent sessions are supported.
//
// pty_open's "target" field picks WHICH MACHINE: "workspace" (or absent, for
// control planes older than the field) runs `podman exec -it
// aw-remote-host-workspace`, "host" runs the shell right here, on the box
// this process is running on. Bash with an `sh` fallback either way.
package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"
	"github.com/tekflox/aw-remote-host/internal/ops"
)

// PTY abstracts a spawned pseudo-terminal process so tests can inject a fake
// instead of shelling out to podman/creack-pty. Read/Write operate on the
// pty's master side (what a terminal emulator would see).
type PTY interface {
	io.Reader
	io.Writer
	Resize(cols, rows uint16) error
	Close() error
}

// execPTY is the production PTY — a real podman-exec process attached to a
// creack/pty master.
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

// Where a pty_open lands. These are two genuinely different machines, not a
// convenience flag: TargetWorkspace is inside the podman-managed workspace
// container, TargetHost is the box running this aw-remote-host process itself
// — which for a containerised deployment is that container, and for a bare
// metal deployment is the metal.
const (
	TargetWorkspace = "workspace"
	TargetHost      = "host"
)

// resolveTarget maps a pty_open's target field onto one of the two constants.
// An absent/empty target means TargetWorkspace, NOT TargetHost: the console's
// browser terminal has always sent no target and has always landed in the
// workspace container, and a control plane newer than this binary must not be
// able to silently redirect an existing session onto the host. Any unknown
// value is an error rather than a default, so a typo fails loudly instead of
// opening a shell somewhere the caller did not ask for.
func resolveTarget(target string) (string, error) {
	switch target {
	case "", TargetWorkspace:
		return TargetWorkspace, nil
	case TargetHost:
		return TargetHost, nil
	default:
		return "", fmt.Errorf("unknown pty target %q (expected %q or %q)", target, TargetHost, TargetWorkspace)
	}
}

// Spawner starts a new PTY-backed shell process on target. Overridable in
// tests so they never touch a real podman/creack-pty.
type Spawner func(ctx context.Context, target string) (PTY, error)

// interactiveShell is the command both targets run: detect bash with
// `command -v` (redirecting only the *probe's* output), then exec it WITHOUT
// redirecting the shell's own stderr — an interactive bash writes its prompt
// (PS1) and readline UI to stderr, so the old `exec bash 2>/dev/null` silently
// discarded the prompt and the session looked dead until you typed a command
// whose stdout happened to show. `exec` replaces the process but keeps fd
// redirections, which is exactly why that redirection leaked into the shell.
const interactiveShell = "command -v bash >/dev/null 2>&1 && exec bash || exec sh"

// DefaultSpawner runs an interactive shell on target — inside the workspace
// container via podman exec, or directly on this host.
//
// The host branch is NOT `podman exec` minus the podman: it is this process's
// own environment, so it inherits whatever aw-remote-host was started with.
// That makes TERM the one thing worth forcing — a shell spawned from a systemd
// unit or a container entrypoint has no TERM at all, and bash then falls back
// to `dumb`, which kills arrow keys, colour and every full-screen program
// (vim, top) the interactive shell exists for.
func DefaultSpawner(ctx context.Context, target string) (PTY, error) {
	resolved, err := resolveTarget(target)
	if err != nil {
		return nil, err
	}

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

// EmitFunc sends a pty_output frame for sessionID back over the /link
// connection. data is raw bytes — the caller (Manager) base64-encodes it,
// since PTY output isn't guaranteed valid UTF-8.
type EmitFunc func(sessionID string, dataB64 string)

// session tracks one open PTY keyed by the id the control plane assigned.
type session struct {
	pty    PTY
	closed chan struct{}
}

// Manager multiplexes concurrent PTY sessions over a single /link
// connection. Not safe for use after CloseAll.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*session
	spawner  Spawner
	emit     EmitFunc
}

// NewManager builds a Manager. spawner defaults to DefaultSpawner if nil —
// tests pass a fake to avoid touching podman/creack-pty.
func NewManager(spawner Spawner, emit EmitFunc) *Manager {
	if spawner == nil {
		spawner = DefaultSpawner
	}
	return &Manager{sessions: map[string]*session{}, spawner: spawner, emit: emit}
}

// Open spawns a new PTY for id on target ("host", "workspace", or "" for the
// workspace container) and starts pumping its output as pty_output frames.
// Returns an error if id is already open, target is unknown, or the spawn
// fails.
func (m *Manager) Open(ctx context.Context, id string, cols, rows uint16, target string) error {
	m.mu.Lock()
	if _, exists := m.sessions[id]; exists {
		m.mu.Unlock()
		return fmt.Errorf("pty session %q already open", id)
	}
	m.mu.Unlock()

	p, err := m.spawner(ctx, target)
	if err != nil {
		return err
	}
	if cols > 0 && rows > 0 {
		_ = p.Resize(cols, rows) // best-effort — an initial size failure shouldn't block the session
	}

	sess := &session{pty: p, closed: make(chan struct{})}
	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()

	go m.pumpOutput(id, sess)
	return nil
}

// pumpOutput reads until the pty closes (process exit or Close() call),
// forwarding every chunk as a pty_output frame, then tears the session down.
func (m *Manager) pumpOutput(id string, sess *session) {
	buf := make([]byte, 4096)
	for {
		n, err := sess.pty.Read(buf)
		if n > 0 && m.emit != nil {
			m.emit(id, base64.StdEncoding.EncodeToString(buf[:n]))
		}
		if err != nil {
			break
		}
	}
	m.remove(id)
}

// Input writes bytes to id's pty stdin.
func (m *Manager) Input(id string, data []byte) error {
	sess := m.get(id)
	if sess == nil {
		return fmt.Errorf("no such pty session %q", id)
	}
	_, err := sess.pty.Write(data)
	return err
}

// Resize applies a TIOCSWINSZ resize to id's pty.
func (m *Manager) Resize(id string, cols, rows uint16) error {
	sess := m.get(id)
	if sess == nil {
		return fmt.Errorf("no such pty session %q", id)
	}
	return sess.pty.Resize(cols, rows)
}

// Close tears down id's pty (kills + reaps the process). No-op if id isn't
// open (already closed, or a close for an id that never opened).
func (m *Manager) Close(id string) error {
	return m.remove(id)
}

// CloseAll tears down every open session — called when the /link connection
// itself drops, since a dead tunnel can never deliver pty_input again.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.remove(id)
	}
}

func (m *Manager) get(id string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

func (m *Manager) remove(id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	select {
	case <-sess.closed:
	default:
		close(sess.closed)
	}
	return sess.pty.Close()
}
