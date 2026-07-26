// Package shell implements Phase 3's PTY channel — the host side of the
// pty_open/pty_input/pty_output/pty_resize/pty_close frames link.go's pump()
// dispatches (see that file's module docstring for the frame protocol,
// mirrored in aw-backend's src/api/routes/host_link.py). Each pty_open
// spawns an interactive shell INSIDE the workspace container
// (`podman exec -it aw-remote-host-workspace bash`, falling back to `sh`
// if bash isn't installed in the image) and streams its stdout/stderr back
// as pty_output frames, keyed by the session id the browser/control-plane
// picked — multiple concurrent sessions are supported.
package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// Spawner starts a new PTY-backed shell process. Overridable in tests so
// they never touch a real podman/creack-pty.
type Spawner func(ctx context.Context) (PTY, error)

// DefaultSpawner runs an interactive shell inside the workspace container.
// The bash-then-sh fallback happens INSIDE the container (via `sh -c`)
// rather than by inspecting the podman-exec exit code here, since a missing
// `bash` only surfaces as the shell exiting immediately with "not found" —
// by the time creack/pty.Start returns, podman exec has already succeeded
// at the process-spawn level regardless of whether bash exists.
func DefaultSpawner(ctx context.Context) (PTY, error) {
	cmd := exec.CommandContext(ctx, "podman", "exec", "-it", ops.WorkspaceContainer,
		"sh", "-c", "exec bash 2>/dev/null || exec sh")
	f, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}
	return &execPTY{cmd: cmd, f: f}, nil
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

// Open spawns a new PTY for id and starts pumping its output as pty_output
// frames. Returns an error if id is already open or the spawn fails.
func (m *Manager) Open(ctx context.Context, id string, cols, rows uint16) error {
	m.mu.Lock()
	if _, exists := m.sessions[id]; exists {
		m.mu.Unlock()
		return fmt.Errorf("pty session %q already open", id)
	}
	m.mu.Unlock()

	p, err := m.spawner(ctx)
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
