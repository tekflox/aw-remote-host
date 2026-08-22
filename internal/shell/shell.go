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
//
// How the terminal itself is created is per-platform and lives next door:
// spawn_unix.go (creack/pty) and conpty_windows.go (Win32 ConPTY, built by
// hand because creack/pty's Windows files are stubs). Both export the same
// startPTY, so everything in this file is platform-agnostic.
package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
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
// tests so they never touch a real podman/pty.
type Spawner func(ctx context.Context, target string) (PTY, error)

// DefaultSpawner resolves the target and hands off to the platform's own
// startPTY — spawn_unix.go on POSIX, conpty_windows.go on Windows. The
// resolution is deliberately shared: an unknown target must be rejected
// identically everywhere, since it decides WHICH MACHINE a shell opens on.
func DefaultSpawner(ctx context.Context, target string) (PTY, error) {
	resolved, err := resolveTarget(target)
	if err != nil {
		return nil, err
	}
	return startPTY(ctx, resolved)
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
