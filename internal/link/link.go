// Package link is the WebSocket client that dials the control plane's
// /link endpoint (server side: aw-backend's src/api/routes/host_link.py),
// redeems an awbs_ bootstrap token for a durable awlk_ host credential on
// first connect, and keeps a persistent reconnecting session alive
// afterwards using that stored credential.
//
// Phase 3 PTY channel: on top of the Phase 2 cmd/cmd_result/activity
// frames, five more frame types bridge an interactive shell inside the
// workspace container, keyed by a session id the control plane picks —
// multiple concurrent sessions are supported:
//
//   - control-plane -> host: {"op":"pty_open","id","cols","rows"}
//   - control-plane -> host: {"op":"pty_input","id","data"} (base64)
//   - host -> control-plane: {"op":"pty_output","id","data"} (base64)
//   - control-plane -> host: {"op":"pty_resize","id","cols","rows"}
//   - either direction:      {"op":"pty_close","id","reason"?}
//
// data is always base64 — PTY output isn't guaranteed valid UTF-8. See
// internal/shell for the Manager that spawns/pumps the actual PTYs; pump()
// below just dispatches frames to whatever ShellManager RunCallbacks.OnShell
// builds for the live connection.
package link

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// RegisterInfo is the client-identifying data sent in every register frame.
type RegisterInfo struct {
	Hostname        string
	OS              string
	Arch            string
	CLIVersion      string
	BootstrapReport map[string]any
}

// RegisteredReply is the server's response to a register frame.
// HostCredential is only present on a fresh bootstrap-token redemption;
// WorkspaceSlug tells the client which workspace it was scoped to (so the
// user never has to type a slug — see the card-4 design).
type RegisteredReply struct {
	Op             string `json:"op"`
	RemoteHostID   string `json:"remote_host_id"`
	HostCredential string `json:"host_credential,omitempty"`
	WorkspaceSlug  string `json:"workspace_slug,omitempty"`
}

// Client holds the connection parameters for a /link session.
type Client struct {
	ControlPlane string // e.g. https://api.aw.tekflox.com
	Token        string // --token flag; only used on first connect if no credential is stored yet
	Info         RegisterInfo

	MinBackoff time.Duration // default 1s
	MaxBackoff time.Duration // default 60s
}

// New builds a Client from the CLI's --control-plane and --token flags.
func New(controlPlane, token string) *Client {
	return &Client{ControlPlane: controlPlane, Token: token}
}

func (c *Client) minBackoff() time.Duration {
	if c.MinBackoff > 0 {
		return c.MinBackoff
	}
	return time.Second
}

func (c *Client) maxBackoff() time.Duration {
	if c.MaxBackoff > 0 {
		return c.MaxBackoff
	}
	return 60 * time.Second
}

// WebSocketURL returns the wss:// (or ws://) URL this client would dial.
func (c *Client) WebSocketURL() (string, error) {
	u, err := url.Parse(c.ControlPlane)
	if err != nil {
		return "", fmt.Errorf("parse control plane url: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported control plane scheme %q", u.Scheme)
	}
	u.Path = "/link"
	return u.String(), nil
}

func (c *Client) dial(ctx context.Context, token string) (*websocket.Conn, error) {
	wsURL, err := c.WebSocketURL()
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", wsURL, err)
	}
	return conn, nil
}

func (c *Client) registerFrame() map[string]any {
	frame := map[string]any{
		"op":          "register",
		"kind":        "workspace-host",
		"hostname":    c.Info.Hostname,
		"os":          c.Info.OS,
		"arch":        c.Info.Arch,
		"cli_version": c.Info.CLIVersion,
	}
	if c.Info.BootstrapReport != nil {
		frame["bootstrap_report"] = c.Info.BootstrapReport
	}
	return frame
}

func register(conn *websocket.Conn, frame map[string]any) (*RegisteredReply, error) {
	if err := conn.WriteJSON(frame); err != nil {
		return nil, fmt.Errorf("send register frame: %w", err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read registered reply: %w", err)
	}
	var reply RegisteredReply
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, fmt.Errorf("parse registered reply: %w", err)
	}
	if reply.Op != "registered" {
		return nil, fmt.Errorf("unexpected reply op %q", reply.Op)
	}
	return &reply, nil
}

// ConnectResult is a single successful dial+register.
type ConnectResult struct {
	Conn  *websocket.Conn
	Reply *RegisteredReply
}

// Connect dials /link with token, sends the register frame, and — if the
// server minted a fresh host_credential (first-time bootstrap redemption)
// — persists it to credentialsPath. Returns the live connection; the
// caller owns closing it.
func (c *Client) Connect(ctx context.Context, token, credentialsPath string) (*ConnectResult, error) {
	conn, err := c.dial(ctx, token)
	if err != nil {
		return nil, err
	}
	reply, err := register(conn, c.registerFrame())
	if err != nil {
		conn.Close()
		return nil, err
	}
	if reply.HostCredential != "" {
		if err := SaveCredentials(credentialsPath, &Credentials{
			RemoteHostID:   reply.RemoteHostID,
			HostCredential: reply.HostCredential,
		}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("persist credentials: %w", err)
		}
	}
	return &ConnectResult{Conn: conn, Reply: reply}, nil
}

// Emit sends an unsolicited activity event ({"op":"activity", ...}) back
// over the live /link connection — the tunnel-protocol counterpart of
// aw-backend's activity_log.record(). Passed to CommandHandler so a verb
// (e.g. bootstrap) can stream progress while it runs.
type Emit func(level, phase, message string)

// CommandHandler processes one inbound {"op":"cmd", "id", "verb", "args"}
// frame and returns the verb-specific result data (or an error) for the
// {"op":"cmd_result"} reply. Runs in its own goroutine per command (see
// handleCmd) so a slow verb (bootstrap) never blocks the read loop that
// keeps the liveness ping/pong alive.
type CommandHandler func(ctx context.Context, verb string, args map[string]any, emit Emit) (data any, err error)

// ShellManager abstracts internal/shell's Manager so this package doesn't
// need to import it directly — just the shape pump()'s pty_* dispatch
// needs. One instance is scoped to a single live /link connection (built
// fresh per connection by NewShellManagerFunc, torn down via CloseAll when
// the connection drops).
type ShellManager interface {
	Open(ctx context.Context, id string, cols, rows uint16) error
	Input(id string, data []byte) error
	Resize(id string, cols, rows uint16) error
	Close(id string) error
	CloseAll()
}

// NewShellManagerFunc builds a fresh ShellManager for one live connection,
// wired to emit pty_output frames (dataB64) via the given callback.
type NewShellManagerFunc func(emit func(id, dataB64 string)) ShellManager

// RunCallbacks lets the CLI react to state changes in the reconnect loop
// without Run needing to know about logging/UI concerns.
type RunCallbacks struct {
	OnRegistered func(reply *RegisteredReply)
	OnDisconnect func(err error) // err is nil on a clean ctx cancellation
	OnCommand    CommandHandler  // nil = every "cmd" frame gets an error cmd_result
	OnShell      NewShellManagerFunc // nil = every "pty_open" frame gets a pty_close error reply
}

// Run keeps a /link session alive for as long as ctx is not cancelled:
// connect, register, pump frames (auto-replying to server pings) until the
// connection drops, then reconnect with exponential backoff (1s->60s cap,
// reset on every successful registration) using whatever credential is on
// disk by then (so a bootstrap token is only ever needed once).
func (c *Client) Run(ctx context.Context, credentialsPath string, cb RunCallbacks) error {
	backoff := c.minBackoff()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		token := c.Token
		if creds, _ := LoadCredentials(credentialsPath); creds != nil && creds.HostCredential != "" {
			token = creds.HostCredential
		}
		if token == "" {
			return fmt.Errorf("no token available: pass --token, or link once so a credential is stored at %s", credentialsPath)
		}

		result, err := c.Connect(ctx, token, credentialsPath)
		if err != nil {
			if cb.OnDisconnect != nil {
				cb.OnDisconnect(err)
			}
			if !sleepBackoff(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, c.maxBackoff())
			continue
		}

		backoff = c.minBackoff()
		if cb.OnRegistered != nil {
			cb.OnRegistered(result.Reply)
		}

		pumpErr := pump(ctx, result.Conn, cb.OnCommand, cb.OnShell)
		result.Conn.Close()
		if cb.OnDisconnect != nil {
			cb.OnDisconnect(pumpErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !sleepBackoff(ctx, backoff) {
			return ctx.Err()
		}
		backoff = nextBackoff(backoff, c.maxBackoff())
	}
}

// frameWriter serializes writes to conn — pump's own ping/pong replies and
// the per-command goroutines spawned by handleCmd (cmd_result + any
// activity frames a slow verb emits along the way) all write through this,
// since gorilla/websocket connections aren't safe for concurrent writers.
type frameWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (w *frameWriter) WriteJSON(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.WriteJSON(v)
}

// pump reads frames until the connection closes or ctx is cancelled,
// replying to server-initiated liveness pings ({"op":"ping"}) with a pong
// frame (any client frame refreshes the server's last_seen_at), dispatching
// {"op":"cmd"} frames to handler, and — via newShell — bridging the Phase 3
// pty_* frames to a per-connection ShellManager. Every open PTY session is
// torn down (CloseAll) when the connection drops, since a dead tunnel can
// never deliver another pty_input for it.
func pump(ctx context.Context, conn *websocket.Conn, handler CommandHandler, newShell NewShellManagerFunc) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()

	fw := &frameWriter{conn: conn}

	var shellMgr ShellManager
	if newShell != nil {
		shellMgr = newShell(func(id, dataB64 string) {
			_ = fw.WriteJSON(map[string]any{"op": "pty_output", "id": id, "data": dataB64})
		})
		defer shellMgr.CloseAll()
	}

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var msg map[string]any
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		switch msg["op"] {
		case "ping":
			if err := fw.WriteJSON(map[string]string{"op": "pong"}); err != nil {
				return err
			}
		case "cmd":
			handleCmd(ctx, fw, msg, handler)
		case "pty_open":
			handlePTYOpen(ctx, fw, msg, shellMgr)
		case "pty_input":
			handlePTYInput(msg, shellMgr)
		case "pty_resize":
			handlePTYResize(msg, shellMgr)
		case "pty_close":
			handlePTYClose(msg, shellMgr)
		}
	}
}

func ptyDims(msg map[string]any) (id string, cols, rows uint16) {
	id, _ = msg["id"].(string)
	if c, ok := msg["cols"].(float64); ok {
		cols = uint16(c)
	}
	if r, ok := msg["rows"].(float64); ok {
		rows = uint16(r)
	}
	return
}

// handlePTYOpen spawns the session in its own goroutine — podman-exec
// startup can take a noticeable moment and must not block the read loop
// (same rationale as handleCmd). A spawn failure is reported as a
// pty_close with a reason rather than silently dropping the session, so
// the browser doesn't hang on a black terminal.
func handlePTYOpen(ctx context.Context, fw *frameWriter, msg map[string]any, mgr ShellManager) {
	id, cols, rows := ptyDims(msg)
	if mgr == nil {
		_ = fw.WriteJSON(map[string]any{"op": "pty_close", "id": id, "reason": "no shell manager registered on this host"})
		return
	}
	go func() {
		if err := mgr.Open(ctx, id, cols, rows); err != nil {
			_ = fw.WriteJSON(map[string]any{"op": "pty_close", "id": id, "reason": err.Error()})
		}
	}()
}

func handlePTYInput(msg map[string]any, mgr ShellManager) {
	if mgr == nil {
		return
	}
	id, _ := msg["id"].(string)
	dataB64, _ := msg["data"].(string)
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return
	}
	_ = mgr.Input(id, data)
}

func handlePTYResize(msg map[string]any, mgr ShellManager) {
	if mgr == nil {
		return
	}
	id, cols, rows := ptyDims(msg)
	_ = mgr.Resize(id, cols, rows)
}

func handlePTYClose(msg map[string]any, mgr ShellManager) {
	if mgr == nil {
		return
	}
	id, _ := msg["id"].(string)
	_ = mgr.Close(id)
}

// handleCmd runs handler in its own goroutine (a verb like bootstrap can
// take minutes — it must not block pump's read loop, or the connection
// would look dead and the server's liveness ping would go unanswered) and
// writes the {"op":"cmd_result"} reply when it finishes. Any activity
// events the handler emits along the way are written as they happen, not
// buffered until completion.
func handleCmd(ctx context.Context, fw *frameWriter, msg map[string]any, handler CommandHandler) {
	id, _ := msg["id"].(string)
	verb, _ := msg["verb"].(string)
	args, _ := msg["args"].(map[string]any)

	if handler == nil {
		_ = fw.WriteJSON(map[string]any{
			"op": "cmd_result", "id": id, "ok": false,
			"error": "no command handler registered on this host",
		})
		return
	}

	go func() {
		emit := func(level, phase, message string) {
			_ = fw.WriteJSON(map[string]any{
				"op": "activity", "ts": float64(time.Now().UnixNano()) / 1e9,
				"level": level, "phase": phase, "message": message,
			})
		}
		result, err := handler(ctx, verb, args, emit)
		out := map[string]any{"op": "cmd_result", "id": id, "ok": err == nil}
		if err != nil {
			out["error"] = err.Error()
		} else {
			out["data"] = result
		}
		_ = fw.WriteJSON(out)
	}()
}

func sleepBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		return max
	}
	return next
}
