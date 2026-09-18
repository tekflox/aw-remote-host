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
//
// Phase 4 HTTP/WS tunnel-proxy channel: on top of the above, six more frame
// types forward browser HTTP/WS traffic to the local aw-workspace HTTP
// server this host bootstrapped (see internal/tunnelproxy and aw-backend's
// src/api/routes/workspace_tunnel_proxy.py, the control-plane consumer),
// keyed by a request/session id the control plane picks:
//
//   - control-plane -> host: {"op":"http_req","id","method","path","headers","body"?} (b64)
//   - host -> control-plane: {"op":"http_resp_head","id","status","headers"}, then
//     zero or more {"op":"http_resp_chunk","id","data"} (b64), then {"op":"http_resp_end","id"}
//   - control-plane -> host: {"op":"ws_open","id","path","headers"}
//   - either direction:      {"op":"ws_msg","id","data","dir":"text"|"binary"} (data b64)
//   - either direction:      {"op":"ws_close","id","reason"?}
//
// pump() dispatches these to whatever TunnelProxy RunCallbacks.OnTunnelProxy
// builds for the live connection, same "one instance per connection, torn
// down on disconnect" shape as ShellManager.
package link

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	// HostPower is the elevated host access this machine grants app
	// containers (comma-separated grant names), and HostPowerRequested is
	// what the operator asked for. They differ when the host cannot deliver
	// something — `--host-power=all` on a Mac has no /dev/kvm to give.
	//
	// Both are sent so the console badge can show the DELTA, not just the
	// result. "You asked for kvm and this machine cannot provide it" is the
	// one thing about this feature nobody can discover otherwise: the
	// symptom otherwise shows up as a guest VM that is mysteriously slow.
	HostPower          string
	HostPowerRequested string
	// Elevated reports whether the aw-remote-host process itself is running
	// with elevated privileges (root euid on Unix, an elevated token on
	// Windows) — not whether the host CAN escalate, which is a different
	// question already answered by internal/vpn's Privileged(). This is what
	// lets the console show a "running as root" badge.
	Elevated bool
	// UsernsContained reports whether this daemon runs inside a REMAPPED
	// user namespace, and UsernsMeasured whether that could be determined
	// at all (it cannot on non-Linux hosts, which have no
	// /proc/self/uid_map). UIDMap carries the raw evidence.
	//
	// Sent alongside Elevated because Elevated alone cannot distinguish the
	// two shapes it gets used to judge: a userns-remapped container-root and
	// an uncontained host root both report Elevated=true. See
	// internal/hostfacts.UsernsContained for the full reasoning.
	UsernsContained bool
	UsernsMeasured  bool
	UIDMap          string
	// ContainerForm reports that this daemon IS the packaged container image,
	// and ContainerID which container. They are what let the control plane
	// send this host the update it can actually use: replacing the binary is
	// the whole job on a BYOD Mac or VM, but inside the image it updates the
	// host only until the next recreate. See hostfacts.ContainerForm for why
	// the recreate has to happen from outside, and why ContainerID is allowed
	// to be empty even when ContainerForm is true.
	ContainerForm bool
	ContainerID   string
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
	// Only carried by an {"op":"register_error"} reply — see
	// RegisterRefusedError. The control plane sends one and closes when it
	// declines a registration it could otherwise have accepted (today: the
	// workspace already has a host holding its placement).
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// ErrRegisterRefused marks a registration the control plane DECIDED against,
// as opposed to one that failed. Match with errors.Is.
var ErrRegisterRefused = errors.New("registration refused by the control plane")

// RegisterRefusedError is the {"op":"register_error"} reply, typed.
//
// It exists because Run treats every Connect failure as retryable, which is
// right for a dropped network and wrong for a decision: a refusal will be
// made identically on every retry, so backing off on it means an operator
// running --background never sees the reason at all — the service just sits
// there reconnecting forever. Terminal, so it reaches the operator's stdout.
type RegisterRefusedError struct {
	Code    string
	Message string
}

func (e *RegisterRefusedError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return fmt.Sprintf("registration refused (%s)", e.Code)
	}
	return ErrRegisterRefused.Error()
}

func (e *RegisterRefusedError) Unwrap() error { return ErrRegisterRefused }

// Client holds the connection parameters for a /link session.
type Client struct {
	ControlPlane string // e.g. https://api.aw.tekflox.com
	Token        string // --token flag; only used on first connect if no credential is stored yet
	Info         RegisterInfo

	MinBackoff time.Duration // default 1s
	MaxBackoff time.Duration // default 60s

	// RegisterReadTimeout bounds how long register() waits for the server's
	// "registered" reply after a successful WebSocket upgrade (default 30s).
	// PumpReadTimeout bounds how long pump()'s read loop waits for the next
	// frame from the server once registered (default 90s). Both exist so a
	// server that accepted the upgrade but never writes back — or a TCP
	// connection that dies silently mid-read, no FIN/RST — surfaces as a
	// read error within a bounded time instead of blocking conn.ReadMessage
	// forever, which used to wedge the process indefinitely: Run's
	// reconnect/backoff loop never got the chance to iterate because the
	// read it was blocked on never returned. Zero means "use the default".
	RegisterReadTimeout time.Duration
	PumpReadTimeout     time.Duration

	// HeartbeatFile, when set, has its mtime touched once per completed
	// pump() read-loop iteration — i.e. proof the loop is actually turning
	// (received and dispatched a frame), not merely that this process still
	// exists. Empty disables it (default: most callers, e.g. a plain `link`
	// on a developer machine, have no supervisor watching this file).
	//
	// This exists for the hosted container's entrypoint.sh, which restarts
	// this process on exit but previously had no way to notice one that is
	// alive yet wedged (deadlocked on the shared frameWriter mutex, stuck in
	// a handler, whatever) and so never exits on its own. The watcher on the
	// other end must use a staleness threshold well above PumpReadTimeout —
	// see resilience:hosted-entrypoint-signal-and-hang-supervision — or it
	// will kill a link that is merely idle, which is worse than the bug.
	HeartbeatFile string
}

// defaultRegisterReadTimeout / defaultPumpReadTimeout are the production
// defaults behind Client.RegisterReadTimeout / PumpReadTimeout above.
// defaultPumpReadTimeout is set comfortably above aw-backend's own
// PONG_TIMEOUT_S (60s = 2x its 30s PING_INTERVAL_S, see host_link.py) so a
// healthy connection's normal server-initiated ping cadence never trips it,
// while the server's own dead-connection cleanup fires first in the common
// case and this is just the client-side backstop for when it doesn't.
const (
	defaultRegisterReadTimeout = 30 * time.Second
	defaultPumpReadTimeout     = 90 * time.Second
)

func (c *Client) registerReadTimeout() time.Duration {
	if c.RegisterReadTimeout > 0 {
		return c.RegisterReadTimeout
	}
	return defaultRegisterReadTimeout
}

func (c *Client) pumpReadTimeout() time.Duration {
	if c.PumpReadTimeout > 0 {
		return c.PumpReadTimeout
	}
	return defaultPumpReadTimeout
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
	// Sent on every register, including reconnects, and including when empty:
	// the backend's reconnect path only overwrites a field when the frame
	// carries a truthy value, so a host that REVOKED its grants has to be
	// able to say so. An empty string is a real state here, not a missing one.
	frame["host_power"] = c.Info.HostPower
	frame["host_power_requested"] = c.Info.HostPowerRequested
	// Sent unconditionally, including false: a host that stopped running as
	// root has to be able to say so, same reasoning as host_power above.
	frame["elevated"] = c.Info.Elevated
	// Only sent when it could actually be measured. Omitted (rather than
	// sent as false) on a host with no /proc/self/uid_map, so the backend's
	// "only overwrite on a key that is present" reconnect path leaves the
	// column NULL — "not measured" must not land in the DB as "measured,
	// not contained".
	if c.Info.UsernsMeasured {
		frame["userns_contained"] = c.Info.UsernsContained
		frame["uid_map"] = c.Info.UIDMap
	}
	// Only sent by the container form. Omitted entirely elsewhere so the
	// backend's "only overwrite on a key that is present" reconnect path
	// leaves the columns alone — same discipline as userns_contained above.
	// container_id can still be absent within it: a container whose hostname
	// was pinned by the operator cannot report one, and an empty string would
	// be a worse answer than none (see hostfacts.ContainerForm).
	if c.Info.ContainerForm {
		frame["container_form"] = true
		if c.Info.ContainerID != "" {
			frame["container_id"] = c.Info.ContainerID
		}
	}
	return frame
}

func register(conn *websocket.Conn, frame map[string]any, readTimeout time.Duration) (*RegisteredReply, error) {
	if err := conn.WriteJSON(frame); err != nil {
		return nil, fmt.Errorf("send register frame: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read registered reply: %w", err)
	}
	var reply RegisteredReply
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, fmt.Errorf("parse registered reply: %w", err)
	}
	if reply.Op == "register_error" {
		return nil, &RegisterRefusedError{Code: reply.Code, Message: reply.Message}
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
	reply, err := register(conn, c.registerFrame(), c.registerReadTimeout())
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

// DetachTimeout bounds the one HTTP call unlink makes. Short on purpose: it
// is best-effort courtesy to the control plane, and an operator unlinking a
// machine that has already lost its network must not wait on it.
const DetachTimeout = 10 * time.Second

// Detach tells the control plane this host is unlinking itself — POST
// /api/link/detach (aw-backend's host_link.HostLinkRoutes.detach_self),
// authenticated by this host's OWN awlk_ credential and revoking only its own
// RemoteHost row.
//
// unlink used to be purely local: it uninstalled the service, deleted
// credentials.json, and never said a word to the control plane, so a
// workspace's remote_host_id outlived the host holding it and the console
// reported a machine that had already gone (Kanban 3df5bf3b). The caller
// treats a failure here as a warning, not a fatal — the local unlink still
// has to finish on a machine that is offline.
func Detach(ctx context.Context, controlPlane, hostCredential string) error {
	u, err := url.Parse(controlPlane)
	if err != nil {
		return fmt.Errorf("parse control plane url: %w", err)
	}
	u.Path = "/api/link/detach"
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build detach request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+hostCredential)

	client := &http.Client{Timeout: DetachTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", u.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Bounded: an error body is a sentence, not a payload, and an HTML
		// error page from a proxy in front of the control plane could be
		// megabytes.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		detail := strings.TrimSpace(string(body))
		if detail != "" {
			return fmt.Errorf("control plane returned %s: %s", resp.Status, detail)
		}
		return fmt.Errorf("control plane returned %s", resp.Status)
	}
	return nil
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
	Open(ctx context.Context, id string, cols, rows uint16, target string) error
	Input(id string, data []byte) error
	Resize(id string, cols, rows uint16) error
	Close(id string) error
	CloseAll()
}

// NewShellManagerFunc builds a fresh ShellManager for one live connection,
// wired to emit pty_output frames (dataB64) via the given callback.
type NewShellManagerFunc func(emit func(id, dataB64 string)) ShellManager

// TunnelProxy abstracts internal/tunnelproxy's Handler so this package
// doesn't need to import it directly — just the shape pump()'s Phase 4
// http_req/ws_* dispatch needs. One instance is scoped to a single live
// /link connection (built fresh per connection by NewTunnelProxyFunc, torn
// down via CloseAllWS when the connection drops — mirrors ShellManager).
type TunnelProxy interface {
	ServeHTTP(
		ctx context.Context, id, method, path string, headers map[string]string, body []byte,
		head func(id string, status int, headers map[string]string),
		chunk func(id string, data []byte),
		end func(id string),
	)
	OpenWS(ctx context.Context, id, path string, headers map[string]string, sendMsg func(id string, data []byte, isText bool)) error
	WSMessage(id string, data []byte, isText bool) error
	CloseWS(id string) error
	CloseAllWS()
}

// TCPProxy is the OPTIONAL tcp_* half of the tunnel — a proxy that can also
// dial an arbitrary host:port from this machine (see internal/tcpproxy).
// Deliberately a separate interface, type-asserted at dispatch: an older or
// narrower TunnelProxy that only knows http/ws still satisfies TunnelProxy,
// and its tcp_open frames are answered with a close+reason instead of a
// compile error or a panic.
type TCPProxy interface {
	OpenTCP(ctx context.Context, id, host string, port int,
		sendData func(id string, data []byte),
		onEOF func(id string, reason string)) error
	SendTCP(id string, data []byte) error
	CloseTCP(id string) error
	CloseAllTCP()
}

// NewTunnelProxyFunc builds a fresh TunnelProxy for one live connection.
type NewTunnelProxyFunc func() TunnelProxy

// RunCallbacks lets the CLI react to state changes in the reconnect loop
// without Run needing to know about logging/UI concerns.
type RunCallbacks struct {
	OnRegistered  func(reply *RegisteredReply)
	OnDisconnect  func(err error)     // err is nil on a clean ctx cancellation
	OnCommand     CommandHandler      // nil = every "cmd" frame gets an error cmd_result
	OnShell       NewShellManagerFunc // nil = every "pty_open" frame gets a pty_close error reply
	OnTunnelProxy NewTunnelProxyFunc  // nil = every "http_req"/"ws_open" frame is dropped with an error reply
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
		if err != nil && !errors.Is(err, ErrRegisterRefused) && c.Token != "" && c.Token != token {
			// A saved host credential can become invalid after an uninstall or
			// workspace reset. If the operator supplied a fresh bootstrap token,
			// fall back to it once before backing off so BYOD reinstall can
			// recover without manual credential-file cleanup.
			//
			// Skipped on a refusal, and that exclusion is load-bearing — it is
			// NOT covered by the terminal check below, because this retry runs
			// FIRST. The control plane refuses a reconnect whose workspace is
			// placed elsewhere; falling through to here would then redeem the
			// operator's single-use bootstrap token against the very
			// registration we were just told to stop attempting, burning it on
			// a machine that will be refused again anyway. The operator is then
			// left with no token and a 4403 that explains nothing.
			result, err = c.Connect(ctx, c.Token, credentialsPath)
		}
		if err != nil {
			if cb.OnDisconnect != nil {
				cb.OnDisconnect(err)
			}
			// Terminal: the control plane refused this registration on
			// purpose, and will refuse it identically for as long as whatever
			// it named stays true. Retrying would bury the one message that
			// tells the operator what to do about it under a backoff loop
			// nobody reads — and under --background, nobody would ever see it.
			// Returned so runLinkOrBootstrap's runDone path prints it.
			if errors.Is(err, ErrRegisterRefused) {
				return err
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

		pumpErr := pump(ctx, result.Conn, c.pumpReadTimeout(), c.HeartbeatFile, cb.OnCommand, cb.OnShell, cb.OnTunnelProxy)
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
// {"op":"cmd"} frames to handler, — via newShell — bridging the Phase 3
// pty_* frames to a per-connection ShellManager, and — via newTunnelProxy —
// bridging the Phase 4 http_req/ws_* frames to a per-connection TunnelProxy.
// Every open PTY session / ws proxy session is torn down (CloseAll/
// CloseAllWS) when the connection drops, since a dead tunnel can never
// deliver another pty_input/ws_msg for any of them.
//
// Each iteration renews conn's read deadline to now+readTimeout before
// blocking on ReadMessage, so a connection that goes silent — the server
// hangs, or the TCP path dies with no FIN/RST — surfaces as a read error
// (and this function returning) within readTimeout instead of blocking
// forever and starving Run's reconnect/backoff loop of its next iteration.
func pump(ctx context.Context, conn *websocket.Conn, readTimeout time.Duration, heartbeatFile string, handler CommandHandler, newShell NewShellManagerFunc, newTunnelProxy NewTunnelProxyFunc) error {
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

	var proxy TunnelProxy
	if newTunnelProxy != nil {
		proxy = newTunnelProxy()
		defer proxy.CloseAllWS()
	}

	for {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return err
		}
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		touchHeartbeat(heartbeatFile)
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
		case "http_req":
			handleHTTPReq(ctx, fw, msg, proxy)
		case "ws_open":
			handleWSOpen(ctx, fw, msg, proxy)
		case "ws_msg":
			handleWSMsg(msg, proxy)
		case "ws_close":
			handleWSClose(msg, proxy)
		case "tcp_open":
			handleTCPOpen(ctx, fw, msg, proxy)
		case "tcp_data":
			handleTCPData(msg, proxy)
		case "tcp_close":
			handleTCPClose(msg, proxy)
		}
	}
}

// touchHeartbeat updates path's mtime to now, creating it on the first call.
// Best-effort: a supervisor reading a stale or missing file treats it the
// same as "not turning", so any error here just leaves that signal as-is
// rather than being worth failing the pump over. No-op when path is empty.
func touchHeartbeat(path string) {
	if path == "" {
		return
	}
	now := time.Now()
	if err := os.Chtimes(path, now, now); err == nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return
	}
	f.Close()
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

// ptyTarget reads pty_open's optional "target" field — "host" for a shell on
// the box running this process, "workspace" (or absent, for control planes
// older than the field) for the workspace container. Validation belongs to the
// shell package, which owns what the values mean; this only extracts.
func ptyTarget(msg map[string]any) string {
	target, _ := msg["target"].(string)
	return target
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
	target := ptyTarget(msg)
	go func() {
		if err := mgr.Open(ctx, id, cols, rows, target); err != nil {
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

func stringMap(v any) map[string]string {
	out := map[string]string{}
	m, _ := v.(map[string]any)
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

// handleHTTPReq forwards one http_req frame to proxy.ServeHTTP in its own
// goroutine (the local workspace server's response could take a while —
// must not block the read loop, same rationale as handleCmd) and streams
// the reply back as http_resp_head/chunk/end frames.
func handleHTTPReq(ctx context.Context, fw *frameWriter, msg map[string]any, proxy TunnelProxy) {
	id, _ := msg["id"].(string)
	method, _ := msg["method"].(string)
	path, _ := msg["path"].(string)
	headers := stringMap(msg["headers"])

	var body []byte
	if b64, ok := msg["body"].(string); ok && b64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			body = decoded
		}
	}

	if proxy == nil {
		_ = fw.WriteJSON(map[string]any{
			"op": "http_resp_head", "id": id, "status": 502,
			"headers": map[string]string{"content-type": "text/plain"},
		})
		_ = fw.WriteJSON(map[string]any{
			"op": "http_resp_chunk", "id": id,
			"data": base64.StdEncoding.EncodeToString([]byte("no tunnel proxy registered on this host")),
		})
		_ = fw.WriteJSON(map[string]any{"op": "http_resp_end", "id": id})
		return
	}

	go func() {
		proxy.ServeHTTP(ctx, id, method, path, headers, body,
			func(id string, status int, headers map[string]string) {
				_ = fw.WriteJSON(map[string]any{"op": "http_resp_head", "id": id, "status": status, "headers": headers})
			},
			func(id string, data []byte) {
				_ = fw.WriteJSON(map[string]any{
					"op": "http_resp_chunk", "id": id, "data": base64.StdEncoding.EncodeToString(data),
				})
			},
			func(id string) {
				_ = fw.WriteJSON(map[string]any{"op": "http_resp_end", "id": id})
			},
		)
	}()
}

// handleWSOpen dials the local workspace server's WS endpoint in its own
// goroutine (dial can block briefly) — a dial failure is reported as a
// ws_close with a reason rather than silently dropping the session,
// mirroring handlePTYOpen.
func handleWSOpen(ctx context.Context, fw *frameWriter, msg map[string]any, proxy TunnelProxy) {
	id, _ := msg["id"].(string)
	path, _ := msg["path"].(string)
	headers := stringMap(msg["headers"])

	if proxy == nil {
		_ = fw.WriteJSON(map[string]any{"op": "ws_close", "id": id, "reason": "no tunnel proxy registered on this host"})
		return
	}

	go func() {
		err := proxy.OpenWS(ctx, id, path, headers, func(id string, data []byte, isText bool) {
			dir := "binary"
			if isText {
				dir = "text"
			}
			_ = fw.WriteJSON(map[string]any{
				"op": "ws_msg", "id": id, "data": base64.StdEncoding.EncodeToString(data), "dir": dir,
			})
		})
		if err != nil {
			_ = fw.WriteJSON(map[string]any{"op": "ws_close", "id": id, "reason": err.Error()})
		}
	}()
}

func handleWSMsg(msg map[string]any, proxy TunnelProxy) {
	if proxy == nil {
		return
	}
	id, _ := msg["id"].(string)
	dataB64, _ := msg["data"].(string)
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return
	}
	isText := msg["dir"] == "text"
	_ = proxy.WSMessage(id, data, isText)
}

func handleWSClose(msg map[string]any, proxy TunnelProxy) {
	if proxy == nil {
		return
	}
	id, _ := msg["id"].(string)
	_ = proxy.CloseWS(id)
}

// tcpOf returns the proxy's tcp half, or nil when this build/implementation
// does not have one.
func tcpOf(proxy TunnelProxy) TCPProxy {
	t, _ := proxy.(TCPProxy)
	return t
}

func handleTCPOpen(ctx context.Context, fw *frameWriter, msg map[string]any, proxy TunnelProxy) {
	id, _ := msg["id"].(string)
	host, _ := msg["host"].(string)
	port := 0
	if p, ok := msg["port"].(float64); ok {
		port = int(p)
	}

	tcp := tcpOf(proxy)
	if tcp == nil {
		_ = fw.WriteJSON(map[string]any{
			"op": "tcp_close", "id": id, "reason": "no tcp proxy registered on this host"})
		return
	}

	// Dial off the read loop: a connect can take up to dialTimeout, and
	// blocking pump() there would stall every other frame on the tunnel
	// (same rationale as handleWSOpen/handleCmd).
	go func() {
		err := tcp.OpenTCP(ctx, id, host, port,
			func(id string, data []byte) {
				_ = fw.WriteJSON(map[string]any{
					"op": "tcp_data", "id": id,
					"data": base64.StdEncoding.EncodeToString(data)})
			},
			func(id string, reason string) {
				_ = fw.WriteJSON(map[string]any{"op": "tcp_close", "id": id, "reason": reason})
			})
		if err != nil {
			_ = fw.WriteJSON(map[string]any{"op": "tcp_close", "id": id, "reason": err.Error()})
			return
		}
		// Tell the control plane the socket is up, so it can distinguish
		// "connected, waiting for the server to speak first" (which is exactly
		// what RFB does) from "still dialing".
		_ = fw.WriteJSON(map[string]any{"op": "tcp_open_ok", "id": id})
	}()
}

func handleTCPData(msg map[string]any, proxy TunnelProxy) {
	tcp := tcpOf(proxy)
	if tcp == nil {
		return
	}
	id, _ := msg["id"].(string)
	dataB64, _ := msg["data"].(string)
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return
	}
	_ = tcp.SendTCP(id, data)
}

func handleTCPClose(msg map[string]any, proxy TunnelProxy) {
	tcp := tcpOf(proxy)
	if tcp == nil {
		return
	}
	id, _ := msg["id"].(string)
	_ = tcp.CloseTCP(id)
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
