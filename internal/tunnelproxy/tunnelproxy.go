// Package tunnelproxy is the host side of the /link tunnel's Phase 4
// HTTP/WS proxy channel (see internal/link's http_req/ws_* frame dispatch
// and aw-backend's src/api/routes/workspace_tunnel_proxy.py, the control-
// plane consumer). It forwards each http_req/ws_open frame to the LOCAL
// aw-workspace HTTP server this host bootstrapped (see internal/ops —
// same 127.0.0.1:9030 address ops.HealthURL already probes for the health
// verb), streaming the response/ws frames back over the callbacks link.go
// wires to the live connection's frameWriter.
package tunnelproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/tekflox/aw-remote-host/internal/rlog"
)

// DefaultTarget is the local aw-workspace HTTP server this host bootstrapped
// — same address ops.HealthURL probes for the "health" cmd verb.
const DefaultTarget = "http://127.0.0.1:9030"

// chunkSize bounds how much of a response body travels in one
// http_resp_chunk frame — keeps a single frame well under typical
// WebSocket/base64 overhead limits without adding real latency.
const chunkSize = 32 * 1024

// The dial-retry envelope. 127.0.0.1:9030 is not really loopback on a BYOD
// Mac: the workspace container lives inside the podman-machine VM, so this
// address is that VM's gvproxy port-forward, and gvproxy drops the odd
// connection-setup packet. A single dropped SYN used to surface as a hard
// 502 "upstream unreachable" on the very first occurrence — an app install
// failing in the browser while the local server was never down at all.
//
// Retry lives HERE, at the dial, and nowhere else in this package. A failed
// net.Dial means no connection exists, therefore no request bytes were
// written, therefore replaying is provably free of side effects. Retrying
// one layer up — around client.Do — would also catch "request was fully
// written and the server processed it, then the connection broke before the
// response headers came back", and re-issuing that POST would double-install
// the app. The dial layer gets that proof structurally instead of by comment.
//
// The envelope is deliberately sub-second, NOT internal/link's 1s→60s
// reconnect scale: aw-backend's relay gives this whole exchange 30s total
// (HTTP_TIMEOUT_S in src/api/routes/workspace_tunnel_proxy.py:195, a hard
// deadline from send_http_req to the head frame's arrival), and blowing it
// serves the browser an offline page — strictly worse than the 502. Worst
// case added here is 3×2s + 50ms + 100ms ≈ 6.15s, leaving ~24s for the real
// request; the common connection-refused case returns in microseconds, so
// the realistic cost is the 150ms of sleep.
const (
	dialAttempts       = 3 // 1 original + 2 retries
	dialTimeout        = 2 * time.Second
	dialBackoffMin     = 50 * time.Millisecond
	dialBackoffMax     = 200 * time.Millisecond
	wsHandshakeTimeout = 10 * time.Second
)

// Handler forwards http_req/ws_open frames to Target — one instance is
// scoped to a single live /link connection (mirrors shell.Manager), so its
// ws connection map is torn down wholesale on disconnect via CloseAll.
type Handler struct {
	Target string // base URL of the local workspace HTTP server; DefaultTarget if empty
	Client *http.Client

	// Test seams for the dial-retry envelope above — zero means the const,
	// same idiom as link.Client's MinBackoff/MaxBackoff. Tests shrink these
	// so they don't eat real backoff; production never sets them.
	DialAttempts   int
	DialTimeout    time.Duration
	DialBackoffMin time.Duration
	DialBackoffMax time.Duration

	// dialTCP substitutes the single dial attempt inside dialContext — a
	// test seam, unexported because only this package's own tests set it.
	// Per-Handler rather than a package var like internal/vpn's confPresent:
	// http.Transport abandons an in-flight dial goroutine the moment ctx is
	// cancelled, so a global would get swapped back underneath a goroutine
	// that outlives the test which installed it.
	dialTCP func(ctx context.Context, timeout time.Duration, network, addr string) (net.Conn, error)

	clientOnce sync.Once
	httpClient *http.Client

	wsDialerOnce sync.Once
	wsDialerVal  *websocket.Dialer

	mu      sync.Mutex
	wsConns map[string]*websocket.Conn
}

// NewHandler builds a Handler targeting DefaultTarget. The HTTP client is
// built lazily by client() so it picks up the retrying dialer — see the
// dial-retry envelope above, and note that a bare &http.Client{} would
// inherit http.DefaultTransport's 30s dial timeout, dead-equal to the
// relay's own 30s budget: a gvproxy hop that blackholes the SYN instead of
// refusing it would then hang until the control plane gave up first, and no
// retry would ever run.
func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) target() string {
	if h.Target != "" {
		return h.Target
	}
	return DefaultTarget
}

func (h *Handler) client() *http.Client {
	// A caller-supplied Client is theirs — respect it, inject nothing. It
	// owns its own redirect policy too, and a proxy's Client must set
	// CheckRedirect for the reason spelled out below.
	if h.Client != nil {
		return h.Client
	}
	h.clientOnce.Do(func() {
		// Clone: http.DefaultTransport is process-global, and mutating it
		// would change dial behaviour for every unrelated caller in this
		// binary. No Client.Timeout — long-lived streaming responses are
		// expected; the control plane owns per-request timeouts.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = h.dialContext
		h.httpClient = &http.Client{
			Transport: tr,
			// A proxy relays a 3xx; it does not chase it. Go's default
			// policy follows up to 10 redirects, which turned every
			// redirect the local workspace emitted into a body fetched
			// here and served under the workspace's OWN origin — the
			// browser never saw the 302 and never left the origin. That
			// broke /api/apps/google-workspace-mcp/oauth/start: Google's
			// consent page arrived as 200 HTML from
			// api.<slug>.workspace.<domain>, so its own scripts were
			// blocked by CORS and the sign-in form was inert.
			//
			// Worse than wrong: a Location is usually ABSOLUTE and often
			// off-host, so the default policy had this agent dialling
			// arbitrary third-party URLs from the user's own machine.
			// ErrUseLastResponse hands the 3xx back untouched — status
			// and Location relay through the head frame like any other
			// response, and the browser does the redirect itself.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return h.httpClient
}

// wsDialer is OpenWS's dialer. Handler-owned rather than
// websocket.DefaultDialer, which is a package global shared with every other
// gorilla user in the process. HandshakeTimeout is 10s, not the default 45s:
// 45s outlives the relay's 30s budget, so the control plane gives up first
// and leaves the dial orphaned.
func (h *Handler) wsDialer() *websocket.Dialer {
	h.wsDialerOnce.Do(func() {
		h.wsDialerVal = &websocket.Dialer{
			NetDialContext:   h.dialContext,
			HandshakeTimeout: wsHandshakeTimeout,
		}
	})
	return h.wsDialerVal
}

func (h *Handler) attempts() int {
	if h.DialAttempts > 0 {
		return h.DialAttempts
	}
	return dialAttempts
}

func (h *Handler) perAttemptTimeout() time.Duration {
	if h.DialTimeout > 0 {
		return h.DialTimeout
	}
	return dialTimeout
}

func (h *Handler) backoffMin() time.Duration {
	if h.DialBackoffMin > 0 {
		return h.DialBackoffMin
	}
	return dialBackoffMin
}

func (h *Handler) backoffMax() time.Duration {
	if h.DialBackoffMax > 0 {
		return h.DialBackoffMax
	}
	return dialBackoffMax
}

// realDialTCP is one dial attempt — what dialContext uses unless a test has
// substituted Handler.dialTCP.
func realDialTCP(ctx context.Context, timeout time.Duration, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}

// dialContext is the only place in this package a retry may live — see the
// dial-retry envelope above for why. Returns the LAST dial error unwrapped
// so ServeHTTP's "upstream unreachable: %v" stays readable.
func (h *Handler) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := h.dialTCP
	if dial == nil {
		dial = realDialTCP
	}
	timeout := h.perAttemptTimeout()
	attempts := h.attempts()
	backoff := h.backoffMin()
	maxBackoff := h.backoffMax()

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		conn, err := dial(ctx, timeout, network, addr)
		if err == nil {
			if attempt > 1 {
				// One line, only when a retry actually saved the request —
				// logging every first-attempt success would be per-request
				// noise. Without this a hop degrading from "rare blip" to
				// "failing half the time" would look perfectly healthy.
				rlog.Printf("tunnelproxy: dial %s recovered on attempt %d/%d (previous failure: %v)\n",
					addr, attempt, attempts, lastErr)
			}
			return conn, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		// sleepBackoff returns false when ctx is done — the caller hung up,
		// so stop rather than burning the remaining attempts holding a
		// request goroutine open for nobody.
		if !sleepBackoff(ctx, backoff) {
			break
		}
		backoff = nextBackoff(backoff, maxBackoff)
	}
	return nil, lastErr
}

// sleepBackoff and nextBackoff mirror internal/link's own (link.go:975,
// :986) — unexported there, so not importable. Duplicated rather than
// extracted: internal/vpn already keeps its own backoff constants, so
// per-package backoff is this repo's idiom, and go.mod is deliberately
// dependency-light.
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

// ServeHTTP forwards one http_req to the local workspace server and streams
// the reply back via head/chunk/end. Runs synchronously — callers (link.go's
// frame dispatch) are expected to run this in its own goroutine, same
// rationale as handleCmd/handlePTYOpen: a slow upstream must never block the
// read loop that keeps the liveness ping/pong alive.
func (h *Handler) ServeHTTP(
	ctx context.Context, id, method, path string, headers map[string]string, body []byte,
	head func(id string, status int, headers map[string]string),
	chunk func(id string, data []byte),
	end func(id string),
) {
	target := strings.TrimRight(h.target(), "/") + normalizePath(path)
	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		head(id, http.StatusBadGateway, map[string]string{"content-type": "text/plain"})
		chunk(id, []byte(fmt.Sprintf("bad request: %v", err)))
		end(id)
		return
	}
	for k, v := range headers {
		// Go's http.Client reads the outgoing wire "Host:" from req.Host
		// (falling back to req.URL.Host), never from req.Header — setting
		// it here via req.Header.Set would be silently discarded when the
		// request is written. aw-backend's workspace_tunnel_proxy.py now
		// forwards the original public Host through (it used to strip it
		// as hop-by-hop noise), specifically so the local aw-workspace
		// process can tell a Tier-2 app-mount hostname
		// (<app_id>.app.<slug>...) apart from its own API/SPA hosts; that
		// only works end-to-end if this hop actually sets req.Host instead
		// of leaving it defaulted to the 127.0.0.1 target.
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := h.client().Do(req)
	if err != nil {
		head(id, http.StatusBadGateway, map[string]string{"content-type": "text/plain"})
		chunk(id, []byte(fmt.Sprintf("upstream unreachable: %v", err)))
		end(id)
		return
	}
	defer resp.Body.Close()

	respHeaders := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}
	head(id, resp.StatusCode, respHeaders)

	buf := make([]byte, chunkSize)
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			chunk(id, data)
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			break
		}
	}
	end(id)
}

// normalizePath ensures the forwarded path always starts with "/" — the
// control plane sends the original request path verbatim (which always
// does), this is just defense in depth against a malformed frame.
func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// OpenWS dials the local workspace server's WS endpoint at path and starts
// a read loop that relays every inbound frame back via sendMsg. Runs the
// dial synchronously (fast — loopback) but the read loop in its own
// goroutine, same as ServeHTTP's caller contract.
//
// onOpen (may be nil) runs synchronously right after the dial succeeds and
// BEFORE the read-loop goroutine is started — the caller's only guarantee
// that whatever onOpen does (link.go's handleWSOpen writes the ws_open_ok
// frame there) reaches the wire before the first ws_msg possibly could. A
// callback fired from inside the goroutine instead would race it: Go makes
// no promise about when a newly spawned goroutine gets scheduled relative to
// its parent, so an ack written from there could arrive after a message it
// was supposed to precede.
func (h *Handler) OpenWS(ctx context.Context, id, path string, headers map[string]string, onOpen func(), sendMsg func(id string, data []byte, isText bool)) error {
	target := strings.TrimRight(h.target(), "/") + normalizePath(path)
	wsURL := strings.Replace(target, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)

	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("parse ws target: %w", err)
	}

	header := http.Header{}
	for k, v := range headers {
		// Strip the reserved handshake headers gorilla's dialer sets itself —
		// forwarding the browser's verbatim (relayed through the /link tunnel)
		// makes DialContext fail "duplicate header not allowed" (notably
		// Sec-Websocket-Extensions: permessage-deflate). Must cover every name
		// in gorilla's forbidden list, not just the key/version subset.
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "connection") ||
			strings.EqualFold(k, "upgrade") || strings.EqualFold(k, "sec-websocket-key") ||
			strings.EqualFold(k, "sec-websocket-version") ||
			strings.EqualFold(k, "sec-websocket-extensions") ||
			strings.EqualFold(k, "sec-websocket-protocol") {
			continue
		}
		header.Set(k, v)
	}

	conn, _, err := h.wsDialer().DialContext(ctx, u.String(), header)
	if err != nil {
		return fmt.Errorf("dial local workspace ws %s: %w", u.String(), err)
	}

	h.mu.Lock()
	if h.wsConns == nil {
		h.wsConns = map[string]*websocket.Conn{}
	}
	h.wsConns[id] = conn
	h.mu.Unlock()

	if onOpen != nil {
		onOpen()
	}

	go func() {
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			sendMsg(id, data, msgType == websocket.TextMessage)
		}
	}()
	return nil
}

// WSMessage relays one ws_msg frame from the control plane to the local
// workspace's WS connection for session id.
func (h *Handler) WSMessage(id string, data []byte, isText bool) error {
	h.mu.Lock()
	conn := h.wsConns[id]
	h.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("no open ws session %q", id)
	}
	msgType := websocket.BinaryMessage
	if isText {
		msgType = websocket.TextMessage
	}
	return conn.WriteMessage(msgType, data)
}

// CloseWS closes and forgets the local WS connection for session id.
// Idempotent — closing an already-closed/unknown session is a no-op.
func (h *Handler) CloseWS(id string) error {
	h.mu.Lock()
	conn := h.wsConns[id]
	delete(h.wsConns, id)
	h.mu.Unlock()
	if conn == nil {
		return nil
	}
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second))
	return conn.Close()
}

// CloseAllWS tears down every open WS session — called when the underlying
// /link connection to the control plane drops, since a dead tunnel can
// never deliver another ws_msg for any of them.
func (h *Handler) CloseAllWS() {
	h.mu.Lock()
	conns := h.wsConns
	h.wsConns = nil
	h.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}
