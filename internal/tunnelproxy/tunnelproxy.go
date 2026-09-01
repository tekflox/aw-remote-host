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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DefaultTarget is the local aw-workspace HTTP server this host bootstrapped
// — same address ops.HealthURL probes for the "health" cmd verb.
const DefaultTarget = "http://127.0.0.1:9030"

// chunkSize bounds how much of a response body travels in one
// http_resp_chunk frame — keeps a single frame well under typical
// WebSocket/base64 overhead limits without adding real latency.
const chunkSize = 32 * 1024

// Handler forwards http_req/ws_open frames to Target — one instance is
// scoped to a single live /link connection (mirrors shell.Manager), so its
// ws connection map is torn down wholesale on disconnect via CloseAll.
type Handler struct {
	Target string // base URL of the local workspace HTTP server; DefaultTarget if empty
	Client *http.Client

	mu      sync.Mutex
	wsConns map[string]*websocket.Conn
}

// NewHandler builds a Handler targeting DefaultTarget with a sane default
// HTTP client (no timeout here — long-lived streaming responses are
// expected; the control plane owns per-request timeouts).
func NewHandler() *Handler {
	return &Handler{Client: &http.Client{}}
}

func (h *Handler) target() string {
	if h.Target != "" {
		return h.Target
	}
	return DefaultTarget
}

func (h *Handler) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
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
func (h *Handler) OpenWS(ctx context.Context, id, path string, headers map[string]string, sendMsg func(id string, data []byte, isText bool)) error {
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

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return fmt.Errorf("dial local workspace ws %s: %w", u.String(), err)
	}

	h.mu.Lock()
	if h.wsConns == nil {
		h.wsConns = map[string]*websocket.Conn{}
	}
	h.wsConns[id] = conn
	h.mu.Unlock()

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
