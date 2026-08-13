// Package tcpproxy is the host side of the /link tunnel's TCP channel: it
// dials an arbitrary host:port FROM THIS MACHINE on the control plane's
// behalf and relays the bytes both ways as tcp_data frames.
//
// Why this exists, and why it is not internal/tunnelproxy: that package
// forwards http_req/ws_open to ONE fixed local target (the aw-workspace HTTP
// server this host bootstrapped, DefaultTarget). It is a reverse proxy for a
// known service. This one takes host+port off the frame, so the workspace can
// reach anything the HOST can reach — a VNC server on 127.0.0.1:5900, a
// database on the LAN — over the outbound WebSocket the host already holds
// open, with no inbound port and no VPN.
//
// Shape deliberately mirrors tunnelproxy's ws_* trio (one instance per live
// /link connection, a map keyed by session id, CloseAll on disconnect) so the
// two read the same and neither can drift into its own idea of lifecycle.
//
// SECURITY: a dial target is whatever the control plane sends. That is the
// same trust boundary the `cmd`/`pty_open` verbs already sit on — anyone who
// can drive this host's /link can already run commands on it — so this adds
// no new authority. It does add reach, so Dialer is injectable and the
// allowlist hook is a single obvious place to grow one.
package tcpproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// dialTimeout bounds a single connect attempt. A tunnel to an unreachable
// port must fail fast and say so, not hang the consumer's socket open with no
// bytes and no error — that failure mode is indistinguishable from "the
// service is just quiet".
const dialTimeout = 10 * time.Second

// readChunk bounds one tcp_data frame. Matches tunnelproxy's http chunk size:
// large enough that a screen-sized VNC update is a handful of frames, small
// enough to stay well under typical WebSocket/base64 overhead limits.
const readChunk = 32 * 1024

// Handler owns every open TCP session for ONE /link connection.
type Handler struct {
	// Dialer is used for every outbound connection; nil means net.Dialer with
	// dialTimeout. Injectable so tests can run without real sockets.
	Dialer func(ctx context.Context, network, address string) (net.Conn, error)

	mu    sync.Mutex
	conns map[string]net.Conn
}

func (h *Handler) dial(ctx context.Context, address string) (net.Conn, error) {
	if h.Dialer != nil {
		return h.Dialer(ctx, "tcp", address)
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", address)
}

// OpenTCP connects to host:port and starts a read loop relaying every inbound
// chunk through sendData. The dial is synchronous so the caller can report a
// connect failure as a close reason; the read loop runs in its own goroutine.
//
// onEOF fires exactly once, when the remote end closes or the read fails, so
// the control plane can tear its half down rather than wait for a timeout.
func (h *Handler) OpenTCP(ctx context.Context, id, host string, port int,
	sendData func(id string, data []byte), onEOF func(id string, reason string)) error {

	if host == "" || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid tcp target %q:%d", host, port)
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := h.dial(ctx, address)
	if err != nil {
		return fmt.Errorf("dial %s: %w", address, err)
	}

	h.mu.Lock()
	if h.conns == nil {
		h.conns = map[string]net.Conn{}
	}
	// A repeated id would orphan the previous socket with no way to close it.
	if prev := h.conns[id]; prev != nil {
		_ = prev.Close()
	}
	h.conns[id] = conn
	h.mu.Unlock()

	go func() {
		buf := make([]byte, readChunk)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				// Copy: sendData may hold the slice past this iteration
				// (base64 + frame write), and buf is reused every read.
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				sendData(id, chunk)
			}
			if err != nil {
				reason := "eof"
				if err != io.EOF {
					reason = err.Error()
				}
				h.mu.Lock()
				// Only report if this session is still the live one — a
				// CloseTCP racing the read loop must not resurrect it.
				current, still := h.conns[id]
				if still && current == conn {
					delete(h.conns, id)
				}
				h.mu.Unlock()
				if still {
					onEOF(id, reason)
				}
				_ = conn.Close()
				return
			}
		}
	}()
	return nil
}

// SendTCP writes one tcp_data frame's payload to the local socket for id.
func (h *Handler) SendTCP(id string, data []byte) error {
	h.mu.Lock()
	conn := h.conns[id]
	h.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("no open tcp session %q", id)
	}
	_, err := conn.Write(data)
	return err
}

// CloseTCP closes and forgets one session. Idempotent.
func (h *Handler) CloseTCP(id string) error {
	h.mu.Lock()
	conn := h.conns[id]
	delete(h.conns, id)
	h.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// CloseAllTCP tears down every session — called when the /link connection
// drops, since a dead tunnel can never deliver another tcp_data for any of
// them and the sockets would leak for as long as the process lives.
func (h *Handler) CloseAllTCP() {
	h.mu.Lock()
	conns := h.conns
	h.conns = nil
	h.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// OpenCount reports how many sessions are live (tests + diagnostics).
func (h *Handler) OpenCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}
