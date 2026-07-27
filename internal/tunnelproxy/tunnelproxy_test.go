package tunnelproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestServeHTTPStreamsHeadChunksAndEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dashboard" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("X-Test") != "yes" {
			t.Errorf("expected header X-Test=yes, got %q", r.Header.Get("X-Test"))
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}

	var headStatus int
	var headHeaders map[string]string
	var chunks [][]byte
	ended := false

	h.ServeHTTP(context.Background(), "req-1", "GET", "/dashboard", map[string]string{"X-Test": "yes"}, nil,
		func(id string, status int, headers map[string]string) {
			if id != "req-1" {
				t.Errorf("head: id = %q, want req-1", id)
			}
			headStatus = status
			headHeaders = headers
		},
		func(id string, data []byte) {
			if id != "req-1" {
				t.Errorf("chunk: id = %q, want req-1", id)
			}
			chunks = append(chunks, data)
		},
		func(id string) {
			if id != "req-1" {
				t.Errorf("end: id = %q, want req-1", id)
			}
			ended = true
		},
	)

	if headStatus != http.StatusOK {
		t.Fatalf("status = %d, want 200", headStatus)
	}
	if headHeaders["Content-Type"] != "text/plain" {
		t.Fatalf("content-type = %q", headHeaders["Content-Type"])
	}
	var body []byte
	for _, c := range chunks {
		body = append(body, c...)
	}
	if string(body) != "hello world" {
		t.Fatalf("body = %q, want %q", body, "hello world")
	}
	if !ended {
		t.Fatal("expected end() to be called")
	}
}

func TestServeHTTPUpstreamUnreachableIs502(t *testing.T) {
	h := &Handler{Target: "http://127.0.0.1:1"} // nothing listens here

	var headStatus int
	ended := false
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", nil, nil,
		func(id string, status int, headers map[string]string) { headStatus = status },
		func(id string, data []byte) {},
		func(id string) { ended = true },
	)

	if headStatus != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", headStatus)
	}
	if !ended {
		t.Fatal("expected end() to be called")
	}
}

func TestServeHTTPForwardsRequestBody(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}
	h.ServeHTTP(context.Background(), "req-1", "POST", "/", nil, []byte("payload"),
		func(string, int, map[string]string) {}, func(string, []byte) {}, func(string) {},
	)

	if string(receivedBody) != "payload" {
		t.Fatalf("body = %q, want %q", receivedBody, "payload")
	}
}

func TestOpenWSBridgesMessagesBothWays(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Echo back uppercased-ish (just reversed marker) so the test can
			// tell request/response apart.
			_ = conn.WriteMessage(mt, append([]byte("echo:"), data...))
		}
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}

	var mu sync.Mutex
	var received []string
	done := make(chan struct{})

	err := h.OpenWS(context.Background(), "sess-1", "/ws", nil, func(id string, data []byte, isText bool) {
		mu.Lock()
		received = append(received, string(data))
		mu.Unlock()
		close(done)
	})
	if err != nil {
		t.Fatalf("OpenWS: %v", err)
	}
	defer h.CloseAllWS()

	if err := h.WSMessage("sess-1", []byte("ping"), true); err != nil {
		t.Fatalf("WSMessage: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for echoed message")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0] != "echo:ping" {
		t.Fatalf("received = %v, want [echo:ping]", received)
	}
}

// The browser's original WS handshake headers are relayed verbatim through
// the /link tunnel, so OpenWS receives reserved names (Sec-Websocket-Key,
// Sec-Websocket-Version, Sec-Websocket-Extensions, Sec-Websocket-Protocol,
// Connection, Upgrade). gorilla's DialContext manages those itself and errors
// "duplicate header not allowed" if any are passed in requestHeader — OpenWS
// must strip them all. Regression for the BYOD PTY-over-tunnel bug where
// Sec-Websocket-Extensions: permessage-deflate broke the local dial.
func TestOpenWSStripsReservedHandshakeHeaders(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			_ = conn.WriteMessage(mt, append([]byte("echo:"), data...))
		}
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}
	reserved := map[string]string{
		"Sec-Websocket-Key":        "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-Websocket-Version":    "13",
		"Sec-Websocket-Extensions": "permessage-deflate; client_max_window_bits",
		"Sec-Websocket-Protocol":   "chat",
		"Connection":               "Upgrade",
		"Upgrade":                  "websocket",
		"Host":                     "browser.example",
		"Cookie":                   "aw_id_jwt=abc", // a NON-reserved header must still pass through
	}
	done := make(chan struct{})
	err := h.OpenWS(context.Background(), "sess-x", "/ws", reserved, func(id string, data []byte, isText bool) {
		close(done)
	})
	if err != nil {
		t.Fatalf("OpenWS with reserved headers failed (regression): %v", err)
	}
	defer h.CloseAllWS()

	if err := h.WSMessage("sess-x", []byte("ping"), true); err != nil {
		t.Fatalf("WSMessage: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for echoed message")
	}
}

func TestWSMessageUnknownSessionErrors(t *testing.T) {
	h := &Handler{}
	if err := h.WSMessage("no-such-session", []byte("x"), true); err == nil {
		t.Fatal("expected error for unknown session")
	}
}

func TestCloseWSIsIdempotent(t *testing.T) {
	h := &Handler{}
	if err := h.CloseWS("never-opened"); err != nil {
		t.Fatalf("CloseWS on unknown session should be a no-op, got: %v", err)
	}
}
