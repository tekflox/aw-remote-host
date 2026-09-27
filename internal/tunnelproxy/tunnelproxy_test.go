package tunnelproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fastRetry is the dial-retry envelope shrunk to test speed, via the seams on
// Handler — same idiom as link.Client's MinBackoff/MaxBackoff. Production
// never sets these; the package consts apply there.
func fastRetry(h *Handler) *Handler {
	h.DialAttempts = 3
	h.DialBackoffMin = time.Millisecond
	h.DialBackoffMax = 2 * time.Millisecond
	h.DialTimeout = 2 * time.Second
	return h
}

// countDials gives h a dial that records every attempt and fails the first
// failFirst of them with a synthetic connection error, then delegates to the
// real dialer. Deterministic, unlike racing a real listener on and off a
// port. Returns the counter.
func countDials(h *Handler, failFirst int) *atomic.Int32 {
	var n atomic.Int32
	h.dialTCP = func(ctx context.Context, timeout time.Duration, network, addr string) (net.Conn, error) {
		if int(n.Add(1)) <= failFirst {
			return nil, errors.New("simulated gvproxy blip: connection refused")
		}
		return realDialTCP(ctx, timeout, network, addr)
	}
	return &n
}

// TestServeHTTPRetriesATransientDialFailure is the core of this fix: the
// first two dials fail the way a gvproxy blip fails, and the request still
// comes back 200 rather than the 502 it used to.
func TestServeHTTPRetriesATransientDialFailure(t *testing.T) {
	var upstreamCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	h := fastRetry(&Handler{Target: srv.URL})
	dials := countDials(h, 2)

	var headStatus int
	var body []byte
	ended := false
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", nil, nil,
		func(id string, status int, headers map[string]string) { headStatus = status },
		func(id string, data []byte) { body = append(body, data...) },
		func(id string) { ended = true },
	)

	if headStatus != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the retry should have recovered the dial)", headStatus)
	}
	if string(body) != "recovered" {
		t.Fatalf("body = %q, want %q", body, "recovered")
	}
	if !ended {
		t.Fatal("expected end() to be called")
	}
	if got := dials.Load(); got != 3 {
		t.Fatalf("dial attempts = %d, want 3 (2 failures then success)", got)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream handler calls = %d, want 1 — a failed dial must not reach the server", got)
	}
}

// TestServeHTTPNeverRetriesAReceived5xx — a 5xx is a real answer from the
// local workspace server, not the flaky-hop symptom this fix targets. It must
// pass straight through, once.
func TestServeHTTPNeverRetriesAReceived5xx(t *testing.T) {
	var upstreamCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	h := fastRetry(&Handler{Target: srv.URL})

	var headStatus int
	var body []byte
	h.ServeHTTP(context.Background(), "req-1", "POST", "/api/apps/install", nil, []byte(`{"app":"x"}`),
		func(id string, status int, headers map[string]string) { headStatus = status },
		func(id string, data []byte) { body = append(body, data...) },
		func(id string) {},
	)

	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream handler calls = %d, want exactly 1 — a received 5xx must never be retried", got)
	}
	if headStatus != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 relayed as-is (not 502)", headStatus)
	}
	if string(body) != "boom" {
		t.Fatalf("body = %q, want the upstream's own 500 body", body)
	}
}

// TestServeHTTPDoesNotRetryAfterTheRequestWasWritten is the anti-double-install
// regression, and the whole reason the retry lives at the dial layer instead of
// around client.Do. The upstream receives the request, runs its side effect,
// then the connection dies before any response — Do returns an error, which a
// naive "retry on err != nil" around Do would happily replay. It must not.
// This test fails loudly if anyone later moves the retry back up.
func TestServeHTTPDoesNotRetryAfterTheRequestWasWritten(t *testing.T) {
	var upstreamCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1) // stands in for "the app was installed"
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close() // die without writing a response
	}))
	defer srv.Close()

	h := fastRetry(&Handler{Target: srv.URL})
	dials := countDials(h, 0) // count only; never fail a dial

	var headStatus int
	ended := false
	h.ServeHTTP(context.Background(), "req-1", "POST", "/api/apps/install", nil, []byte(`{"app":"x"}`),
		func(id string, status int, headers map[string]string) { headStatus = status },
		func(id string, data []byte) {},
		func(id string) { ended = true },
	)

	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream handler calls = %d, want exactly 1 — the request was already executed, "+
			"replaying it would double-install; the retry must stay at the dial layer", got)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial attempts = %d, want 1 — the dial succeeded, so nothing should be redialled", got)
	}
	if headStatus != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", headStatus)
	}
	if !ended {
		t.Fatal("expected end() to be called")
	}
}

// TestServeHTTPGivesUpAfterMaxAttempts — bounded, not infinite.
func TestServeHTTPGivesUpAfterMaxAttempts(t *testing.T) {
	h := fastRetry(&Handler{Target: "http://127.0.0.1:1"})
	dials := countDials(h, 1<<30) // every dial fails

	var headStatus int
	var body []byte
	ended := false
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", nil, nil,
		func(id string, status int, headers map[string]string) { headStatus = status },
		func(id string, data []byte) { body = append(body, data...) },
		func(id string) { ended = true },
	)

	if headStatus != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", headStatus)
	}
	if !ended {
		t.Fatal("expected end() to be called")
	}
	if got := dials.Load(); got != int32(h.DialAttempts) {
		t.Fatalf("dial attempts = %d, want exactly %d", got, h.DialAttempts)
	}
	if !strings.Contains(string(body), "upstream unreachable") {
		t.Fatalf("body = %q, want it to still say %q", body, "upstream unreachable")
	}
}

// TestServeHTTPRetryStopsOnContextCancellation — the caller hung up, so the
// remaining attempts are pointless; stop instead of holding the request
// goroutine past the control plane's own deadline. head+end must still fire so
// the frame protocol never strands a request id.
func TestServeHTTPRetryStopsOnContextCancellation(t *testing.T) {
	// Deliberately NOT countDials: once ctx is cancelled http.Transport
	// abandons the dial goroutine and returns, so a deferred restore of the
	// package-level dialTCP would race that still-running goroutine. Nothing
	// listens on port 1, so the real dialer refuses instantly anyway; the
	// precise attempt count is pinned by the direct dialContext test below.
	h := &Handler{
		Target:         "http://127.0.0.1:1",
		DialAttempts:   50,
		DialBackoffMin: 50 * time.Millisecond,
		DialBackoffMax: 50 * time.Millisecond,
		DialTimeout:    time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	var headStatus int
	ended := false
	start := time.Now()
	h.ServeHTTP(ctx, "req-1", "GET", "/", nil, nil,
		func(id string, status int, headers map[string]string) { headStatus = status },
		func(id string, data []byte) {},
		func(id string) { ended = true },
	)
	elapsed := time.Since(start)

	// The full budget is 50 attempts × 50ms of sleep ≈ 2.5s; cancelling must
	// cut it short by a wide margin.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("took %v — cancellation should abort the retry loop promptly", elapsed)
	}
	if headStatus != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", headStatus)
	}
	if !ended {
		t.Fatal("expected end() to be called even on cancellation")
	}
}

// TestDialContextStopsOnContextCancellation pins the ctx-honouring inside the
// retry loop itself. The ServeHTTP-level test above cannot: http.Transport
// abandons the dial goroutine as soon as ctx is done and returns, so reading
// an attempt counter after ServeHTTP returns races that goroutine. Called
// directly, the loop is observable — a loop that ignored sleepBackoff's false
// would burn all 50 attempts instead of stopping at the cancellation.
func TestDialContextStopsOnContextCancellation(t *testing.T) {
	h := &Handler{
		DialAttempts:   50,
		DialBackoffMin: 50 * time.Millisecond,
		DialBackoffMax: 50 * time.Millisecond,
		DialTimeout:    time.Second,
	}
	dials := countDials(h, 1<<30) // every dial fails

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	conn, err := h.dialContext(ctx, "tcp", "127.0.0.1:1")
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.Close()
		t.Fatal("expected a dial error")
	}
	// Full budget is 49 sleeps x 50ms ~ 2.45s.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("took %v — cancellation should abort the retry loop, not run it out", elapsed)
	}
	if got := dials.Load(); got >= 50 {
		t.Fatalf("dial attempts = %d — cancellation should stop well short of the 50-attempt budget", got)
	}
}

// TestOpenWSRetriesATransientDialFailure — OpenWS crosses the identical hop,
// and at the dial layer it gets the same retry for free. Retrying here is
// unconditionally safe: NetDialContext returns before the HTTP upgrade is
// written, so there is no handshake to replay.
func TestOpenWSRetriesATransientDialFailure(t *testing.T) {
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

	h := fastRetry(&Handler{Target: srv.URL})
	dials := countDials(h, 2)

	done := make(chan struct{})
	var mu sync.Mutex
	var received []string
	err := h.OpenWS(context.Background(), "sess-1", "/ws", nil, func(id string, data []byte, isText bool) {
		mu.Lock()
		received = append(received, string(data))
		mu.Unlock()
		close(done)
	})
	if err != nil {
		t.Fatalf("OpenWS: %v — the retry should have recovered the dial", err)
	}
	defer h.CloseAllWS()

	if got := dials.Load(); got != 3 {
		t.Fatalf("dial attempts = %d, want 3 (2 failures then success)", got)
	}

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

func TestServeHTTPSetsRequestHostFromHeaders(t *testing.T) {
	// Regression: Go's http.Client reads the outgoing wire Host from
	// req.Host (falling back to req.URL.Host), never from req.Header — a
	// naive req.Header.Set("host", ...) is silently discarded. aw-backend
	// forwards the browser's original public Host (e.g. a Tier-2 app's own
	// <app_id>.app.<slug>... hostname) through the "host" entry in this
	// map specifically so the local aw-workspace process can tell that
	// hostname apart from its own API/SPA hosts.
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", map[string]string{
		"Host":    "signoz.app.acme.workspace.aw.tekflox.com",
		"X-Other": "kept",
	}, nil,
		func(string, int, map[string]string) {}, func(string, []byte) {}, func(string) {},
	)

	if gotHost != "signoz.app.acme.workspace.aw.tekflox.com" {
		t.Fatalf("r.Host = %q, want the forwarded app-mount host", gotHost)
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
