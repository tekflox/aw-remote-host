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
		func(id string, status int, headers http.Header) { headStatus = status },
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
		func(id string, status int, headers http.Header) { headStatus = status },
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

// TestServeHTTPRelaysARedirectInsteadOfFollowingIt — a proxy answers a 3xx by
// handing it to the browser, never by chasing it itself. Go's http.Client
// follows up to 10 redirects by DEFAULT, so the bare &http.Client{Transport:
// tr} this handler used to build silently turned every redirect the local
// workspace emitted into "fetch the target here, relay its body under the
// workspace's own origin".
//
// Live symptom (2026-09-28, workspace `fredericowu` on host Mac.Home):
// GET /api/apps/google-workspace-mcp/oauth/start returns a real 302 to
// accounts.google.com, and the browser received 200 + Google's sign-in HTML
// served from api.fredericowu.workspace.aw.tekflox.com — so Google's own
// scripts were blocked by CORS and the page was dead. Nothing was wrong with
// the app's route; this hop ate the redirect.
//
// The off-host leg is the sharp edge: the Location was ABSOLUTE and external,
// so this agent dialled it from the user's own machine. A proxy that chases
// arbitrary redirect targets is a request-forgery surface, not just a bug.
func TestServeHTTPRelaysARedirectInsteadOfFollowingIt(t *testing.T) {
	var targetCalls atomic.Int32
	// Stands in for accounts.google.com — a host this hop must never dial.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>consent screen</html>"))
	}))
	defer target.Close()

	location := target.URL + "/o/oauth2/auth?client_id=x"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("location", location)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	h := fastRetry(&Handler{Target: srv.URL})

	var headStatus int
	var headHeaders http.Header
	var body []byte
	h.ServeHTTP(context.Background(), "req-1", "GET", "/api/apps/google-workspace-mcp/oauth/start", nil, nil,
		func(id string, status int, headers http.Header) { headStatus, headHeaders = status, headers },
		func(id string, data []byte) { body = append(body, data...) },
		func(id string) {},
	)

	if headStatus != http.StatusFound {
		t.Fatalf("status = %d, want 302 relayed verbatim — the browser must do the redirect, not this hop", headStatus)
	}
	if got := headHeaders.Get("Location"); got != location {
		t.Fatalf("Location = %q, want %q", got, location)
	}
	if got := targetCalls.Load(); got != 0 {
		t.Fatalf("redirect target was fetched %d time(s), want 0 — this hop must never dial the Location", got)
	}
	if strings.Contains(string(body), "consent screen") {
		t.Fatalf("body = %q, want the 302's own (empty) body, not the redirect target's page", body)
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
		func(id string, status int, headers http.Header) { headStatus = status },
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
		func(id string, status int, headers http.Header) { headStatus = status },
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
		func(id string, status int, headers http.Header) { headStatus = status },
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

// TestOpenWSCallsOnOpenBeforeFirstMessage pins the ordering guarantee
// link.go's handleWSOpen depends on to send ws_open_ok before any ws_msg:
// onOpen must run before the read-loop goroutine can deliver its first
// message, even when the upstream fires one immediately.
func TestOpenWSCallsOnOpenBeforeFirstMessage(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("first"))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}

	var mu sync.Mutex
	var order []string
	done := make(chan struct{})

	err := h.OpenWS(context.Background(), "sess-1", "/ws", nil,
		func() {
			mu.Lock()
			order = append(order, "open")
			mu.Unlock()
		},
		func(id string, data []byte, isText bool) {
			mu.Lock()
			order = append(order, "msg:"+string(data))
			mu.Unlock()
			close(done)
		},
	)
	if err != nil {
		t.Fatalf("OpenWS: %v", err)
	}
	defer h.CloseAllWS()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first message")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "open" || order[1] != "msg:first" {
		t.Fatalf("order = %v, want [open msg:first] — onOpen must fire before any message", order)
	}
}

// TestOpenWSDoesNotCallOnOpenOnFailedDial — a failed dial must never report
// a false-positive open; the caller (link.go's handleWSOpen) relies on
// exactly one of onOpen or a non-nil error, never both.
func TestOpenWSDoesNotCallOnOpenOnFailedDial(t *testing.T) {
	h := &Handler{Target: "http://127.0.0.1:1"} // nothing listens here
	called := false
	err := h.OpenWS(context.Background(), "sess-1", "/ws", nil,
		func() { called = true },
		func(id string, data []byte, isText bool) {},
	)
	if err == nil {
		t.Fatal("expected a dial error")
	}
	if called {
		t.Fatal("onOpen must not fire when the dial failed")
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
	err := h.OpenWS(context.Background(), "sess-1", "/ws", nil, nil, func(id string, data []byte, isText bool) {
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
	var headHeaders http.Header
	var chunks [][]byte
	ended := false

	h.ServeHTTP(context.Background(), "req-1", "GET", "/dashboard", http.Header{"X-Test": []string{"yes"}}, nil,
		func(id string, status int, headers http.Header) {
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
	if headHeaders.Get("Content-Type") != "text/plain" {
		t.Fatalf("content-type = %q", headHeaders.Get("Content-Type"))
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
		func(id string, status int, headers http.Header) { headStatus = status },
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
		func(string, int, http.Header) {}, func(string, []byte) {}, func(string) {},
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
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", http.Header{
		"Host":    []string{"signoz.app.acme.workspace.aw.tekflox.com"},
		"X-Other": []string{"kept"},
	}, nil,
		func(string, int, http.Header) {}, func(string, []byte) {}, func(string) {},
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

	err := h.OpenWS(context.Background(), "sess-1", "/ws", nil, nil, func(id string, data []byte, isText bool) {
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
	reserved := http.Header{
		"Sec-Websocket-Key":        []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		"Sec-Websocket-Version":    []string{"13"},
		"Sec-Websocket-Extensions": []string{"permessage-deflate; client_max_window_bits"},
		"Sec-Websocket-Protocol":   []string{"chat"},
		"Connection":               []string{"Upgrade"},
		"Upgrade":                  []string{"websocket"},
		"Host":                     []string{"browser.example"},
		"Cookie":                   []string{"aw_id_jwt=abc"}, // a NON-reserved header must still pass through
	}
	done := make(chan struct{})
	err := h.OpenWS(context.Background(), "sess-x", "/ws", reserved, nil, func(id string, data []byte, isText bool) {
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

// TestServeHTTPPreservesMultipleSetCookie is the regression test for the
// collapsed-cart bug: WooCommerce's add-to-cart emits three Set-Cookie
// headers, and the old `respHeaders[k] = resp.Header.Get(k)` kept only the
// first — the two extra cookies died here, before anything was serialised.
func TestServeHTTPPreservesMultipleSetCookie(t *testing.T) {
	cookies := []string{
		"woocommerce_items_in_cart=1; path=/",
		"woocommerce_cart_hash=abc123; path=/",
		"wp_woocommerce_session_9f=lmn%7C%7C456; path=/",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range cookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var headHeaders http.Header
	h := &Handler{Target: srv.URL}
	h.ServeHTTP(context.Background(), "req-1", "POST", "/?add-to-cart=42", nil, nil,
		func(id string, status int, headers http.Header) { headHeaders = headers },
		func(string, []byte) {}, func(string) {},
	)

	got := headHeaders.Values("Set-Cookie")
	if len(got) != 3 {
		t.Fatalf("Set-Cookie count = %d, want 3 — headers collapsed: %#v", len(got), got)
	}
	for i, want := range cookies {
		if got[i] != want {
			t.Errorf("Set-Cookie[%d] = %q, want %q", i, got[i], want)
		}
	}
}

// TestServeHTTPForwardsMultiValuedRequestHeader covers the request direction:
// the loop used .Set, so a name arriving with several values reached the
// upstream carrying only the last one.
func TestServeHTTPForwardsMultiValuedRequestHeader(t *testing.T) {
	var gotCookies []string
	var gotXFF []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookies = r.Header.Values("Cookie")
		gotXFF = r.Header.Values("X-Forwarded-For")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", http.Header{
		"Cookie":          []string{"a=1", "b=2"},
		"X-Forwarded-For": []string{"203.0.113.1", "198.51.100.7"},
	}, nil,
		func(string, int, http.Header) {}, func(string, []byte) {}, func(string) {},
	)

	if len(gotCookies) != 2 {
		t.Errorf("upstream saw %d Cookie headers, want 2: %#v", len(gotCookies), gotCookies)
	}
	if len(gotXFF) != 2 {
		t.Errorf("upstream saw %d X-Forwarded-For headers, want 2: %#v", len(gotXFF), gotXFF)
	}
}

// TestServeHTTPMultiValuedHostStillSetsReqHost guards the Host special case
// against the .Set -> .Add change: Host must land on req.Host (the only place
// http.Client reads the outgoing wire Host from), not in req.Header, even
// though it now arrives as a value slice like every other name.
func TestServeHTTPMultiValuedHostStillSetsReqHost(t *testing.T) {
	var gotHost string
	var hostHeader []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		hostHeader = r.Header.Values("Host")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}
	h.ServeHTTP(context.Background(), "req-1", "GET", "/", http.Header{
		"Host": []string{"signoz.app.acme.workspace.aw.tekflox.com"},
	}, nil,
		func(string, int, http.Header) {}, func(string, []byte) {}, func(string) {},
	)

	if gotHost != "signoz.app.acme.workspace.aw.tekflox.com" {
		t.Fatalf("r.Host = %q, want the forwarded app-mount host", gotHost)
	}
	if len(hostHeader) != 0 {
		t.Errorf("Host leaked into req.Header as %#v — must go to req.Host only", hostHeader)
	}
}

// TestOpenWSStripsReservedHeaderWithMultipleValues guards the gorilla
// forbidden-list strip: the guard runs once per NAME, so a reserved header
// arriving with several values must be dropped whole. If any survived, every
// browser WebSocket fails the dial with "duplicate header not allowed".
func TestOpenWSStripsReservedHeaderWithMultipleValues(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage()
	}))
	defer srv.Close()

	h := &Handler{Target: srv.URL}
	err := h.OpenWS(context.Background(), "sess-m", "/ws", http.Header{
		"Sec-Websocket-Extensions": []string{"permessage-deflate", "client_max_window_bits"},
		"Connection":               []string{"Upgrade", "keep-alive"},
		"Cookie":                   []string{"a=1", "b=2"},
	}, nil, func(id string, data []byte, isText bool) {})
	if err != nil {
		t.Fatalf("OpenWS failed with multi-valued reserved headers (regression): %v", err)
	}
	defer h.CloseAllWS()
}
