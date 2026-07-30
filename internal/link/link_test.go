package link

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketURL(t *testing.T) {
	cases := []struct {
		controlPlane string
		want         string
		wantErr      bool
	}{
		{"https://api.aw.tekflox.com", "wss://api.aw.tekflox.com/link", false},
		{"http://localhost:9123", "ws://localhost:9123/link", false},
		{"ftp://bad.example.com", "", true},
	}

	for _, tc := range cases {
		c := New(tc.controlPlane, "token")
		got, err := c.WebSocketURL()
		if tc.wantErr {
			if err == nil {
				t.Errorf("WebSocketURL(%q): expected error, got %q", tc.controlPlane, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("WebSocketURL(%q): unexpected error: %v", tc.controlPlane, err)
			continue
		}
		if got != tc.want {
			t.Errorf("WebSocketURL(%q) = %q, want %q", tc.controlPlane, got, tc.want)
		}
	}
}

// fakeLinkServer mimics just enough of aw-backend's /link contract
// (src/api/routes/host_link.py) to exercise the Go client's state machine:
// bearer-token gate, one register frame in, one registered reply out, then
// either holds the connection open (pumping pings) or closes it on demand.
type fakeLinkServer struct {
	mu           sync.Mutex
	acceptTokens map[string]string // token -> host_credential to mint ("" = reconnect, no new credential)
	upgrader     websocket.Upgrader

	registerFrames  []map[string]any
	authTokens      []string
	registerCount   int32
	forceCloseAfter int32 // close the Nth connection right after registering (0 = never)
	connCount       int32

	framesToSend   []map[string]any // sent right after "registered", in order (Phase 3 pty tests)
	receivedFrames []map[string]any // every non-register frame the client sends back
}

func newFakeLinkServer() *fakeLinkServer {
	return &fakeLinkServer{
		acceptTokens: map[string]string{},
		upgrader:     websocket.Upgrader{},
	}
}

func (s *fakeLinkServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	s.mu.Lock()
	hostCred, known := s.acceptTokens[token]
	s.authTokens = append(s.authTokens, token)
	s.mu.Unlock()
	if !known {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	connN := atomic.AddInt32(&s.connCount, 1)

	_, data, err := conn.ReadMessage()
	if err != nil {
		return
	}
	var frame map[string]any
	_ = json.Unmarshal(data, &frame)
	s.mu.Lock()
	s.registerFrames = append(s.registerFrames, frame)
	s.mu.Unlock()
	atomic.AddInt32(&s.registerCount, 1)

	reply := map[string]any{
		"op":             "registered",
		"remote_host_id": "host-1",
		"workspace_slug": "acme",
	}
	if hostCred != "" {
		reply["host_credential"] = hostCred
	}
	if err := conn.WriteJSON(reply); err != nil {
		return
	}

	if s.forceCloseAfter != 0 && connN == s.forceCloseAfter {
		return // close immediately, forcing the client to reconnect
	}

	s.mu.Lock()
	toSend := append([]map[string]any(nil), s.framesToSend...)
	s.mu.Unlock()
	for _, f := range toSend {
		if err := conn.WriteJSON(f); err != nil {
			return
		}
	}

	// Hold the connection open, recording whatever the client sends back
	// (pty_output, cmd_result, pong, ...) until it disconnects.
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var frame map[string]any
		if json.Unmarshal(data, &frame) == nil {
			s.mu.Lock()
			s.receivedFrames = append(s.receivedFrames, frame)
			s.mu.Unlock()
		}
	}
}

func TestConnectPersistsFreshHostCredential(t *testing.T) {
	srv := newFakeLinkServer()
	srv.acceptTokens["awbs_test"] = "awlk_minted"
	ts := httptest.NewServer(srv)
	defer ts.Close()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	c := New(ts.URL, "awbs_test")
	c.Info = RegisterInfo{Hostname: "box1", OS: "linux", Arch: "amd64", CLIVersion: "test"}

	result, err := c.Connect(context.Background(), "awbs_test", credPath)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer result.Conn.Close()

	if result.Reply.WorkspaceSlug != "acme" {
		t.Errorf("WorkspaceSlug = %q, want acme", result.Reply.WorkspaceSlug)
	}
	if result.Reply.RemoteHostID != "host-1" {
		t.Errorf("RemoteHostID = %q, want host-1", result.Reply.RemoteHostID)
	}

	creds, err := LoadCredentials(credPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if creds == nil || creds.HostCredential != "awlk_minted" {
		t.Fatalf("expected persisted host_credential awlk_minted, got %+v", creds)
	}
	if creds.RemoteHostID != "host-1" {
		t.Errorf("RemoteHostID = %q, want host-1", creds.RemoteHostID)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.registerFrames) != 1 {
		t.Fatalf("expected exactly 1 register frame, got %d", len(srv.registerFrames))
	}
	frame := srv.registerFrames[0]
	if frame["op"] != "register" || frame["hostname"] != "box1" {
		t.Errorf("unexpected register frame: %+v", frame)
	}
}

func TestRunReconnectsWithStoredCredentialAfterDrop(t *testing.T) {
	srv := newFakeLinkServer()
	srv.acceptTokens["awbs_test"] = "awlk_minted"
	srv.acceptTokens["awlk_minted"] = "" // reconnect: no new credential minted
	srv.forceCloseAfter = 1              // drop the very first connection right after registering
	ts := httptest.NewServer(srv)
	defer ts.Close()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	c := New(ts.URL, "awbs_test")
	c.MinBackoff = 5 * time.Millisecond
	c.MaxBackoff = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var registeredCount int32
	var lastToken string
	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, credPath, RunCallbacks{
			OnRegistered: func(reply *RegisteredReply) {
				n := atomic.AddInt32(&registeredCount, 1)
				if n >= 2 {
					cancel() // stop once we've proven a reconnect happened
				}
			},
		})
	}()

	<-done

	if atomic.LoadInt32(&registeredCount) < 2 {
		t.Fatalf("expected at least 2 registrations (initial + reconnect), got %d", registeredCount)
	}

	srv.mu.Lock()
	frames := append([]map[string]any(nil), srv.registerFrames...)
	srv.mu.Unlock()
	if len(frames) < 2 {
		t.Fatalf("expected at least 2 register frames, got %d", len(frames))
	}

	creds, err := LoadCredentials(credPath)
	if err != nil || creds == nil {
		t.Fatalf("expected credentials to be persisted after first connect: %v", err)
	}
	lastToken = creds.HostCredential
	if lastToken != "awlk_minted" {
		t.Errorf("expected stored credential awlk_minted, got %q", lastToken)
	}
}

func TestRunFallsBackToExplicitBootstrapTokenWhenStoredCredentialIsRejected(t *testing.T) {
	srv := newFakeLinkServer()
	srv.acceptTokens["awbs_reinstall"] = "awlk_replacement"
	ts := httptest.NewServer(srv)
	defer ts.Close()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	if err := SaveCredentials(credPath, &Credentials{
		RemoteHostID:   "host-stale",
		HostCredential: "awlk_stale",
	}); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	c := New(ts.URL, "awbs_reinstall")
	c.MinBackoff = 5 * time.Millisecond
	c.MaxBackoff = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, credPath, RunCallbacks{
			OnRegistered: func(reply *RegisteredReply) {
				cancel()
			},
		})
	}()
	<-done

	creds, err := LoadCredentials(credPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if creds == nil || creds.HostCredential != "awlk_replacement" {
		t.Fatalf("expected replacement credential, got %+v", creds)
	}

	srv.mu.Lock()
	tokens := append([]string(nil), srv.authTokens...)
	srv.mu.Unlock()
	if len(tokens) < 2 {
		t.Fatalf("expected stale credential attempt plus bootstrap fallback, got %v", tokens)
	}
	if tokens[0] != "awlk_stale" || tokens[1] != "awbs_reinstall" {
		t.Fatalf("unexpected token order: %v", tokens)
	}
}

// fakeShellManager records every call so tests can assert dispatch without
// touching a real pty/podman.
type fakeShellManager struct {
	mu      sync.Mutex
	opened  []string
	input   map[string][]byte
	resized map[string][2]uint16
	closed  []string
	openErr error
	emit    func(id, dataB64 string)
}

func newFakeShellManager(emit func(id, dataB64 string)) *fakeShellManager {
	return &fakeShellManager{input: map[string][]byte{}, resized: map[string][2]uint16{}, emit: emit}
}

func (f *fakeShellManager) Open(_ context.Context, id string, cols, rows uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openErr != nil {
		return f.openErr
	}
	f.opened = append(f.opened, id)
	if f.emit != nil {
		f.emit(id, "aGVsbG8=") // "hello", proves the emit path is wired end to end
	}
	return nil
}

func (f *fakeShellManager) Input(id string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.input[id] = append([]byte(nil), data...)
	return nil
}

func (f *fakeShellManager) Resize(id string, cols, rows uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resized[id] = [2]uint16{cols, rows}
	return nil
}

func (f *fakeShellManager) Close(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, id)
	return nil
}

func (f *fakeShellManager) CloseAll() {}

func TestRunDispatchesPTYFrames(t *testing.T) {
	srv := newFakeLinkServer()
	srv.acceptTokens["awbs_test"] = "awlk_minted"
	srv.framesToSend = []map[string]any{
		{"op": "pty_open", "id": "s1", "cols": float64(80), "rows": float64(24)},
		{"op": "pty_input", "id": "s1", "data": "aGk="},
		{"op": "pty_resize", "id": "s1", "cols": float64(100), "rows": float64(40)},
		{"op": "pty_close", "id": "s1"},
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	c := New(ts.URL, "awbs_test")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var mgr *fakeShellManager
	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, credPath, RunCallbacks{
			OnShell: func(emit func(id, dataB64 string)) ShellManager {
				mgr = newFakeShellManager(emit)
				return mgr
			},
		})
	}()

	// Give the pump loop time to process the scripted frames, then cancel.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if mgr == nil {
		t.Fatal("OnShell was never called")
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if len(mgr.opened) != 1 || mgr.opened[0] != "s1" {
		t.Errorf("opened = %v, want [s1]", mgr.opened)
	}
	if string(mgr.input["s1"]) != "hi" {
		t.Errorf("input[s1] = %q, want \"hi\"", mgr.input["s1"])
	}
	if mgr.resized["s1"] != [2]uint16{100, 40} {
		t.Errorf("resized[s1] = %v, want [100 40]", mgr.resized["s1"])
	}
	if len(mgr.closed) != 1 || mgr.closed[0] != "s1" {
		t.Errorf("closed = %v, want [s1]", mgr.closed)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	found := false
	for _, f := range srv.receivedFrames {
		if f["op"] == "pty_output" && f["id"] == "s1" && f["data"] == "aGVsbG8=" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a pty_output frame for s1, got %+v", srv.receivedFrames)
	}
}

func TestPumpRepliesPTYCloseWhenNoShellManager(t *testing.T) {
	srv := newFakeLinkServer()
	srv.acceptTokens["awbs_test"] = "awlk_minted"
	srv.framesToSend = []map[string]any{
		{"op": "pty_open", "id": "s1", "cols": float64(80), "rows": float64(24)},
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	c := New(ts.URL, "awbs_test")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, credPath, RunCallbacks{})
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	srv.mu.Lock()
	defer srv.mu.Unlock()
	found := false
	for _, f := range srv.receivedFrames {
		if f["op"] == "pty_close" && f["id"] == "s1" && f["reason"] != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a pty_close-with-reason frame for s1, got %+v", srv.receivedFrames)
	}
}

func TestRunFailsFastWithNoTokenAndNoStoredCredential(t *testing.T) {
	c := New("http://127.0.0.1:1", "")
	credPath := filepath.Join(t.TempDir(), "credentials.json")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := c.Run(ctx, credPath, RunCallbacks{})
	if err == nil {
		t.Fatal("expected an error when there's no --token and no stored credential")
	}
	if !strings.Contains(err.Error(), "no token available") {
		t.Errorf("unexpected error: %v", err)
	}
}
