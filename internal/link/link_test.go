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
	registerCount   int32
	forceCloseAfter int32 // close the Nth connection right after registering (0 = never)
	connCount       int32
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

	// Hold the connection open, replying to whatever the client sends
	// (pong replies to our pings, or just idle) until it disconnects.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
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
