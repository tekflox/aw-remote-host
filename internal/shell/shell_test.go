package shell

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakePTY is an in-memory PTY — no real podman/creack-pty. Read drains
// outbox (what the "shell" writes back), Write appends to inbox (what the
// browser typed).
type fakePTY struct {
	mu      sync.Mutex
	outbox  *bytes.Buffer
	inbox   bytes.Buffer
	closed  bool
	closeCh chan struct{}
	cols    uint16
	rows    uint16
}

func newFakePTY() *fakePTY {
	return &fakePTY{outbox: &bytes.Buffer{}, closeCh: make(chan struct{})}
}

func (f *fakePTY) Read(p []byte) (int, error) {
	for {
		f.mu.Lock()
		if f.outbox.Len() > 0 {
			n, _ := f.outbox.Read(p)
			f.mu.Unlock()
			return n, nil
		}
		if f.closed {
			f.mu.Unlock()
			return 0, io.EOF
		}
		f.mu.Unlock()
		select {
		case <-f.closeCh:
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *fakePTY) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	f.inbox.Write(p)
	return len(p), nil
}

func (f *fakePTY) Resize(cols, rows uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cols, f.rows = cols, rows
	return nil
}

func (f *fakePTY) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.mu.Unlock()
	close(f.closeCh)
	return nil
}

// push queues bytes the fake "shell process" writes to its stdout — the
// next Read() call(s) will return them.
func (f *fakePTY) push(data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outbox.WriteString(data)
}

func (f *fakePTY) writtenInput() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inbox.String()
}

type emitCall struct {
	id      string
	dataB64 string
}

func collectEmit() (EmitFunc, func() []emitCall) {
	var mu sync.Mutex
	var calls []emitCall
	return func(id, dataB64 string) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, emitCall{id, dataB64})
		}, func() []emitCall {
			mu.Lock()
			defer mu.Unlock()
			return append([]emitCall(nil), calls...)
		}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition never became true within timeout")
	}
}

func TestOpenPumpsOutputAsPTYOutputFrames(t *testing.T) {
	fake := newFakePTY()
	emit, calls := collectEmit()
	mgr := NewManager(func(context.Context, string) (PTY, error) { return fake, nil }, emit)

	if err := mgr.Open(context.Background(), "s1", 80, 24, ""); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if fake.cols != 80 || fake.rows != 24 {
		t.Errorf("initial resize = %d,%d, want 80,24", fake.cols, fake.rows)
	}

	fake.push("hello")
	waitFor(t, time.Second, func() bool { return len(calls()) > 0 })

	got := calls()
	if len(got) != 1 || got[0].id != "s1" {
		t.Fatalf("unexpected emits: %+v", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(got[0].dataB64)
	if err != nil || string(decoded) != "hello" {
		t.Errorf("decoded emit = %q, err %v; want hello", decoded, err)
	}
}

func TestOpenRejectsDuplicateID(t *testing.T) {
	fake := newFakePTY()
	mgr := NewManager(func(context.Context, string) (PTY, error) { return fake, nil }, nil)

	if err := mgr.Open(context.Background(), "s1", 0, 0, ""); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := mgr.Open(context.Background(), "s1", 0, 0, ""); err == nil {
		t.Fatal("expected an error opening a duplicate session id")
	}
}

func TestOpenPropagatesSpawnerError(t *testing.T) {
	mgr := NewManager(func(context.Context, string) (PTY, error) { return nil, errors.New("boom") }, nil)
	if err := mgr.Open(context.Background(), "s1", 0, 0, ""); err == nil {
		t.Fatal("expected spawner error to propagate")
	}
}

func TestInputWritesToPTYStdin(t *testing.T) {
	fake := newFakePTY()
	mgr := NewManager(func(context.Context, string) (PTY, error) { return fake, nil }, nil)
	_ = mgr.Open(context.Background(), "s1", 0, 0, "")

	if err := mgr.Input("s1", []byte("echo hi\n")); err != nil {
		t.Fatalf("Input: %v", err)
	}
	if fake.writtenInput() != "echo hi\n" {
		t.Errorf("writtenInput = %q, want %q", fake.writtenInput(), "echo hi\n")
	}
}

func TestInputUnknownSessionErrors(t *testing.T) {
	mgr := NewManager(func(context.Context, string) (PTY, error) { return newFakePTY(), nil }, nil)
	if err := mgr.Input("nope", []byte("x")); err == nil {
		t.Fatal("expected an error for an unknown session id")
	}
}

func TestResizeAppliesToPTY(t *testing.T) {
	fake := newFakePTY()
	mgr := NewManager(func(context.Context, string) (PTY, error) { return fake, nil }, nil)
	_ = mgr.Open(context.Background(), "s1", 80, 24, "")

	if err := mgr.Resize("s1", 120, 50); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if fake.cols != 120 || fake.rows != 50 {
		t.Errorf("resize = %d,%d, want 120,50", fake.cols, fake.rows)
	}
}

func TestCloseKillsSessionAndIsIdempotent(t *testing.T) {
	fake := newFakePTY()
	mgr := NewManager(func(context.Context, string) (PTY, error) { return fake, nil }, nil)
	_ = mgr.Open(context.Background(), "s1", 0, 0, "")

	if err := mgr.Close("s1"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitFor(t, time.Second, func() bool { fake.mu.Lock(); defer fake.mu.Unlock(); return fake.closed })

	// Closing again, or acting on the now-gone session, must not panic or error.
	if err := mgr.Close("s1"); err != nil {
		t.Errorf("second Close returned an error: %v", err)
	}
	if err := mgr.Input("s1", []byte("x")); err == nil {
		t.Error("expected Input on a closed session to error")
	}
}

func TestCloseAllTearsDownEverySession(t *testing.T) {
	fake1, fake2 := newFakePTY(), newFakePTY()
	seq := []PTY{fake1, fake2}
	i := 0
	mgr := NewManager(func(context.Context, string) (PTY, error) {
		p := seq[i]
		i++
		return p, nil
	}, nil)

	_ = mgr.Open(context.Background(), "s1", 0, 0, "")
	_ = mgr.Open(context.Background(), "s2", 0, 0, "")

	mgr.CloseAll()

	waitFor(t, time.Second, func() bool {
		fake1.mu.Lock()
		fake2.mu.Lock()
		defer fake1.mu.Unlock()
		defer fake2.mu.Unlock()
		return fake1.closed && fake2.closed
	})
}

func TestPTYExitClosesSessionAndStopsEmitting(t *testing.T) {
	fake := newFakePTY()
	emit, calls := collectEmit()
	mgr := NewManager(func(context.Context, string) (PTY, error) { return fake, nil }, emit)
	_ = mgr.Open(context.Background(), "s1", 0, 0, "")

	fake.push("bye")
	_ = fake.Close() // simulate the shell process exiting — Read returns EOF next

	waitFor(t, time.Second, func() bool { return len(calls()) > 0 })

	// A pty_input after the session's Read loop already reaped it should error.
	waitFor(t, time.Second, func() bool { return mgr.Input("s1", []byte("x")) != nil })
}

func TestResolveTarget(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		// Absent resolves to the platform's defaultTarget — the workspace
		// container on a host that can run one (the console's browser
		// terminal has always sent no target, and a newer control plane
		// must not be able to silently move that session onto the host),
		// the host itself on Windows, where no container can exist. Asserted
		// against the constant so this passes on both.
		{"", defaultTarget, false},
		{TargetWorkspace, TargetWorkspace, false},
		{TargetHost, TargetHost, false},
		// A typo must fail loudly rather than defaulting — "hsot" opening a
		// shell in the wrong place is undetectable from the prompt.
		{"hsot", "", true},
		{"HOST", "", true},
	} {
		got, err := resolveTarget(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resolveTarget(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveTarget(%q) errored: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("resolveTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestOpenRejectsAnUnknownTargetWithoutSpawning(t *testing.T) {
	spawned := false
	mgr := NewManager(func(_ context.Context, target string) (PTY, error) {
		spawned = true
		return newFakePTY(), nil
	}, nil)

	// The real DefaultSpawner validates, so a Manager wired to a fake spawner
	// that ignores target must still not leave a half-open session behind.
	if err := mgr.Open(context.Background(), "s1", 0, 0, "host"); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	if !spawned {
		t.Error("spawner was never called for a valid target")
	}
}

func TestOpenPassesTargetThroughToTheSpawner(t *testing.T) {
	var got string
	mgr := NewManager(func(_ context.Context, target string) (PTY, error) {
		got = target
		return newFakePTY(), nil
	}, nil)

	if err := mgr.Open(context.Background(), "s1", 80, 24, TargetHost); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != TargetHost {
		t.Errorf("spawner got target %q, want %q", got, TargetHost)
	}
}

// TestWithTermOnlyFillsAMissingOne moved to spawn_unix_test.go — withTerm is
// POSIX-only now that the Windows terminal comes from ConPTY, which gets its
// environment from CreateProcess rather than from an env slice.
