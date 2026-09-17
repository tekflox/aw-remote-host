//go:build !windows

package diagdump

import (
	"context"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tekflox/aw-remote-host/internal/rlog"
)

// captureLog redirects rlog's console writer to a buffer for the duration
// of the test via rlog.Init — the only exported hook this package (outside
// rlog itself) has for that. HOME is pointed at a throwaway dir first so
// this doesn't also touch a real ~/.aw-remote-host/client.log.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	buf := &syncBuffer{}
	rlog.Init(buf)
	return buf
}

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestStart_DumpsGoroutinesOnSIGUSR1_NonFatal(t *testing.T) {
	buf := captureLog(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Start(ctx)

	// A named goroutine (well, named via its function so it's identifiable
	// in the stack dump) parked on a channel receive — the SIGUSR1 dump
	// must be able to name it, the same way the asyncio-task half on the
	// aw-backend side has to name a parked coroutine.
	block := make(chan struct{})
	defer close(block)
	go func() {
		<-block
	}()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to signal self: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "diagdump: SIGUSR1") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	out := buf.String()
	if !strings.Contains(out, "diagdump: SIGUSR1") {
		t.Fatalf("expected a SIGUSR1 dump line, got: %q", out)
	}
	if !strings.Contains(out, "goroutine") {
		t.Fatalf("expected goroutine stacks in the dump, got: %q", out)
	}

	// The whole point: the process (and this test) must still be alive to
	// observe the second signal too, unlike Go's default SIGQUIT handler.
	buf2 := &syncBuffer{}
	rlog.Init(buf2)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to signal self a second time: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf2.String(), "diagdump: SIGUSR1") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process did not keep handling SIGUSR1 after the first dump — got: %q", buf2.String())
}

func TestStart_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	Start(ctx)
	cancel()
	// No direct observable here beyond "doesn't panic/hang" — signal.Stop
	// inside Start's goroutine is exercised by simply letting the test
	// finish; a leaked goroutine would show up under -race/-count runs.
	time.Sleep(50 * time.Millisecond)
}
