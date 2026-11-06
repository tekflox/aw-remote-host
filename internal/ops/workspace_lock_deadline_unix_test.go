//go:build !windows

package ops

import (
	"context"
	"testing"
	"time"
)

// allHangRunner blocks every shellout until its ctx ends — the whole podman
// daemon wedged, not just one call.
type allHangRunner struct{}

func (allHangRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// A verb that never returns must not hold the lifecycle lock forever: the
// per-verb deadline ends it, and the NEXT click is admitted instead of being
// rejected as "already in progress" for the rest of the host's life.
func TestLifecycleVerbDeadlineReleasesTheLock(t *testing.T) {
	withTempMachineDir(t)
	stubRunModule(t)
	prev := lifecycleVerbTimeout
	lifecycleVerbTimeout = 100 * time.Millisecond
	t.Cleanup(func() { lifecycleVerbTimeout = prev })

	h := &Handler{Runner: allHangRunner{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.Dispatch(context.Background(), "reinstall", nil, nil)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reinstall did not return; the deadline never fired and the lock would be held forever")
	}

	release, err := acquireWorkspaceLock("update", nil)
	if err != nil {
		t.Fatalf("lock still held after the verb timed out: %v", err)
	}
	release()
}
