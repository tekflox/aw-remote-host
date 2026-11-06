package ops

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// deadlockRunner reproduces the 2026-11-06 libpod lock-order deadlock at the
// Runner seam: `podman rm --depend <workspace>` blocks until its ctx is
// cancelled (what a wedged client does until it is killed), for the first
// hangFirst calls, then behaves normally.
type deadlockRunner struct {
	*fakeRunner
	mu        sync.Mutex
	hangFirst int
	depends   int
}

func (d *deadlockRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "podman" && len(args) > 0 && args[0] == "rm" && contains(args, "--depend") {
		d.mu.Lock()
		d.depends++
		hang := d.depends <= d.hangFirst
		d.mu.Unlock()
		if hang {
			d.fakeRunner.Run(ctx, name, args...) // record the call
			<-ctx.Done()
			return "", ctx.Err()
		}
	}
	return d.fakeRunner.Run(ctx, name, args...)
}

func fastTimeouts(t *testing.T) {
	t.Helper()
	prev := podmanStepTimeout
	podmanStepTimeout = 30 * time.Millisecond
	t.Cleanup(func() { podmanStepTimeout = prev })
}

func callIndex(f *fakeRunner, want ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.calls {
		if strings.Join(c, " ") == strings.Join(want, " ") {
			return i
		}
	}
	return -1
}

func TestRemoveWorkspaceRetriesAHungRmAndSucceeds(t *testing.T) {
	fastTimeouts(t)
	r := &deadlockRunner{fakeRunner: newFakeRunner(), hangFirst: 2}
	h := &Handler{Runner: r}
	emit, lines := collectEmits()

	start := time.Now()
	if err := h.removeWorkspaceContainer(context.Background(), emit); err != nil {
		t.Fatalf("a hang that clears on retry must not fail the update: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %s; the deadline did not free the caller", time.Since(start))
	}
	if r.depends != 3 {
		t.Fatalf("rm --depend attempts = %d, want 3 (2 hung + 1 ok)", r.depends)
	}
	if got := strings.Count(strings.Join(*lines, "\n"), "hung (attempt"); got != 2 {
		t.Fatalf("expected 2 hang warnings, got %d: %v", got, *lines)
	}
}

func TestRemoveWorkspaceGivesUpAfterBoundedAttempts(t *testing.T) {
	fastTimeouts(t)
	r := &deadlockRunner{fakeRunner: newFakeRunner(), hangFirst: 1000}
	h := &Handler{Runner: r}
	emit, _ := collectEmits()

	err := h.removeWorkspaceContainer(context.Background(), emit)
	if err == nil || !errors.Is(err, errStepTimeout) {
		t.Fatalf("a permanently wedged rm must fail loudly with a timeout, got %v", err)
	}
	if !strings.Contains(err.Error(), "libpod lock deadlock") {
		t.Fatalf("error should name the likely cause: %v", err)
	}
	if r.depends != removeWorkspaceAttempts {
		t.Fatalf("attempts = %d, want %d", r.depends, removeWorkspaceAttempts)
	}
}

func TestRemoveWorkspaceDoesNotRetryARealFailure(t *testing.T) {
	r := &deadlockRunner{fakeRunner: newFakeRunner()}
	r.on("some real podman error", "podman", "rm", "-f", "--ignore", "--depend", WorkspaceContainer)
	r.fail(errors.New("exit status 125"), "podman", "rm", "-f", "--ignore", "--depend", WorkspaceContainer)
	h := &Handler{Runner: r}

	err := h.removeWorkspaceContainer(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "some real podman error") {
		t.Fatalf("real failure must surface podman's own message, got %v", err)
	}
	if r.depends != 1 {
		t.Fatalf("a real failure was retried %d times", r.depends)
	}
}

// The structural half of the fix: runners are removed one call at a time
// BEFORE the workspace, so no single call holds the workspace lock while
// waiting on a runner's.
func TestRemoveWorkspaceRemovesWarmRunnersIndividuallyFirst(t *testing.T) {
	r := &deadlockRunner{fakeRunner: newFakeRunner()}
	const w1 = "aw-warm-aaa-111"
	const w2 = "aw-warm-bbb-222-draining-1793979148"
	r.on(w1+"\n"+w2+"\nunrelated-container\n", "podman", "ps", "-a",
		"--filter", "name=aw-warm-", "--format", "{{.Names}}")
	h := &Handler{Runner: r}

	if err := h.removeWorkspaceContainer(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	i1 := callIndex(r.fakeRunner, "podman", "rm", "-f", "--ignore", w1)
	i2 := callIndex(r.fakeRunner, "podman", "rm", "-f", "--ignore", w2)
	iw := callIndex(r.fakeRunner, "podman", "rm", "-f", "--ignore", "--depend", WorkspaceContainer)
	if i1 < 0 || i2 < 0 || iw < 0 {
		t.Fatalf("missing removals: w1=%d w2=%d workspace=%d calls=%v", i1, i2, iw, r.calls)
	}
	if !(i1 < iw && i2 < iw) {
		t.Fatalf("warm runners must be removed before the workspace: %d,%d vs %d", i1, i2, iw)
	}
	if r.ran("unrelated-container") {
		t.Fatal("removed a container that is not a warm runner")
	}
}

func TestRemoveWorkspaceStopsWhenTheOperationIsCancelled(t *testing.T) {
	fastTimeouts(t)
	r := &deadlockRunner{fakeRunner: newFakeRunner(), hangFirst: 1000}
	h := &Handler{Runner: r}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := h.removeWorkspaceContainer(ctx, nil)
	if err == nil || errors.Is(err, errStepTimeout) {
		t.Fatalf("a cancelled operation is not a step timeout (no retry loop): %v", err)
	}
	if r.depends > 1 {
		t.Fatalf("kept retrying after cancellation: %d attempts", r.depends)
	}
}

// The production runner itself must honour the deadline: a real child that
// ignores nothing but never exits is killed and the caller is freed.
func TestExecRunnerReturnsWhenTheDeadlineKillsAHungChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := execRunner{}.Run(ctx, "sleep", "30")
	if err == nil {
		t.Fatal("expected the hung child to be killed")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("Run blocked %s past its deadline", time.Since(start))
	}
}
