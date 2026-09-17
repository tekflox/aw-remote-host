package ops

import (
	"context"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
)

// A lean host (never provisioned with a local runtime) must never be
// silently provisioned by this loop — the whole point of gating on
// localRuntimeProvisioned before checking for zombies at all.
func TestSelfHealTick_LeanHostDoesNothing(t *testing.T) {
	ran := stubRunModule(t)
	r := newFakeRunner()
	r.fail(errNoSuchContainer, "podman", "inspect", WorkspaceContainer)
	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	h.selfHealTick(context.Background(), emit)

	if len(*ran) != 0 {
		t.Fatalf("lean host must never trigger a reconcile, ran=%v", *ran)
	}
	if r.ran("exec") {
		t.Fatalf("lean host must never be probed for zombie containers: calls=%v", r.calls)
	}
	if len(*lines) != 0 {
		t.Fatalf("lean host must emit nothing, got %v", *lines)
	}
}

// A provisioned host whose three containers all answer `podman exec ... true`
// must be left alone — no reconcile, no log noise on every tick.
func TestSelfHealTick_HealthyHostDoesNothing(t *testing.T) {
	ran := stubRunModule(t)
	r := newFakeRunner()
	r.on("true", "podman", "inspect", WorkspaceContainer)
	for _, name := range zombieCheckContainers {
		r.on("", "podman", "exec", name, "true")
	}
	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	h.selfHealTick(context.Background(), emit)

	if len(*ran) != 0 {
		t.Fatalf("healthy host must never trigger a reconcile, ran=%v", *ran)
	}
	if len(*lines) != 0 {
		t.Fatalf("healthy host must emit nothing, got %v", *lines)
	}
}

// The incident this exists for: podman inspect says WorkspaceContainer
// exists (this host WAS provisioned), but postgres and redis are zombies —
// `podman exec` on them fails exactly the way `crun: the container ... is
// not running` did live. A reconcile must be triggered, and it must be the
// FULL module set (the same one Bootstrap()/the console's Install button
// runs), not a partial one — a zombie postgres needs the whole manifest
// re-verified, not just the workspace container recreated in isolation.
func TestSelfHealTick_ZombieTriggersFullReconcile(t *testing.T) {
	ran := stubRunModule(t)
	r := newFakeRunner()
	r.on("true", "podman", "inspect", WorkspaceContainer)
	r.fail(errContainerNotRunning, "podman", "exec", PostgresContainer, "true")
	r.fail(errContainerNotRunning, "podman", "exec", RedisContainer, "true")
	r.on("", "podman", "exec", WorkspaceContainer, "true")
	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	h.selfHealTick(context.Background(), emit)

	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}
	var required []string
	for _, mod := range m.Modules {
		if !mod.Optional {
			required = append(required, mod.Name)
		}
	}
	for _, name := range required {
		if !contains(*ran, name) {
			t.Errorf("zombie detection should have run the full manifest — missing module %q, ran=%v", name, *ran)
		}
	}
	if !anyContains(*lines, "detected zombie container") {
		t.Errorf("expected a warning naming the zombie containers, got %v", *lines)
	}
	if !anyContains(*lines, PostgresContainer) || !anyContains(*lines, RedisContainer) {
		t.Errorf("the zombie warning should name the actual containers found dead, got %v", *lines)
	}
}

// After a successful reconcile the post-check re-probes the same three
// containers — if THEY now answer, this is a real recovery and must say so,
// not just "we ran a reconcile and hoped".
func TestSelfHealTick_RecoversAfterReconcile(t *testing.T) {
	stubRunModule(t)
	r := &recoveringRunner{fakeRunner: newFakeRunner()}
	r.on("true", "podman", "inspect", WorkspaceContainer)
	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	h.selfHealTick(context.Background(), emit)

	if !anyContains(*lines, "recovered") {
		t.Errorf("expected a recovery confirmation after the containers started answering, got %v", *lines)
	}
	if anyContains(*lines, "still unhealthy") {
		t.Errorf("must not report still-unhealthy once the post-check passes, got %v", *lines)
	}
}

// A reconcile that runs but does NOT actually bring the containers back —
// runModule reports healthy while the real podman exec probe still fails,
// which is exactly the gap a stale-but-"OK" module status could hide — must
// say so loudly rather than claim success it didn't verify.
func TestSelfHealTick_StillZombieAfterReconcileIsReportedNotHidden(t *testing.T) {
	stubRunModule(t)
	r := newFakeRunner()
	r.on("true", "podman", "inspect", WorkspaceContainer)
	r.fail(errContainerNotRunning, "podman", "exec", PostgresContainer, "true")
	r.on("", "podman", "exec", RedisContainer, "true")
	r.on("", "podman", "exec", WorkspaceContainer, "true")
	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	h.selfHealTick(context.Background(), emit)

	if !anyContains(*lines, "still unhealthy") {
		t.Errorf("expected an explicit still-unhealthy/needs-a-human report, got %v", *lines)
	}
	if !anyContains(*lines, PostgresContainer) {
		t.Errorf("the still-unhealthy report should name postgres specifically, got %v", *lines)
	}
	if anyContains(*lines, "recovered") {
		t.Errorf("must not claim recovery when a container is still not answering, got %v", *lines)
	}
}

func anyContains(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

var (
	errNoSuchContainer     = &fakeExecError{"no such container"}
	errContainerNotRunning = &fakeExecError{"OCI runtime error: crun: the container is not running"}
)

type fakeExecError struct{ msg string }

func (e *fakeExecError) Error() string { return e.msg }

// recoveringRunner answers `podman exec <core container> true` with a
// failure on the FIRST call and success on every call after — simulating a
// reconcile that genuinely fixes the containers, so the post-reconcile
// re-check (not just "runModule said OK") is what proves recovery.
type recoveringRunner struct {
	*fakeRunner
	execCalls map[string]int
}

func (r *recoveringRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "podman" && len(args) == 3 && args[0] == "exec" && args[2] == "true" {
		if r.execCalls == nil {
			r.execCalls = map[string]int{}
		}
		container := args[1]
		r.execCalls[container]++
		if r.execCalls[container] == 1 {
			return "", errContainerNotRunning
		}
		return "", nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}
