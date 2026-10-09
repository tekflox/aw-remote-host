package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceLogsPodmanArgsDefaults(t *testing.T) {
	args, follow, timeout := workspaceLogsPodmanArgs(map[string]any{})
	want := []string{"logs", "--timestamps", "--tail", "200", WorkspaceContainer}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", args, want)
	}
	if follow {
		t.Error("follow should default to false")
	}
	if timeout != 2*time.Minute {
		t.Errorf("timeout = %v, want 2m for a non-follow tail", timeout)
	}
}

func TestWorkspaceLogsPodmanArgsCapsTail(t *testing.T) {
	args, _, _ := workspaceLogsPodmanArgs(map[string]any{"tail": float64(999999)})
	if !contains(args, "--tail") {
		t.Fatalf("args = %v, missing --tail", args)
	}
	if contains(args, "999999") {
		t.Errorf("args = %v, tail should have been capped at %d", args, maxLogTail)
	}
}

func TestWorkspaceLogsPodmanArgsFollowAndSince(t *testing.T) {
	args, follow, timeout := workspaceLogsPodmanArgs(map[string]any{"follow": true, "since": "10m"})
	if !follow {
		t.Error("follow should be true")
	}
	if timeout != execHardTimeout {
		t.Errorf("timeout = %v, want execHardTimeout for a follow job", timeout)
	}
	if !contains(args, "--since") || !contains(args, "10m") {
		t.Errorf("args = %v, missing --since 10m", args)
	}
	if !contains(args, "--follow") {
		t.Errorf("args = %v, missing --follow", args)
	}
}

func TestWorkspaceLogsLiveTailUsesRunner(t *testing.T) {
	r := newFakeRunner()
	r.on("hello from the workspace\n", "podman", "logs", "--timestamps", "--tail", "50", WorkspaceContainer)
	h := &Handler{Runner: r}

	data, err := h.WorkspaceLogs(context.Background(), map[string]any{"tail": float64(50)}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["output"] != "hello from the workspace\n" {
		t.Errorf("unexpected output: %v", data)
	}
	if data["follow"] != false {
		t.Errorf("expected follow=false in the reply, got %v", data)
	}
}

func TestWorkspaceLogsLiveTailWrapsRunnerError(t *testing.T) {
	r := newFakeRunner()
	r.fail(os.ErrNotExist, "podman", "logs", "--timestamps", "--tail", "200", WorkspaceContainer)
	h := &Handler{Runner: r}

	_, err := h.WorkspaceLogs(context.Background(), map[string]any{}, nil)
	if err == nil {
		t.Fatal("expected an error when podman logs fails")
	}
}

func TestWorkspaceLogsRejectsUnknownSource(t *testing.T) {
	useTempWorkspaceLogSnapshotDir(t)
	h := &Handler{Runner: newFakeRunner()}
	if _, err := h.WorkspaceLogs(context.Background(), map[string]any{"source": "future"}, nil); err == nil {
		t.Fatal("expected an error for an unknown source")
	}
}

func TestWorkspaceLogsIsAWorkspaceLifecycleVerb(t *testing.T) {
	if !workspaceLifecycleVerbs["workspace_logs"] {
		t.Error("workspace_logs should be gated behind a local workspace runtime, same as stop/restart/update")
	}
}

func TestDispatchRoutesWorkspaceLogs(t *testing.T) {
	r := newFakeRunner()
	r.on("a log line\n", "podman", "logs", "--timestamps", "--tail", "200", WorkspaceContainer)
	h := &Handler{Runner: r}

	data, err := h.Dispatch(context.Background(), "workspace_logs", map[string]any{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := data.(map[string]any)
	if !ok || got["output"] != "a log line\n" {
		t.Errorf("unexpected Dispatch result: %v", data)
	}
}

func TestWorkspaceLogsPreviousSourceWithNoSnapshotIsNotFound(t *testing.T) {
	useTempWorkspaceLogSnapshotDir(t)
	h := &Handler{Runner: newFakeRunner()}

	data, err := h.WorkspaceLogs(context.Background(), map[string]any{"source": "previous"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["found"] != false {
		t.Errorf("expected found=false with no snapshot on disk, got %v", data)
	}
}

func TestSnapshotWorkspaceLogBeforeRecreateWritesAndIsReadableAsPrevious(t *testing.T) {
	useTempWorkspaceLogSnapshotDir(t)
	r := newFakeRunner()
	r.on("boot output line 1\nboot output line 2\n", "podman", "logs", "--timestamps", WorkspaceContainer)
	h := &Handler{Runner: r}
	emit, lines := collectEmits()

	h.snapshotWorkspaceLogBeforeRecreate(context.Background(), emit)

	dir, err := workspaceLogSnapshotDir()
	if err != nil {
		t.Fatalf("workspaceLogSnapshotDir: %v", err)
	}
	names := listWorkspaceLogSnapshots(dir)
	if len(names) != 1 {
		t.Fatalf("expected exactly one snapshot file, got %v", names)
	}
	if len(*lines) == 0 {
		t.Error("expected an activity emit confirming the snapshot was saved")
	}

	data, err := h.WorkspaceLogs(context.Background(), map[string]any{"source": "previous"}, nil)
	if err != nil {
		t.Fatalf("unexpected error reading it back: %v", err)
	}
	if data["found"] != true || data["content"] != "boot output line 1\nboot output line 2\n" {
		t.Errorf("unexpected previous-log reply: %v", data)
	}
}

func TestSnapshotWorkspaceLogBeforeRecreateIsBestEffortOnRunnerFailure(t *testing.T) {
	useTempWorkspaceLogSnapshotDir(t)
	r := newFakeRunner()
	r.fail(os.ErrNotExist, "podman", "logs", "--timestamps", WorkspaceContainer)
	h := &Handler{Runner: r}
	emit, _ := collectEmits()

	// Must not panic and must not block Update — a container that never
	// ran (first bootstrap) has nothing worth saving.
	h.snapshotWorkspaceLogBeforeRecreate(context.Background(), emit)

	dir, _ := workspaceLogSnapshotDir()
	if names := listWorkspaceLogSnapshots(dir); len(names) != 0 {
		t.Errorf("expected no snapshot written on a runner failure, got %v", names)
	}
}

func TestPruneWorkspaceLogSnapshotsKeepsOnlyTheNewest(t *testing.T) {
	dir := t.TempDir()
	// Lexically increasing names so the chronological assumption holds.
	allNames := []string{
		"boot-20260101T000000Z.log",
		"boot-20260102T000000Z.log",
		"boot-20260103T000000Z.log",
		"boot-20260104T000000Z.log",
		"boot-20260105T000000Z.log",
		"boot-20260106T000000Z.log",
		"boot-20260107T000000Z.log",
	}
	for _, n := range allNames {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatalf("seed snapshot file: %v", err)
		}
	}

	pruneWorkspaceLogSnapshots(dir, workspaceLogSnapshotKeep)

	remaining := listWorkspaceLogSnapshots(dir)
	if len(remaining) != workspaceLogSnapshotKeep {
		t.Fatalf("expected %d snapshots left, got %d: %v", workspaceLogSnapshotKeep, len(remaining), remaining)
	}
	want := allNames[len(allNames)-workspaceLogSnapshotKeep:]
	if strings.Join(remaining, ",") != strings.Join(want, ",") {
		t.Errorf("kept %v, want the newest %v", remaining, want)
	}
}
