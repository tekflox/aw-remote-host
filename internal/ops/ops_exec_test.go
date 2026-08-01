package ops

import (
	"context"
	"strings"
	"testing"
	"time"
)

func waitForStatus(t *testing.T, h *Handler, jobID string, want ExecStatus, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	var last map[string]any
	for time.Now().Before(deadline) {
		snap, err := h.ExecStatus(context.Background(), map[string]any{"job_id": jobID})
		if err != nil {
			t.Fatalf("exec_status: %v", err)
		}
		last = snap
		if ExecStatus(snap["status"].(string)) == want {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s never reached status %q, last snapshot: %#v", jobID, want, last)
	return nil
}

func TestExecStartCapturesStdoutAndExitsCleanly(t *testing.T) {
	h := &Handler{}
	res, err := h.ExecStart(context.Background(), map[string]any{"command": "echo hello-exec"}, nil)
	if err != nil {
		t.Fatalf("exec_start: %v", err)
	}
	jobID, _ := res["job_id"].(string)
	if jobID == "" {
		t.Fatalf("expected a job_id, got %#v", res)
	}
	if res["started"] != true {
		t.Fatalf("expected started=true, got %#v", res)
	}

	snap := waitForStatus(t, h, jobID, ExecExited, 2*time.Second)
	if !strings.Contains(snap["stdout"].(string), "hello-exec") {
		t.Fatalf("expected stdout to contain the echoed text, got %q", snap["stdout"])
	}
	if code, _ := snap["exit_code"].(int); code != 0 {
		t.Fatalf("expected exit_code 0, got %#v", snap["exit_code"])
	}
}

func TestExecStartRequiresCommand(t *testing.T) {
	h := &Handler{}
	if _, err := h.ExecStart(context.Background(), map[string]any{}, nil); err == nil {
		t.Fatal("expected an error for a missing command")
	}
}

func TestExecStatusUnknownJobErrors(t *testing.T) {
	h := &Handler{}
	if _, err := h.ExecStatus(context.Background(), map[string]any{"job_id": "does-not-exist"}); err == nil {
		t.Fatal("expected an error for an unknown job_id")
	}
}

// A hung command's exec_start must return immediately (job_id, not a
// blocking wait) — this is the core "não trava" requirement. It races a
// slow job's exec_start call against a fast job's full completion to prove
// the fast one isn't stuck behind the slow one.
func TestExecStartDoesNotBlockOnSlowCommand(t *testing.T) {
	h := &Handler{}

	slowDone := make(chan struct{})
	go func() {
		defer close(slowDone)
		if _, err := h.ExecStart(context.Background(), map[string]any{"command": "sleep 5", "timeout_s": 10}, nil); err != nil {
			t.Errorf("slow exec_start: %v", err)
		}
	}()

	select {
	case <-slowDone:
	case <-time.After(2 * time.Second):
		t.Fatal("exec_start blocked instead of returning immediately for a long-running command")
	}

	fast, err := h.ExecStart(context.Background(), map[string]any{"command": "echo fast"}, nil)
	if err != nil {
		t.Fatalf("fast exec_start: %v", err)
	}
	waitForStatus(t, h, fast["job_id"].(string), ExecExited, 2*time.Second)
}

// Two commands started back-to-back must run concurrently, not serially —
// proves jobs don't share a lock across their whole lifetime.
func TestConcurrentJobsRunInParallelNotSerially(t *testing.T) {
	h := &Handler{}
	started := time.Now()

	a, err := h.ExecStart(context.Background(), map[string]any{"command": "sleep 0.5"}, nil)
	if err != nil {
		t.Fatalf("exec_start a: %v", err)
	}
	b, err := h.ExecStart(context.Background(), map[string]any{"command": "sleep 0.5"}, nil)
	if err != nil {
		t.Fatalf("exec_start b: %v", err)
	}

	waitForStatus(t, h, a["job_id"].(string), ExecExited, 3*time.Second)
	waitForStatus(t, h, b["job_id"].(string), ExecExited, 3*time.Second)

	elapsed := time.Since(started)
	if elapsed > 900*time.Millisecond {
		t.Fatalf("two 0.5s jobs took %s — looks serial, not parallel", elapsed)
	}
}

func TestExecKillStopsAHungCommand(t *testing.T) {
	h := &Handler{}
	res, err := h.ExecStart(context.Background(), map[string]any{"command": "sleep 30", "timeout_s": 60}, nil)
	if err != nil {
		t.Fatalf("exec_start: %v", err)
	}
	jobID := res["job_id"].(string)

	// Give it a moment to actually be running before killing.
	time.Sleep(50 * time.Millisecond)

	killRes, err := h.ExecKill(context.Background(), map[string]any{"job_id": jobID}, nil)
	if err != nil {
		t.Fatalf("exec_kill: %v", err)
	}
	if killRes["killed"] != true {
		t.Fatalf("expected killed=true, got %#v", killRes)
	}

	snap := waitForStatus(t, h, jobID, ExecKilled, 2*time.Second)
	if snap["status"] != string(ExecKilled) {
		t.Fatalf("expected status=killed, got %#v", snap["status"])
	}
}

func TestExecKillOnAlreadyFinishedJobIsANoop(t *testing.T) {
	h := &Handler{}
	res, err := h.ExecStart(context.Background(), map[string]any{"command": "true"}, nil)
	if err != nil {
		t.Fatalf("exec_start: %v", err)
	}
	jobID := res["job_id"].(string)
	waitForStatus(t, h, jobID, ExecExited, 2*time.Second)

	killRes, err := h.ExecKill(context.Background(), map[string]any{"job_id": jobID}, nil)
	if err != nil {
		t.Fatalf("exec_kill on finished job: %v", err)
	}
	if killRes["killed"] != false {
		t.Fatalf("expected killed=false for an already-finished job, got %#v", killRes)
	}
}

func TestExecStartEnforcesHardTimeout(t *testing.T) {
	h := &Handler{}
	res, err := h.ExecStart(context.Background(), map[string]any{"command": "sleep 5", "timeout_s": 0.2}, nil)
	if err != nil {
		t.Fatalf("exec_start: %v", err)
	}
	snap := waitForStatus(t, h, res["job_id"].(string), ExecTimeout, 2*time.Second)
	if snap["status"] != string(ExecTimeout) {
		t.Fatalf("expected status=timeout, got %#v", snap["status"])
	}
}

func TestExecWaitReturnsPromptlyOnFastJobAndOnTimeoutForSlowJob(t *testing.T) {
	h := &Handler{}

	fast, err := h.ExecStart(context.Background(), map[string]any{"command": "echo done"}, nil)
	if err != nil {
		t.Fatalf("exec_start: %v", err)
	}
	waitRes, err := h.ExecWait(context.Background(), map[string]any{"job_id": fast["job_id"], "timeout_s": 2})
	if err != nil {
		t.Fatalf("exec_wait: %v", err)
	}
	if waitRes["status"] != string(ExecExited) {
		t.Fatalf("expected exited, got %#v", waitRes["status"])
	}

	slow, err := h.ExecStart(context.Background(), map[string]any{"command": "sleep 2", "timeout_s": 10}, nil)
	if err != nil {
		t.Fatalf("exec_start slow: %v", err)
	}
	before := time.Now()
	waitRes, err = h.ExecWait(context.Background(), map[string]any{"job_id": slow["job_id"], "timeout_s": 0.2})
	if err != nil {
		t.Fatalf("exec_wait: %v", err)
	}
	if time.Since(before) > time.Second {
		t.Fatalf("exec_wait didn't respect its own timeout_s, took %s", time.Since(before))
	}
	if waitRes["status"] != string(ExecRunning) {
		t.Fatalf("expected still-running snapshot on wait timeout, got %#v", waitRes["status"])
	}
	_, _ = h.ExecKill(context.Background(), map[string]any{"job_id": slow["job_id"]}, nil)
}

func TestListProcessesIncludesStartedJobsWithoutOutputBlobs(t *testing.T) {
	h := &Handler{}
	res, err := h.ExecStart(context.Background(), map[string]any{"command": "echo list-me"}, nil)
	if err != nil {
		t.Fatalf("exec_start: %v", err)
	}
	jobID := res["job_id"].(string)
	waitForStatus(t, h, jobID, ExecExited, 2*time.Second)

	list := h.ListProcesses(context.Background())
	procs, _ := list["processes"].([]map[string]any)
	var found map[string]any
	for _, p := range procs {
		if p["job_id"] == jobID {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatalf("expected job %s in list_processes output, got %#v", jobID, list)
	}
	if _, ok := found["stdout"]; ok {
		t.Fatalf("list_processes entries should not carry full stdout, got %#v", found)
	}
}

func TestDispatchRoutesExecVerbs(t *testing.T) {
	h := &Handler{}
	res, err := h.Dispatch(context.Background(), "exec_start", map[string]any{"command": "echo via-dispatch"}, nil)
	if err != nil {
		t.Fatalf("dispatch exec_start: %v", err)
	}
	data := res.(map[string]any)
	jobID := data["job_id"].(string)

	if _, err := h.Dispatch(context.Background(), "exec_status", map[string]any{"job_id": jobID}, nil); err != nil {
		t.Fatalf("dispatch exec_status: %v", err)
	}
	if _, err := h.Dispatch(context.Background(), "exec_wait", map[string]any{"job_id": jobID, "timeout_s": 2}, nil); err != nil {
		t.Fatalf("dispatch exec_wait: %v", err)
	}
	if _, err := h.Dispatch(context.Background(), "list_processes", nil, nil); err != nil {
		t.Fatalf("dispatch list_processes: %v", err)
	}
}
