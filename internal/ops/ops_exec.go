// Real command execution, added alongside the fixed lifecycle verbs above.
//
// Every job runs in its own goroutine from the moment exec_start is
// dispatched — handleCmd (internal/link) already runs each inbound "cmd"
// frame in its own goroutine so verbs never block the /link read loop
// against each other, but that alone isn't enough for exec: a *synchronous*
// exec_start would still tie up its own goroutine (and the caller waiting
// on cmd_result) for as long as the shelled-out command runs, so a single
// stuck command would never surface a result. Here exec_start only spawns
// the process and returns a job_id immediately; a separate per-job
// goroutine owns waiting on it, so N concurrent jobs run fully in
// parallel and a hung one never blocks another. exec_status/exec_wait/
// exec_kill/list_processes then let the caller poll, block-with-timeout,
// forcibly stop, or enumerate what's running — the same
// start/status/wait/kill shape the control plane already uses elsewhere
// for other long-running background work.
package ops

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

const (
	// Hard ceiling on how long a job is allowed to run before it's killed
	// outright — a runaway/hung command must never pin a slot forever.
	execHardTimeout = 30 * time.Minute
	// Default if the caller doesn't pass timeout_s.
	execDefaultTimeout = 5 * time.Minute
	// Per-stream output cap kept in memory (tail-truncated past this).
	execOutputCap = 1 << 20 // 1 MiB
	// exec_wait's own hard cap, independent of the job's execution timeout.
	execWaitHardCap = 5 * time.Minute
)

// ExecStatus is the lifecycle of one tracked job.
type ExecStatus string

const (
	ExecRunning ExecStatus = "running"
	ExecExited  ExecStatus = "exited"
	ExecKilled  ExecStatus = "killed"
	ExecTimeout ExecStatus = "timeout"
)

// execJob is one exec_start invocation. mu guards every mutable field —
// the owning goroutine (writing on completion) and any number of concurrent
// exec_status/exec_wait/exec_kill callers (reading, or requesting a kill)
// all touch the same job.
type execJob struct {
	mu sync.Mutex

	ID        string
	Command   string
	PID       int
	StartedAt time.Time

	status     ExecStatus
	exitCode   *int
	finishedAt *time.Time
	stdout     *capBuffer
	stderr     *capBuffer

	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan struct{} // closed when the job goroutine finishes
}

func (j *execJob) snapshot() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := map[string]any{
		"job_id":     j.ID,
		"command":    j.Command,
		"pid":        j.PID,
		"status":     string(j.status),
		"started_at": j.StartedAt.Unix(),
		"stdout":     j.stdout.String(),
		"stderr":     j.stderr.String(),
	}
	if j.exitCode != nil {
		out["exit_code"] = *j.exitCode
	}
	if j.finishedAt != nil {
		out["finished_at"] = j.finishedAt.Unix()
		out["runtime_s"] = j.finishedAt.Sub(j.StartedAt).Seconds()
	} else {
		out["runtime_s"] = time.Since(j.StartedAt).Seconds()
	}
	return out
}

// capBuffer is a bytes.Buffer that silently drops writes past execOutputCap
// instead of growing forever — a chatty/looping command must not exhaust
// this process's own memory. Safe for concurrent Write (the process's own
// stdout/stderr pump) and String (status/wait/list readers).
type capBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := execOutputCap - c.buf.Len()
	if room <= 0 {
		return len(p), nil // already at cap — accept-and-discard, don't error the process
	}
	if len(p) > room {
		p = p[:room]
	}
	return c.buf.Write(p)
}

func (c *capBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// execRegistry holds every job this process has started, for the lifetime
// of the process (no persistence across restarts — a restarted host has no
// jobs left to report on anyway, matching that a killed cmd connection
// already orphans anything mid-flight).
type execRegistry struct {
	mu   sync.Mutex
	jobs map[string]*execJob
}

var jobs = &execRegistry{jobs: map[string]*execJob{}}

func (r *execRegistry) add(j *execJob) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs[j.ID] = j
}

func (r *execRegistry) get(id string) (*execJob, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	return j, ok
}

func (r *execRegistry) list() []*execJob {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*execJob, 0, len(r.jobs))
	for _, j := range r.jobs {
		out = append(out, j)
	}
	return out
}

func newJobID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate job id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func floatArg(args map[string]any, key string, def float64) float64 {
	switch v := args[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return def
}

func stringArg(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

// ExecStart runs command through this host's shell ("sh -c" on POSIX,
// "powershell.exe -Command" on Windows — see shellCommand) as a new OS
// process in its own process group (so a shell that forks children can
// still be killed as a unit) and returns immediately —
// {job_id, pid, started: true}. args:
// "command" (required), "timeout_s" (optional, default execDefaultTimeout,
// hard-capped at execHardTimeout — the job is force-killed past this).
func (h *Handler) ExecStart(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	command := stringArg(args, "command")
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}

	timeout := time.Duration(floatArg(args, "timeout_s", execDefaultTimeout.Seconds()) * float64(time.Second))
	if timeout <= 0 || timeout > execHardTimeout {
		timeout = execHardTimeout
	}

	id, err := newJobID()
	if err != nil {
		return nil, err
	}

	// Deliberately NOT derived from ctx (the cmd-frame's request context,
	// which link.go's handleCmd may cancel once cmd_result is written) —
	// this job must keep running independently after exec_start replies.
	jobCtx, cancel := context.WithTimeout(context.Background(), timeout)
	shellName, shellArgs := shellCommand(command)
	cmd := exec.CommandContext(jobCtx, shellName, shellArgs...)
	configureProcessGroup(cmd)
	// Go's default ctx-cancel behavior only kills cmd.Process itself — if
	// the shell forked instead of exec'ing (a grandchild inherits the
	// stdout/stderr pipe fds this package wires below), that grandchild
	// keeps the pipe open and cmd.Wait() hangs past the deadline waiting
	// for EOF even though the direct child is long dead. Kill the whole
	// tree instead (killProcessTree — a process-group SIGKILL on POSIX, a
	// taskkill /T on Windows; see proc_unix.go / proc_windows.go), and
	// WaitDelay is the belt-and-braces backstop: if that still doesn't
	// free every fd holder within 2s, Wait() force-closes the pipes and
	// returns anyway. Without both of these, one forking command can hang
	// a job forever regardless of timeout_s — exactly the "não travar"
	// requirement this feature exists for.
	cmd.Cancel = func() error {
		return killProcessTree(cmd.Process.Pid)
	}
	cmd.WaitDelay = 2 * time.Second

	job := &execJob{
		ID:        id,
		Command:   command,
		StartedAt: time.Now(),
		status:    ExecRunning,
		stdout:    &capBuffer{},
		stderr:    &capBuffer{},
		cmd:       cmd,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	cmd.Stdout = job.stdout
	cmd.Stderr = job.stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start command: %w", err)
	}
	job.PID = cmd.Process.Pid
	jobs.add(job)
	emit("info", "exec", fmt.Sprintf("job %s started (pid %d): %s", id, job.PID, command))

	go func() {
		defer close(job.done)
		waitErr := cmd.Wait()
		defer cancel()

		job.mu.Lock()
		now := time.Now()
		job.finishedAt = &now
		switch {
		case jobCtx.Err() == context.DeadlineExceeded:
			job.status = ExecTimeout
		case job.status == ExecKilled:
			// exec_kill already set this — leave it.
		case waitErr == nil:
			code := 0
			job.exitCode = &code
			job.status = ExecExited
		default:
			code := -1
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			}
			job.exitCode = &code
			job.status = ExecExited
		}
		status := job.status
		job.mu.Unlock()

		emit("info", "exec", fmt.Sprintf("job %s finished: %s", id, status))
	}()

	return map[string]any{"job_id": id, "pid": job.PID, "started": true}, nil
}

// ExecStatus returns a job's current snapshot without blocking.
func (h *Handler) ExecStatus(ctx context.Context, args map[string]any) (map[string]any, error) {
	id := stringArg(args, "job_id")
	job, ok := jobs.get(id)
	if !ok {
		return nil, fmt.Errorf("unknown job_id %q", id)
	}
	return job.snapshot(), nil
}

// ExecWait blocks until the job reaches a terminal status or timeout_s
// elapses (default 30s, hard-capped at execWaitHardCap), then returns the
// current snapshot either way — check "status" to tell timeout-while-
// -still-running apart from a real terminal state.
func (h *Handler) ExecWait(ctx context.Context, args map[string]any) (map[string]any, error) {
	id := stringArg(args, "job_id")
	job, ok := jobs.get(id)
	if !ok {
		return nil, fmt.Errorf("unknown job_id %q", id)
	}

	timeout := time.Duration(floatArg(args, "timeout_s", 30) * float64(time.Second))
	if timeout <= 0 || timeout > execWaitHardCap {
		timeout = execWaitHardCap
	}

	select {
	case <-job.done:
	case <-time.After(timeout):
	case <-ctx.Done():
	}
	return job.snapshot(), nil
}

// ExecKill force-stops a job's whole process group (SIGKILL). Safe to call
// on an already-finished job — it's just a no-op then, not an error, since
// the caller racing the job's own natural completion is expected, not a
// mistake.
func (h *Handler) ExecKill(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	id := stringArg(args, "job_id")
	job, ok := jobs.get(id)
	if !ok {
		return nil, fmt.Errorf("unknown job_id %q", id)
	}

	job.mu.Lock()
	alreadyDone := job.status != ExecRunning
	pid := job.PID
	if !alreadyDone {
		job.status = ExecKilled
	}
	job.mu.Unlock()

	if alreadyDone {
		return map[string]any{"killed": false, "reason": "already finished"}, nil
	}

	// Kill the whole tree, not just the shell itself — a shell that forked
	// children gets all of them. configureProcessGroup at start time is
	// what makes that possible on both platforms.
	_ = killProcessTree(pid)
	job.cancel()
	emit("warning", "exec", fmt.Sprintf("job %s (pid %d) killed", id, pid))
	return map[string]any{"killed": true}, nil
}

// ListProcesses enumerates every job this process has started (running and
// finished), most-recently-started first.
func (h *Handler) ListProcesses(ctx context.Context) map[string]any {
	all := jobs.list()
	out := make([]map[string]any, 0, len(all))
	for _, j := range all {
		snap := j.snapshot()
		// Trim the (possibly large) output blobs out of the list view —
		// callers wanting full stdout/stderr use exec_status per job_id.
		delete(snap, "stdout")
		delete(snap, "stderr")
		out = append(out, snap)
	}
	for i, j := 0, len(out); i < j/2; i++ {
		out[i], out[j-1-i] = out[j-1-i], out[i]
	}
	return map[string]any{"count": len(out), "processes": out}
}
