//go:build !windows

package ops

import (
	"strings"
	"testing"
)

// withTempMachineDir points instance.MachineDir() at a temp dir by moving
// HOME, so these tests never touch the real ~/.aw-remote-host lockfile.
func withTempMachineDir(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

// The headline requirement: ten frantic Update clicks must produce one
// holder and nine rejections, not ten concurrent passes.
func TestAcquireWorkspaceLockAdmitsOneOfTen(t *testing.T) {
	withTempMachineDir(t)

	release, err := acquireWorkspaceLock("update", nil)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	defer release()

	for i := 0; i < 9; i++ {
		if _, err := acquireWorkspaceLock("update", nil); err == nil {
			t.Fatalf("click %d was admitted while the first still holds the lock", i+2)
		} else if !IsWorkspaceBusy(err) {
			t.Fatalf("click %d failed for the wrong reason: %v", i+2, err)
		}
	}
}

// The user must be told why their click did nothing — a silent no-op reads
// as a broken button.
func TestAcquireWorkspaceLockEmitsUserFacingRejection(t *testing.T) {
	withTempMachineDir(t)

	release, err := acquireWorkspaceLock("update", nil)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	defer release()

	var levels, phases, messages []string
	emit := func(level, phase, message string) {
		levels = append(levels, level)
		phases = append(phases, phase)
		messages = append(messages, message)
	}
	_, err = acquireWorkspaceLock("update", emit)
	if err == nil {
		t.Fatal("second acquire was admitted")
	}
	if len(messages) != 1 {
		t.Fatalf("expected exactly one emit, got %d: %v", len(messages), messages)
	}
	if levels[0] != "warning" || phases[0] != "update" {
		t.Fatalf("rejection emitted as %q/%q, want warning/update", levels[0], phases[0])
	}
	// The message must name the holder so the user can tell this apart from
	// a generic failure, and must say the lock self-clears.
	for _, want := range []string{"already in progress", "\"update\"", "crashes or is killed"} {
		if !strings.Contains(messages[0], want) {
			t.Errorf("rejection message missing %q: %s", want, messages[0])
		}
	}
	// The returned error carries the same text, so a caller that ignores
	// emit still surfaces something actionable.
	if err.Error() != messages[0] {
		t.Errorf("error text diverged from the emitted message:\n err: %s\nemit: %s", err.Error(), messages[0])
	}
}

// Release must make the lock immediately reusable — the next legitimate
// update cannot be stranded behind a finished one.
func TestWorkspaceLockReleasedWhenOperationFinishes(t *testing.T) {
	withTempMachineDir(t)

	release, err := acquireWorkspaceLock("update", nil)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	release()

	second, err := acquireWorkspaceLock("update", nil)
	if err != nil {
		t.Fatalf("acquire after release was rejected: %v", err)
	}
	second()

	// Idempotent: a deferred release after an explicit one must not panic
	// or hand the lock to nobody.
	release()
	third, err := acquireWorkspaceLock("reinstall", nil)
	if err != nil {
		t.Fatalf("acquire after a double release was rejected: %v", err)
	}
	third()
}

// A different recreate verb contends on the SAME lock — the contended
// resource is the workspace container, not the verb name.
func TestWorkspaceLockIsSharedAcrossRecreateVerbs(t *testing.T) {
	withTempMachineDir(t)

	release, err := acquireWorkspaceLock("update", nil)
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	defer release()

	_, err = acquireWorkspaceLock("bootstrap", nil)
	if err == nil {
		t.Fatal("bootstrap was admitted while an update holds the lock")
	}
	if !IsWorkspaceBusy(err) {
		t.Fatalf("bootstrap rejected for the wrong reason: %v", err)
	}
	// The rejection should name the UPDATE that is actually running, not
	// the verb being refused.
	if !strings.Contains(err.Error(), "\"update\"") {
		t.Errorf("rejection should name the holding verb: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "ignoring this bootstrap request") {
		t.Errorf("rejection should name the refused verb: %s", err.Error())
	}
}

// Only the verbs that recreate the container are gated. stop/restart/
// uninstall are the recovery path and must never be blocked by a wedged
// update — see the comment in Dispatch.
func TestOnlyRecreateVerbsAreLocked(t *testing.T) {
	for _, verb := range []string{"update", "reinstall", "bootstrap"} {
		if !workspaceRecreateVerbs[verb] {
			t.Errorf("%q recreates the workspace container but is not lock-gated", verb)
		}
	}
	for _, verb := range []string{"stop", "restart", "uninstall", "health", "exec_start"} {
		if workspaceRecreateVerbs[verb] {
			t.Errorf("%q is gated by the lifecycle lock but must stay on the recovery path", verb)
		}
	}
}
