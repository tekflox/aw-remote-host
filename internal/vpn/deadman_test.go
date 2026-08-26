//go:build !windows

package vpn

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// homeIn points HOME at a temp dir so the switch's state file, log and PID
// never touch the machine running the tests. internal/homedir reads $HOME
// first precisely so this works.
func homeIn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func armForTest(t *testing.T, after time.Duration) *Deadman {
	t.Helper()
	d, err := Arm(ArmSpec{
		After:           after,
		ExitNode:        "aw-baremetal",
		TailscalePath:   "/bin/true",
		ExclusionRevert: "/bin/false rule del priority 5260",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Disarm() })
	return d
}

// The switch has to be a real, running, detached process — not a timer inside
// this one. Everything about the design assumes it survives the thing that
// armed it being killed.
func TestArmStartsADetachedProcessInItsOwnSession(t *testing.T) {
	homeIn(t)
	d := armForTest(t, time.Minute)
	if d.PID <= 0 {
		t.Fatalf("pid = %d", d.PID)
	}
	if !processIsDeadman(d.PID) {
		t.Fatal("the armed process must be identifiable by its marker, or a disarm could kill a stranger after PID reuse")
	}
	// setsid is the point: a new session means a new process group led by the
	// child, so its pgid equals its pid. If it had merely been forked, the
	// pgid would still be this test binary's.
	pgid, err := syscall.Getpgid(d.PID)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != d.PID {
		t.Fatalf("pgid = %d, pid = %d — the switch is not in its own session and would die with whatever armed it", pgid, d.PID)
	}
	if pgid == syscall.Getpgrp() {
		t.Fatal("the switch shares this process's group and would be killed along with it")
	}
}

func TestArmRecordsTheSwitchWhereStatusCanFindIt(t *testing.T) {
	home := homeIn(t)
	d := armForTest(t, 90*time.Second)

	path := filepath.Join(home, ".aw-remote-host", "vpn-deadman.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("an unrecorded switch cannot be stood down: %v", err)
	}
	loaded, err := LoadDeadman()
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.PID != d.PID || loaded.ExitNode != "aw-baremetal" {
		t.Fatalf("loaded = %+v", loaded)
	}
	expiry, err := time.Parse(time.RFC3339, loaded.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(expiry) <= 0 {
		t.Fatalf("expiry %s is not in the future", loaded.ExpiresAt)
	}
	if loaded.Fired() {
		t.Fatal("a freshly armed switch has not fired")
	}
	if !strings.Contains(loaded.Describe(), "ARMED") {
		t.Fatalf("describe = %q", loaded.Describe())
	}
}

func TestDisarmKillsTheProcessGroupAndForgetsIt(t *testing.T) {
	homeIn(t)
	d := armForTest(t, time.Minute)

	stood, err := Disarm()
	if err != nil {
		t.Fatal(err)
	}
	if !stood {
		t.Fatal("Disarm should report that there was something to stand down")
	}
	// Killing -pid takes the sh AND the sleep it is blocked in; leaving the
	// sleep behind would mean the revert still fires.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processIsDeadman(d.PID) {
		time.Sleep(20 * time.Millisecond)
	}
	if processIsDeadman(d.PID) {
		t.Fatal("the armed process is still alive after Disarm")
	}
	loaded, err := LoadDeadman()
	if err != nil {
		t.Fatal(err)
	}
	if loaded != nil {
		t.Fatalf("the record should be gone, got %+v", loaded)
	}
}

func TestDisarmIsSafeWhenNothingIsArmed(t *testing.T) {
	homeIn(t)
	stood, err := Disarm()
	if err != nil {
		t.Fatal(err)
	}
	if stood {
		t.Fatal("nothing was armed")
	}
}

// PIDs are reused. A disarm that killed whatever now holds the recorded PID
// would be a worse bug than the one this file exists to prevent, so the
// marker is checked before any signal is sent.
func TestDisarmWillNotKillAStrangerHoldingAReusedPID(t *testing.T) {
	homeIn(t)
	if err := saveDeadman(&Deadman{
		PID:       os.Getpid(), // this test binary, which carries no marker
		ArmedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	stood, err := Disarm()
	if err != nil {
		t.Fatal(err)
	}
	if stood {
		t.Fatal("Disarm claimed to have killed a process that is not one of ours — and this test is still running, so it did not")
	}
}

// Arming twice must not leave two switches racing: the second would inherit
// nothing from the first, so the first would fire under a selection the
// second legitimately confirmed.
func TestArmStandsDownAPreviouslyArmedSwitch(t *testing.T) {
	homeIn(t)
	first := armForTest(t, time.Minute)
	second := armForTest(t, time.Minute)
	if first.PID == second.PID {
		t.Fatal("the two arms returned the same pid")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processIsDeadman(first.PID) {
		time.Sleep(20 * time.Millisecond)
	}
	if processIsDeadman(first.PID) {
		t.Fatal("the first switch is still armed and would revert the second selection")
	}
}

// The end-to-end property, on a two-second fuse: nothing stands it down, so
// it fires and runs the revert. /bin/echo stands in for tailscale so the test
// can assert on what the revert actually executed.
func TestAnUnattendedSwitchActuallyFires(t *testing.T) {
	home := homeIn(t)
	if _, err := Arm(ArmSpec{
		After:           2 * time.Second,
		ExitNode:        "aw-baremetal",
		TailscalePath:   "/bin/echo TAILSCALE",
		ExclusionRevert: "/bin/false rule del priority 5260",
	}); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(home, ".aw-remote-host", "vpn-deadman.log")
	deadline := time.Now().Add(15 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err == nil {
			body = string(data)
			if strings.Contains(body, "revert complete") {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(body, "FIRED") {
		t.Fatalf("the switch did not fire; log:\n%s", body)
	}
	// A switch that fires silently would reproduce the accident this feature
	// defends against — two days of no internet with nobody alerted.
	if !strings.Contains(body, "aw-baremetal") {
		t.Fatalf("the log must name what it reverted; got:\n%s", body)
	}
	if !strings.Contains(body, "TAILSCALE set --exit-node=") {
		t.Fatalf("the revert must clear the exit node; got:\n%s", body)
	}
	if !strings.Contains(body, "revert complete") {
		t.Fatalf("got:\n%s", body)
	}
}

// The revert cannot depend on this binary. An update, a rename or a partial
// write of aw-remote-host must not be able to take the escape hatch with it.
func TestRevertScriptShellsOutToTailscaleDirectly(t *testing.T) {
	script := ArmSpec{
		After: 120 * time.Second, ExitNode: "aw-baremetal",
		TailscalePath: "/usr/bin/tailscale", ExclusionRevert: "while /usr/sbin/ip rule del priority 5260 2>/dev/null; do :; done",
	}.revertScript()

	if strings.Contains(script, "aw-remote-host ") {
		t.Fatalf("the revert must not re-enter this binary:\n%s", script)
	}
	for _, want := range []string{
		"sleep 120",
		"/usr/bin/tailscale set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false",
		"/usr/sbin/ip rule del priority 5260",
		deadmanMarker,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%q missing from:\n%s", want, script)
		}
	}
}

func TestArmRefusesWithoutAbsolutePathsOrATimeout(t *testing.T) {
	homeIn(t)
	if _, err := Arm(ArmSpec{After: 0, TailscalePath: "/bin/true"}); err == nil {
		t.Fatal("a switch with no timeout is not a switch")
	}
	// Resolved before the route is touched, because a machine whose network
	// has just broken is the worst place to discover a binary is not on PATH.
	if _, err := Arm(ArmSpec{After: time.Minute, TailscalePath: ""}); err == nil {
		t.Fatal("expected a refusal without an absolute tailscale path")
	}
}

// The race that made TestArmRecordsTheSwitchWhereStatusCanFindIt flaky in CI
// (run 32950183747), asserted directly and repeatedly.
//
// A single arm/check pass is exactly what was already there, and it passed on
// a re-run — the window between fork and exec is microseconds wide, so one
// sample proves almost nothing. Repeating it is what turns "usually true" into
// evidence, and it is cheap: each switch is killed immediately.
//
// What must hold after Arm returns is not "a process exists" but "the process
// can be RECOGNISED as this switch". Disarm and Fired are both built on that,
// and the second one is the dangerous reader: an unrecognised switch makes
// `status` announce a revert that never happened.
func TestArmReturnsOnlyOnceTheSwitchIsIdentifiable(t *testing.T) {
	homeIn(t)
	for i := 0; i < 25; i++ {
		d, err := Arm(ArmSpec{
			After:           90 * time.Second,
			ExitNode:        "aw-baremetal",
			TailscalePath:   "/bin/true",
			ExclusionRevert: "/bin/false rule del priority 5260",
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !processIsDeadman(d.PID) {
			t.Fatalf("iteration %d: Arm returned before pid %d was identifiable — Disarm would refuse to kill it and Fired() would call it dead", i, d.PID)
		}
		if d.Fired() {
			t.Fatalf("iteration %d: a freshly armed switch has not fired", i)
		}
		if _, err := Disarm(); err != nil {
			t.Fatalf("iteration %d: disarm: %v", i, err)
		}
	}
}

// The refusal half. A host whose armed process can never be identified must
// stop the sequence rather than let it move a route it cannot put back — so
// the failure has to come out of Arm as an error, not as a warning next to a
// usable Deadman.
func TestArmRefusesWhenTheSwitchNeverBecomesIdentifiable(t *testing.T) {
	homeIn(t)
	prev := processIsDeadman
	processIsDeadman = func(int) bool { return false }
	t.Cleanup(func() { processIsDeadman = prev })

	d, err := Arm(ArmSpec{After: 90 * time.Second, TailscalePath: "/bin/true"})
	if err == nil {
		t.Fatal("a switch nothing can identify cannot be stood down, and must not be reported as armed")
	}
	if d != nil {
		t.Fatalf("no Deadman may be handed back on that path: %+v", d)
	}
	if !strings.Contains(err.Error(), "stand it down") {
		t.Fatalf("the error must say what the consequence is: %q", err)
	}
}
