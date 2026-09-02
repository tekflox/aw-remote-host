package vpn

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

// The dead-man's switch.
//
// It belongs to the TOOL, not to the caller. `use-exit` arms it BEFORE
// touching a route and stands it down only once egress has been confirmed
// through the new one — so every path that can go wrong in between (a gate
// that does not forward, a confirmation that hangs, this process being
// killed, the machine's operator closing the laptop) ends with the route
// coming back on its own. Leaving that ordering to whoever calls the command
// is how it ends up not happening: the caller most likely to strand a machine
// is a control plane that never sees the reply.
//
// The mechanism is the one that was proven by hand on 2026-08-25:
//
//	setsid nohup sh -c 'sleep 120; tailscale set --exit-node=' &
//
// The detail that matters is setsid. The revert has to outlive the session
// that armed it — an SSH connection that dies, a systemd unit that restarts,
// a PTY the control plane closes. Go gets the same thing from
// SysProcAttr.Setsid, which puts the child in a brand-new session and process
// group with no controlling terminal, without depending on a setsid binary
// being installed. The new process group is also what makes disarming exact:
// killing -pgid takes the sh and its sleep together.

// deadmanMarker is embedded in the armed process's command line so a stale
// PID can never be mistaken for the switch. PIDs are reused; a disarm that
// killed whatever now holds the recorded PID would be a far worse bug than
// the one this file exists to prevent.
const deadmanMarker = "aw-vpn-deadman"

const (
	// deadmanVisibleTimeout / deadmanVisiblePoll bound how long Arm waits for
	// the switch it just started to become identifiable. Generous against the
	// race it closes (a fork-to-exec window measured in microseconds) and
	// still short enough that a host where the marker never appears is
	// refused promptly rather than hanging a command that has not yet touched
	// the route.
	deadmanVisibleTimeout = 3 * time.Second
	deadmanVisiblePoll    = 5 * time.Millisecond
)

// Deadman is the record of an armed switch, written to disk so that a later
// invocation — or `status`, or a human — can see that a revert is pending and
// when it will fire.
type Deadman struct {
	PID       int    `json:"pid"`
	ArmedAt   string `json:"armed_at"`
	ExpiresAt string `json:"expires_at"`
	ExitNode  string `json:"exit_node,omitempty"`
	LogPath   string `json:"log_path,omitempty"`
}

// DeadmanPath returns ~/.aw-remote-host/vpn-deadman.json.
func DeadmanPath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "vpn-deadman.json"), nil
}

// DeadmanLogPath returns ~/.aw-remote-host/vpn-deadman.log.
//
// A switch that fires silently would reproduce the exact accident this
// feature is defending against — the container that lost the internet for two
// days with no alarm. The revert writes what it did and when, so the evidence
// outlives the process.
func DeadmanLogPath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "vpn-deadman.log"), nil
}

// ArmSpec is what a switch needs to know to undo a switch it never saw made.
type ArmSpec struct {
	// After is how long to wait before reverting. The proven value is 120s.
	After time.Duration
	// ExitNode is only recorded for reporting.
	ExitNode string
	// TailscalePath is an absolute path resolved at arming time. Resolved,
	// not looked up later, because the revert runs in a shell with whatever
	// PATH it inherits — and on a machine whose network is broken is the
	// worst possible moment to discover a binary is not where it was assumed
	// to be.
	//
	// Empty is legitimate for a selection that has no mesh selection to clear
	// — the external-tunnel path (externalroute.go) moves ONE container with
	// an `ip rule` and never calls `tailscale set`, so there is no binary for
	// it to resolve. Arm requires that such a spec supply ExclusionRevert
	// instead, because a switch that would run nothing is worse than no switch:
	// it reports a guarantee it does not provide.
	TailscalePath string
	// ExclusionRevert is the platform's extra shell for undoing whatever it
	// pinned outside the tunnel, with every path already absolute and every
	// privilege prefix already applied (exitPlatform.revertExclusionsScript).
	//
	// Empty is a legitimate value and means there is nothing to undo — the
	// macOS case, where tailscaled owns the routing and this module installs
	// none. It is deliberately NOT a required field: making it one would have
	// forced darwin to supply a no-op command, i.e. a line of shell that can
	// fail on a machine whose network has just gone.
	ExclusionRevert string
}

// revertScript is the shell the armed process runs. It is deliberately three
// lines of POSIX sh and nothing else: it has to work on a machine that has
// just lost its default route, so it cannot fetch, resolve, or re-exec this
// binary. In particular it does NOT call `aw-remote-host` — a self-referential
// revert dies with any update, rename, or partial write of the very tool that
// armed it.
func (s ArmSpec) revertScript() string {
	exclusions := strings.TrimSpace(s.ExclusionRevert)
	if exclusions == "" {
		exclusions = "# nothing to unpin on this platform"
	}
	// The mesh line is omitted rather than emitted with an empty path when
	// there is no selection to clear. A bare ` set --exit-node=` would run
	// whatever the shell resolved first, on a machine whose network has just
	// gone — the one moment where a surprising binary is least affordable.
	clearSelection := "# no mesh selection to clear on this path"
	if s.TailscalePath != "" {
		clearSelection = s.TailscalePath + " set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false"
	}
	return fmt.Sprintf(`# %s
sleep %d
echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) dead-man's switch FIRED: reverting selection (%s) that was never confirmed"
%s
%s
echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) dead-man's switch: revert complete"
`,
		deadmanMarker,
		int(s.After.Seconds()),
		s.ExitNode,
		clearSelection,
		exclusions,
	)
}

// Arm starts the detached revert and records it.
//
// Any switch already armed is stood down first: two overlapping switches
// would mean a second use-exit inheriting the first one's deadline, and a
// revert firing under a selection that was legitimately confirmed.
func Arm(spec ArmSpec) (*Deadman, error) {
	if spec.After <= 0 {
		return nil, errors.New("dead-man's switch needs a positive timeout")
	}
	// One of the two has to do something. A spec with neither would arm a
	// switch whose whole body is comments — the worst possible outcome,
	// because every layer above reports "ARMED" and none of them would be
	// wrong about anything except the part that matters.
	if spec.TailscalePath == "" && strings.TrimSpace(spec.ExclusionRevert) == "" {
		return nil, errors.New("dead-man's switch needs either an absolute path for tailscale or an explicit revert to run, resolved before the route is touched — a switch with nothing to run would report a guarantee it does not provide")
	}
	if _, err := Disarm(); err != nil {
		return nil, fmt.Errorf("stand down the previously armed switch: %w", err)
	}

	logPath, err := DeadmanLogPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(logPath), err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", logPath, err)
	}
	defer logFile.Close()

	cmd := exec.Command("sh", "-c", spec.revertScript())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Detached into its own session — see the file header. Without that the
	// revert dies with the session that armed it, which is precisely the
	// session most likely to be killed by the route change it is guarding.
	if err := startDetached(cmd); err != nil {
		return nil, fmt.Errorf("arm dead-man's switch: %w", err)
	}
	// Do not return until the switch is IDENTIFIABLE, not merely started.
	//
	// cmd.Start() returns once the child has been forked, which can be before
	// it has exec'd the shell — and in that window the child's command line is
	// still this process's own, so processIsDeadman answers false about a
	// switch that is alive and about to arm. Both readers of that predicate
	// then get the wrong answer, in opposite and equally unacceptable
	// directions: Disarm() declines to kill a switch it cannot identify,
	// leaving a revert to fire under a selection that was legitimately
	// confirmed; and Deadman.Fired() reports that a revert ALREADY HAPPENED
	// with nobody watching — this package inventing the exact alarming event
	// it exists to report honestly.
	//
	// Found as a flaky CI failure (run 32950183747,
	// TestArmRecordsTheSwitchWhereStatusCanFindIt: "a freshly armed switch has
	// not fired") that passed on an unchanged re-run, which is the signature
	// of a narrow race rather than a broken read.
	//
	// Waiting HERE is the fix, rather than retrying in the reader, because
	// this is the only moment at which "not yet visible" is knowably different
	// from "gone". Everywhere later the two are indistinguishable, and a
	// reader that retried would be guessing.
	if err := awaitDeadmanVisible(cmd.Process.Pid); err != nil {
		_ = killGroup(cmd.Process.Pid)
		return nil, err
	}
	// Deliberately never Wait()ed: this process is expected to outlive the
	// command that started it. It is reaped by init once we exit.
	now := time.Now().UTC()
	d := &Deadman{
		PID:       cmd.Process.Pid,
		ArmedAt:   now.Format(time.RFC3339),
		ExpiresAt: now.Add(spec.After).Format(time.RFC3339),
		ExitNode:  spec.ExitNode,
		LogPath:   logPath,
	}
	if err := saveDeadman(d); err != nil {
		// Kill it rather than leave a revert running that nothing knows how
		// to stand down — an unrecorded switch would fire under a confirmed,
		// working selection.
		_ = killGroup(d.PID)
		return nil, err
	}
	return d, nil
}

// awaitDeadmanVisible blocks until the just-started switch's own command line
// carries the marker, or gives up.
//
// Giving up is a REFUSAL, not a warning, and Arm propagates it: UseExit does
// not touch the default route when arming fails. A switch that nothing can
// identify is a switch that nothing can stand down, so it would fire under a
// working selection — strictly worse than never having armed one. Failing in
// that direction is the whole bargain this file is built on.
func awaitDeadmanVisible(pid int) error {
	deadline := time.Now().Add(deadmanVisibleTimeout)
	for {
		if processIsDeadman(pid) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("started a dead-man's switch (pid %d) but its command line never carried the %q marker within %s, so nothing could identify it later to stand it down — refusing to rely on a switch that cannot be disarmed", pid, deadmanMarker, deadmanVisibleTimeout)
		}
		time.Sleep(deadmanVisiblePoll)
	}
}

// LoadDeadman reads the recorded switch, returning nil when none is armed.
func LoadDeadman() (*Deadman, error) {
	path, err := DeadmanPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var d Deadman
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &d, nil
}

func saveDeadman(d *Deadman) error {
	path, err := DeadmanPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Disarm stands down an armed switch and reports whether there was one.
//
// It is safe to call when nothing is armed, when the switch has already
// fired, and when the recorded PID has been reused by something unrelated —
// the marker check is what makes the last one safe.
func Disarm() (bool, error) {
	d, err := LoadDeadman()
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, nil
	}
	path, err := DeadmanPath()
	if err != nil {
		return false, err
	}
	killed := false
	if d.PID > 0 && processIsDeadman(d.PID) {
		// The process GROUP, not the process: the child leads its own group,
		// so this takes the sh and the sleep it is blocked in together.
		if err := killGroup(d.PID); err != nil {
			return false, fmt.Errorf("stand down dead-man's switch (pid %d): %w", d.PID, err)
		}
		killed = true
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return killed, fmt.Errorf("remove %s: %w", path, err)
	}
	return killed, nil
}

// processIsDeadman checks that the PID still belongs to a switch this package
// armed, by looking for the marker in its command line. When the command line
// cannot be read at all this answers false, which fails in the safe
// direction: the switch is left to fire rather than a stranger's process
// being killed.
//
// macOS has no /proc, and answering false there was not a safe degradation —
// it was a bug with the failure mode reversed. Disarm() only kills a process
// it can identify, so on a Mac EVERY switch would have survived being stood
// down and fired minutes later under a selection that had been confirmed,
// reverting a working gate with nobody watching. `ps -o command=` is the
// portable read of the same fact.
var processIsDeadman = func(pid int) bool {
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		return strings.Contains(string(data), deadmanMarker)
	}
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), deadmanMarker)
}

// Pending reports an armed switch that has not fired yet, for `status`.
// A switch whose deadline has passed is reported too, with Fired true: it
// means a revert happened that nobody watched, and that is the single most
// important line this command can print.
func (d *Deadman) Fired() bool {
	if d == nil {
		return false
	}
	expiry, err := time.Parse(time.RFC3339, d.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(expiry) || !processIsDeadman(d.PID)
}

// Describe renders an armed switch for a status line.
func (d *Deadman) Describe() string {
	if d == nil {
		return ""
	}
	if d.Fired() {
		return fmt.Sprintf("a dead-man's switch armed at %s for exit node %s has already fired or died — this host's exit-node selection was reverted automatically and NOT by anyone watching. See %s",
			d.ArmedAt, orNone(d.ExitNode), d.LogPath)
	}
	return fmt.Sprintf("a dead-man's switch is ARMED (pid %d): unless it is stood down, the exit-node selection reverts automatically at %s",
		d.PID, d.ExpiresAt)
}
