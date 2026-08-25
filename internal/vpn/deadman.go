package vpn

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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
	// TailscalePath and IPPath are absolute paths resolved at arming time.
	// Resolved, not looked up later, because the revert runs in a shell with
	// whatever PATH it inherits — and on a machine whose network is broken is
	// the worst possible moment to discover a binary is not where it was
	// assumed to be.
	TailscalePath string
	IPPath        string
}

// revertScript is the shell the armed process runs. It is deliberately three
// lines of POSIX sh and nothing else: it has to work on a machine that has
// just lost its default route, so it cannot fetch, resolve, or re-exec this
// binary. In particular it does NOT call `aw-remote-host` — a self-referential
// revert dies with any update, rename, or partial write of the very tool that
// armed it.
func (s ArmSpec) revertScript() string {
	return fmt.Sprintf(`# %s
sleep %d
echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) dead-man's switch FIRED: reverting exit-node selection (%s) that was never confirmed"
%s set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false
while %s rule del priority %d 2>/dev/null; do :; done
echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) dead-man's switch: revert complete"
`,
		deadmanMarker,
		int(s.After.Seconds()),
		s.ExitNode,
		s.TailscalePath,
		s.IPPath,
		exclusionPriority,
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
	if spec.TailscalePath == "" || spec.IPPath == "" {
		return nil, errors.New("dead-man's switch needs absolute paths for tailscale and ip, resolved before the route is touched")
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
	// Setsid is the whole point — see the file header. Without it the revert
	// dies with the session that armed it, which is precisely the session
	// most likely to be killed by the route change it is guarding.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("arm dead-man's switch: %w", err)
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
		_ = syscall.Kill(-d.PID, syscall.SIGKILL)
		return nil, err
	}
	return d, nil
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
		// Negative PID: the process group. Setsid made the child its own
		// group leader, so this takes the sh and the sleep it is blocked in.
		if err := syscall.Kill(-d.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
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
// armed, by looking for the marker in its command line. On anything without
// /proc this answers false, which fails in the safe direction: the switch is
// left to fire rather than a stranger's process being killed.
func processIsDeadman(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), deadmanMarker)
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
