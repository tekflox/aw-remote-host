package vpn

import (
	"context"
	"strings"
	"testing"
)

// The reason the boot guard exists at all, stated as a test so it survives
// somebody deciding it is redundant: a tailscale exit-node selection is a
// PREFERENCE and survives a reboot, while the `ip rule` exclusions that keep
// the control plane reachable are runtime state and do not. A machine that
// came back up with the first and without the second would be exactly the
// lockout this feature is built to prevent, arriving on its own, after
// everyone has stopped watching.
func TestBootGuardUnitClearsBothHalvesOfASelection(t *testing.T) {
	unit := bootGuardUnit("/usr/bin/tailscale", "/usr/sbin/ip")

	if !strings.Contains(unit, "ExecStart=-/usr/bin/tailscale set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false") {
		t.Fatalf("the unit must clear the selection:\n%s", unit)
	}
	if !strings.Contains(unit, "rule del priority 5260") {
		t.Fatalf("the unit must also drop any exclusions that somehow survived:\n%s", unit)
	}
	// Both ExecStarts are `-` prefixed. This runs on every boot, including
	// the overwhelming majority where nothing was ever selected, and a unit
	// that goes red for having nothing to do trains people to ignore it.
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") && !strings.HasPrefix(line, "ExecStart=-") {
			t.Fatalf("ExecStart must tolerate there being nothing to clear: %q", line)
		}
	}
	if !strings.Contains(unit, "After=tailscaled.service") {
		t.Fatalf("clearing a tailscale preference before tailscaled exists does nothing:\n%s", unit)
	}
	if !strings.Contains(unit, "WantedBy=multi-user.target") {
		t.Fatalf("a unit nothing pulls in never runs:\n%s", unit)
	}
}

func TestInstallBootGuardGoesThroughTheRunnerSoSudoApplies(t *testing.T) {
	r := newRecordingRunner()
	if err := installSystemdBootGuard(context.Background(), r, "/usr/bin/tailscale", "/usr/sbin/ip"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 3 {
		t.Fatalf("calls = %v", r.calls)
	}
	// Written through the Runner rather than os.WriteFile: aw-remote-host does
	// not always run as root, and on a passwordless-sudo host every other
	// privileged step here goes through the same wrapper.
	if !strings.HasPrefix(r.calls[0], "sh -c cat > /etc/systemd/system/"+systemdBootGuardUnit) {
		t.Fatalf("first call = %q", r.calls[0])
	}
	if r.calls[1] != "systemctl daemon-reload" {
		t.Fatalf("a unit written but not reloaded is not installed: %q", r.calls[1])
	}
	if r.calls[2] != "systemctl enable "+systemdBootGuardUnit {
		t.Fatalf("a unit installed but not enabled never runs: %q", r.calls[2])
	}
}
