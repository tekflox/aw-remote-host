package vpn

import (
	"context"
	"fmt"
	"strings"
)

// The boot guard.
//
// `tailscale set --exit-node=X` writes a PREFERENCE, and preferences survive
// a reboot. The route exclusions this package installs on Linux do not — `ip
// rule` is runtime state and the kernel comes up with none of it. So a
// machine that reboots while an exit gate is in force comes back with its
// default route on the tunnel and NOTHING holding the control plane outside
// it. That is not a degraded version of the feature; it is the lockout,
// arriving on its own, after the operator has stopped watching.
//
// So the selection is deliberately made non-persistent: a oneshot unit clears
// it at every boot, which restores the escape hatch that
// tools/host-firewall/aw-firewall-apply.sh established as this repo's
// precedent — the firewall does not persist across a reboot on purpose, so
// that a reboot is always the way out. --persist-across-reboot opts out for
// an operator who has decided otherwise, and `status` says which of the two
// is in force rather than leaving it to be discovered.
//
// macOS reaches the same guarantee through a different object and for a
// partly different reason — see launchdBootGuardLabel in usexit_platform.go.
// Which of the two a host uses is the platform's answer, not this file's.

const (
	// systemdBootGuardUnit is the unit that clears the exit-node selection on
	// boot. Linux only; darwin's counterpart is a LaunchAgent.
	systemdBootGuardUnit = "aw-vpn-exit-clear.service"
	systemdBootGuardPath = "/etc/systemd/system/" + systemdBootGuardUnit
)

// BootGuardName is what to call this host's boot guard in a message.
func BootGuardName() string { return currentPlatform().bootGuardName() }

// BootGuardInstalled reports whether this host's boot guard is in place.
func BootGuardInstalled() bool { return currentPlatform().bootGuardInstalled() }

// bootGuardUnit is the unit file. Both ExecStart lines are prefixed with `-`
// so a failure is ignored: this runs on every boot, including the vast
// majority where no exit node was ever selected, and a unit that goes red
// because there was nothing to clear trains people to ignore it.
func bootGuardUnit(tailscalePath, ipPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Clear any aw-remote-host exit-node selection left over from before a reboot
Documentation=https://github.com/tekflox/aw-remote-host/blob/main/bootstrap/vpn/README.md
After=tailscaled.service
Wants=tailscaled.service

[Service]
Type=oneshot
RemainAfterExit=yes
# An exit-node selection survives a reboot because it is a tailscale
# preference. The route exclusions that keep the control plane reachable do
# NOT survive, because ip rules are runtime state. Coming back up with the
# first and without the second is exactly how a host is stranded, so the
# selection is cleared and has to be made again deliberately.
ExecStart=-%s set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false
ExecStart=-/bin/sh -c 'while %s rule del priority %d 2>/dev/null; do :; done; exit 0'

[Install]
WantedBy=multi-user.target
`, tailscalePath, ipPath, exclusionPriority)
}

// installSystemdBootGuard writes and enables the unit. Idempotent.
//
// The unit file is written through the Runner rather than with os.WriteFile
// so that the caller's privilege wrapper applies: aw-remote-host does not
// always run as root (internal/lanfastpath's DefaultPort comment is the
// standing reminder), and on a passwordless-sudo host every other privileged
// step here goes through the same wrapper.
func installSystemdBootGuard(ctx context.Context, r Runner, tailscalePath, ipPath string) error {
	script := fmt.Sprintf("cat > %s <<'AW_VPN_UNIT_EOF'\n%sAW_VPN_UNIT_EOF\n", systemdBootGuardPath, bootGuardUnit(tailscalePath, ipPath))
	if out, err := r.Run(ctx, "sh", "-c", script); err != nil {
		return fmt.Errorf("write %s: %w: %s", systemdBootGuardPath, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "systemctl", "enable", systemdBootGuardUnit); err != nil {
		return fmt.Errorf("systemctl enable %s: %w: %s", systemdBootGuardUnit, err, strings.TrimSpace(out))
	}
	return nil
}

// removeSystemdBootGuard disables and deletes the unit. Idempotent, and quiet
// about a unit that was never there.
func removeSystemdBootGuard(ctx context.Context, r Runner) error {
	if !fileExists(systemdBootGuardPath) {
		return nil
	}
	if out, err := r.Run(ctx, "systemctl", "disable", systemdBootGuardUnit); err != nil {
		return fmt.Errorf("systemctl disable %s: %w: %s", systemdBootGuardUnit, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "rm", "-f", systemdBootGuardPath); err != nil {
		return fmt.Errorf("remove %s: %w: %s", systemdBootGuardPath, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}
