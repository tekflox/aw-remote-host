package vpn

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// The boot guard.
//
// `tailscale set --exit-node=X` writes a PREFERENCE, and preferences survive
// a reboot. The route exclusions this package installs do not — `ip rule` is
// runtime state and the kernel comes up with none of it. So a machine that
// reboots while an exit gate is in force comes back with its default route on
// the tunnel and NOTHING holding the control plane outside it. That is not a
// degraded version of the feature; it is the lockout, arriving on its own,
// after the operator has stopped watching.
//
// So the selection is deliberately made non-persistent: a oneshot unit clears
// it at every boot, which restores the escape hatch that
// tools/host-firewall/aw-firewall-apply.sh established as this repo's
// precedent — the firewall does not persist across a reboot on purpose, so
// that a reboot is always the way out. --persist-across-reboot opts out for
// an operator who has decided otherwise, and `status` says which of the two
// is in force rather than leaving it to be discovered.

const (
	// BootGuardUnit is the systemd unit that clears the exit-node selection
	// on boot.
	BootGuardUnit = "aw-vpn-exit-clear.service"
	bootGuardPath = "/etc/systemd/system/" + BootGuardUnit
)

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

// InstallBootGuard writes and enables the unit. Idempotent.
//
// The unit file is written through the Runner rather than with os.WriteFile
// so that the caller's privilege wrapper applies: aw-remote-host does not
// always run as root (internal/lanfastpath's DefaultPort comment is the
// standing reminder), and on a passwordless-sudo host every other privileged
// step here goes through the same wrapper.
func InstallBootGuard(ctx context.Context, r Runner, tailscalePath, ipPath string) error {
	script := fmt.Sprintf("cat > %s <<'AW_VPN_UNIT_EOF'\n%sAW_VPN_UNIT_EOF\n", bootGuardPath, bootGuardUnit(tailscalePath, ipPath))
	if out, err := r.Run(ctx, "sh", "-c", script); err != nil {
		return fmt.Errorf("write %s: %w: %s", bootGuardPath, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "systemctl", "enable", BootGuardUnit); err != nil {
		return fmt.Errorf("systemctl enable %s: %w: %s", BootGuardUnit, err, strings.TrimSpace(out))
	}
	return nil
}

// RemoveBootGuard disables and deletes the unit. Idempotent, and quiet about
// a unit that was never there.
func RemoveBootGuard(ctx context.Context, r Runner) error {
	if !BootGuardInstalled() {
		return nil
	}
	if out, err := r.Run(ctx, "systemctl", "disable", BootGuardUnit); err != nil {
		return fmt.Errorf("systemctl disable %s: %w: %s", BootGuardUnit, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "rm", "-f", bootGuardPath); err != nil {
		return fmt.Errorf("remove %s: %w: %s", bootGuardPath, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// BootGuardInstalled reports whether the unit file exists.
func BootGuardInstalled() bool {
	info, err := os.Stat(bootGuardPath)
	return err == nil && !info.IsDir()
}
