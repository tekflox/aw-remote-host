package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const systemdUnitTemplate = `[Unit]
Description=aw-remote-host — Agentic Workspace BYOD workspace-host link
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s bootstrap-workspace --control-plane %s --yes
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`

// systemdUnitPath returns ~/.config/systemd/user/aw-remote-host.service.
func systemdUnitPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", "aw-remote-host.service"), nil
}

// writeSystemdUnit generates the user systemd unit that keeps
// `bootstrap-workspace` running (and thus the /link connection alive)
// across logout/reboot once paired with `loginctl enable-linger $USER`.
// Re-running bootstrap-workspace after the first link is safe: every
// module's own detect step makes it a no-op, and the CLI already has a
// stored awlk_ credential so no --token is needed.
func writeSystemdUnit(controlPlane string) error {
	unitPath, err := systemdUnitPath()
	if err != nil {
		return err
	}
	exePath, err := exec.LookPath(os.Args[0])
	if err != nil {
		exePath, err = filepath.Abs(os.Args[0])
		if err != nil {
			exePath = os.Args[0]
		}
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(unitPath), err)
	}
	content := fmt.Sprintf(systemdUnitTemplate, exePath, controlPlane)
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	return nil
}
