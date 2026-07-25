package servicemgr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemdUnitName is the single, fixed user unit name — unlike launchd,
// this repo doesn't scope it per workspace slug (Linux BYOD hosts are
// expected to run one workspace-host link each).
const systemdUnitName = "aw-remote-host"

const systemdUnitTemplate = `[Unit]
Description=aw-remote-host — Agentic Workspace BYOD workspace-host link (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s bootstrap-workspace --control-plane %s --yes --foreground
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`

type systemdManager struct{}

func (m *systemdManager) Name() string { return "systemd" }

// GenerateSystemdUnit renders the unit file content — split out from
// Install so tests can assert on it without touching the filesystem or
// shelling out to systemctl.
func GenerateSystemdUnit(cfg Config) string {
	slug := cfg.Slug
	if slug == "" {
		slug = "unknown"
	}
	return fmt.Sprintf(systemdUnitTemplate, slug, cfg.ExePath, cfg.ControlPlane)
}

func (m *systemdManager) Path(_ Config) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", systemdUnitName+".service"), nil
}

func (m *systemdManager) Install(cfg Config) (string, error) {
	path, err := m.Path(cfg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(GenerateSystemdUnit(cfg)), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if err := runCmd("systemctl", "--user", "daemon-reload"); err != nil {
		return path, err
	}
	return path, nil
}

func (m *systemdManager) Start(_ Config) error {
	return runCmd("systemctl", "--user", "enable", "--now", systemdUnitName)
}

func (m *systemdManager) Stop(_ Config) error {
	_ = runCmd("systemctl", "--user", "stop", systemdUnitName) // best-effort
	return nil
}

func (m *systemdManager) Uninstall(cfg Config) (string, error) {
	_ = runCmd("systemctl", "--user", "disable", "--now", systemdUnitName) // best-effort
	path, err := m.Path(cfg)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove %s: %w", path, err)
	}
	_ = runCmd("systemctl", "--user", "daemon-reload")
	return path, nil
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
