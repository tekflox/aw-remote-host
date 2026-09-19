package servicemgr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

// systemdUnitName is the DEFAULT instance's user unit name, and it must
// never change: every Linux BYOD host linked before instances existed has
// `aw-remote-host.service` enabled right now, and renaming it would leave
// that unit enabled while the new name is never started.
//
// A named instance is suffixed (see systemdUnit). Before that existed this
// const was used directly by Path/Start/Stop/Uninstall, which ignored their
// Config entirely — so a second `link --background` overwrote the first
// identity's unit file, and an `unlink` of either stopped and removed the
// other's service.
const systemdUnitName = "aw-remote-host"

// systemdUnit is the unit name for cfg's instance — the fixed historical
// name for the default one, `aw-remote-host-<instance>` for a named one.
func systemdUnit(cfg Config) string {
	if cfg.Instance == "" {
		return systemdUnitName
	}
	return systemdUnitName + "-" + cfg.Instance
}

const systemdUnitTemplate = `[Unit]
Description=aw-remote-host — Agentic Workspace BYOD workspace-host link (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s
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
	return fmt.Sprintf(systemdUnitTemplate, slug, cfg.ExePath, strings.Join(serviceArgs(cfg), " "))
}

func (m *systemdManager) Path(cfg Config) (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", systemdUnit(cfg)+".service"), nil
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

func (m *systemdManager) Start(cfg Config) error {
	return runCmd("systemctl", "--user", "enable", "--now", systemdUnit(cfg))
}

func (m *systemdManager) Stop(cfg Config) error {
	_ = runCmd("systemctl", "--user", "stop", systemdUnit(cfg)) // best-effort
	return nil
}

func (m *systemdManager) Uninstall(cfg Config) (string, error) {
	_ = runCmd("systemctl", "--user", "disable", "--now", systemdUnit(cfg)) // best-effort
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
