package servicemgr

import (
	"fmt"
	"os"
	"path/filepath"
)

const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>bootstrap-workspace</string>
		<string>--control-plane</string>
		<string>%s</string>
		<string>--yes</string>
		<string>--foreground</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`

type launchdManager struct{}

func (m *launchdManager) Name() string { return "launchd" }

func launchdSlugOrUnknown(slug string) string {
	if slug == "" {
		return "unknown"
	}
	return slug
}

// launchdLabel is the LaunchAgent Label AND the plist filename stem —
// scoped by workspace slug (unlike the systemd unit) since a Mac could in
// principle bootstrap more than one workspace-host link.
func launchdLabel(slug string) string {
	return "com.tekflox.aw-remote-host." + launchdSlugOrUnknown(slug)
}

// GenerateLaunchdPlist renders the LaunchAgent plist content — split out
// from Install so tests can assert on it without touching the filesystem
// or shelling out to launchctl.
func GenerateLaunchdPlist(cfg Config) (string, error) {
	logPath, err := launchdLogPath(cfg.Slug)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(launchdPlistTemplate, launchdLabel(cfg.Slug), cfg.ExePath, cfg.ControlPlane, logPath, logPath), nil
}

func launchdLogPath(slug string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Logs", "aw-remote-host."+launchdSlugOrUnknown(slug)+".log"), nil
}

func (m *launchdManager) Path(cfg Config) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel(cfg.Slug)+".plist"), nil
}

func (m *launchdManager) Install(cfg Config) (string, error) {
	path, err := m.Path(cfg)
	if err != nil {
		return "", err
	}
	content, err := GenerateLaunchdPlist(cfg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	logPath, err := launchdLogPath(cfg.Slug)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(logPath), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// guiTarget returns the launchctl gui/<uid> domain (Start) or
// gui/<uid>/<label> service target (Stop) — os.Getuid works on both Linux
// and Darwin, so this needs no build tag even though launchctl itself
// only exists on macOS.
func guiDomain() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func (m *launchdManager) Start(cfg Config) error {
	path, err := m.Path(cfg)
	if err != nil {
		return err
	}
	// launchctl bootstrap is the modern (10.11+) way to load a LaunchAgent
	// into the user's GUI domain; fall back to the legacy `load -w` for
	// older macOS or if it's already bootstrapped under a different name.
	if err := runCmd("launchctl", "bootstrap", guiDomain(), path); err != nil {
		if err2 := runCmd("launchctl", "load", "-w", path); err2 != nil {
			return fmt.Errorf("launchctl bootstrap failed (%v); launchctl load also failed (%v)", err, err2)
		}
	}
	return nil
}

func (m *launchdManager) Stop(cfg Config) error {
	path, err := m.Path(cfg)
	if err != nil {
		return err
	}
	target := guiDomain() + "/" + launchdLabel(cfg.Slug)
	if err := runCmd("launchctl", "bootout", target); err != nil {
		_ = runCmd("launchctl", "unload", path) // best-effort legacy fallback
	}
	return nil
}

func (m *launchdManager) Uninstall(cfg Config) (string, error) {
	_ = m.Stop(cfg) // best-effort
	path, err := m.Path(cfg)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove %s: %w", path, err)
	}
	return path, nil
}
