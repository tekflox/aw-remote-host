// Package updater coordinates aw-remote-host self-update rollback.
package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultValidationTimeout = 300 * time.Second
	pendingFileName          = "pending.json"
	backupFileName           = "aw-remote-host.previous"
)

// Pending records a self-update that must be confirmed by a later successful
// /link registration. If the marker survives past the validation timeout, the
// rollback monitor restores BackupPath over CurrentPath and restarts service.
type Pending struct {
	Version     string  `json:"version"`
	CurrentPath string  `json:"current_path"`
	BackupPath  string  `json:"backup_path"`
	Slug        string  `json:"slug,omitempty"`
	CreatedAt   float64 `json:"created_at"`
}

func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "self-update"), nil
}

func PendingPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, pendingFileName), nil
}

func Prepare(currentPath, version, slug string) (*Pending, error) {
	currentPath = strings.TrimSpace(currentPath)
	version = strings.TrimSpace(version)
	if currentPath == "" {
		return nil, fmt.Errorf("current binary path is required")
	}
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	backupPath := filepath.Join(dir, backupFileName)
	if err := copyFile(currentPath, backupPath, 0o755); err != nil {
		return nil, fmt.Errorf("backup current binary: %w", err)
	}
	p := &Pending{
		Version:     version,
		CurrentPath: currentPath,
		BackupPath:  backupPath,
		Slug:        strings.TrimSpace(slug),
		CreatedAt:   float64(time.Now().UnixNano()) / 1e9,
	}
	if err := savePending(p); err != nil {
		return nil, err
	}
	return p, nil
}

func ClearPending() error {
	path, err := PendingPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func StartRollbackMonitor(p *Pending, timeout time.Duration) error {
	if os.Getenv("AW_REMOTE_HOST_SKIP_ROLLBACK_MONITOR") == "1" {
		return nil
	}
	if timeout <= 0 {
		timeout = DefaultValidationTimeout
	}
	pendingPath, err := PendingPath()
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(
		"sleep %d; if test -f %s; then cp %s %s && chmod 755 %s && %s; fi",
		int(timeout.Seconds()),
		shellQuote(pendingPath),
		shellQuote(p.BackupPath),
		shellQuote(p.CurrentPath),
		shellQuote(p.CurrentPath),
		restartCommand(p.Slug),
	)
	return exec.Command("sh", "-c", cmd).Start()
}

func InstallDirFor(currentPath string) string {
	if dir := strings.TrimSpace(os.Getenv("AW_REMOTE_HOST_INSTALL_DIR")); dir != "" {
		return dir
	}
	if currentPath != "" {
		return filepath.Dir(currentPath)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "bin")
}

func RestartCommand(slug string) string {
	return restartCommand(slug)
}

func ShellQuote(value string) string {
	return shellQuote(value)
}

func savePending(p *Pending) error {
	path, err := PendingPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending update: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func restartCommand(slug string) string {
	switch runtime.GOOS {
	case "darwin":
		label := "com.tekflox.aw-remote-host"
		if strings.TrimSpace(slug) != "" {
			label += "." + strings.TrimSpace(slug)
		}
		return fmt.Sprintf("launchctl kickstart -k gui/$(id -u)/%s", shellQuote(label))
	case "linux":
		// A normal rootless BYOD host has this installed as a systemd --user
		// service (Restart=always — see servicemgr/systemd.go), so the
		// restart lands there directly. But a --foreground run (this
		// process's own default, and how the aw-remote-host Docker image
		// runs it: a shell entrypoint loop, not systemd as init) never
		// installs that unit, so `systemctl --user restart` always fails —
		// silently, since the caller only Start()s this command and never
		// checks its exit code. Chaining a self-kill fallback means this
		// process exits either way and whatever actually supervises it
		// (systemd's Restart=always, or the shell loop) brings the new
		// binary up — instead of the restart being a silent no-op that
		// leaves the OLD binary running until the rollback monitor undoes
		// the update 75s later.
		return "systemctl --user restart aw-remote-host || kill $PPID"
	case "windows":
		// Unreachable in practice — ops.Dispatch refuses "self-update" on
		// Windows before it can get here (the rollback monitor below is a
		// `sh -c` script, and there is no sh). Spelled out anyway so that
		// if self-update is ever ported, the restart half is already
		// correct rather than a silent "true" that no-ops the new binary
		// into never running.
		return "schtasks /End /TN aw-remote-host & schtasks /Run /TN aw-remote-host"
	default:
		return "true"
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
