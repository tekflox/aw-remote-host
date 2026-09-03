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

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

const (
	DefaultValidationTimeout = 300 * time.Second
	pendingFileName          = "pending.json"
	backupFileName           = "aw-remote-host.previous"
)

// The Windows halves of "stop this host's service" and "start it again",
// kept apart because the rollback monitor has to slot the binary restore
// BETWEEN them while restartCommand only ever needs the two glued together.
const (
	windowsTaskName = "aw-remote-host" // servicemgr.schtasksName

	// windowsStopService kills the daemon by image name and gives Windows a
	// beat to release the lock on it.
	//
	// taskkill and NOT `schtasks /End`: Task Scheduler terminates a task's
	// whole process tree, and every caller of this string is a detached
	// child of that tree (the rollback monitor, the post-install restart),
	// so /End would kill the very script that still has work to do.
	// Killing the daemon ends the task instance just as effectively and
	// leaves the script alive.
	//
	// Both image names because the Scheduled Task prefers the windowless
	// aw-remote-hostw.exe when it exists and falls back to the console build
	// when it does not (servicemgr.taskExePath) — killing the one that is
	// not running just prints "process not found" and carries on.
	windowsStopService = "taskkill /F /IM aw-remote-host.exe\n" +
		"taskkill /F /IM aw-remote-hostw.exe\n" +
		"Start-Sleep -Seconds 2"

	// windowsStartService is ignored by Task Scheduler if it still counts
	// the old instance as running (MultipleInstancesPolicy=IgnoreNew) —
	// possible, since the script issuing it is the last member of that
	// instance's job. The task's own RestartOnFailure (PT1M, 999 attempts;
	// see servicemgr/schtasks.go) is what covers that case, a minute after
	// this script exits.
	windowsStartService = "schtasks /Run /TN " + windowsTaskName
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
	home, err := homedir.Dir()
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
	return startDetached(rollbackScript(p, pendingPath, timeout))
}

func rollbackScript(p *Pending, pendingPath string, timeout time.Duration) string {
	if runtime.GOOS == "windows" {
		return windowsRollbackScript(p, pendingPath, timeout)
	}
	return posixRollbackScript(p, pendingPath, timeout)
}

func posixRollbackScript(p *Pending, pendingPath string, timeout time.Duration) string {
	return fmt.Sprintf(
		"sleep %d; if test -f %s; then cp %s %s && chmod 755 %s && %s; fi",
		int(timeout.Seconds()),
		shellQuote(pendingPath),
		shellQuote(p.BackupPath),
		shellQuote(p.CurrentPath),
		shellQuote(p.CurrentPath),
		restartCommand(p.Slug),
	)
}

// windowsRollbackScript is the PowerShell twin of the script above, and not
// a transliteration of it — three Windows facts change its shape.
//
//  1. Windows locks a RUNNING image, so copying the backup over the current
//     path fails with a sharing violation exactly when it matters most. The
//     process holding that lock is stopped FIRST, which is what makes the
//     plain copy legal. (install.ps1 solves the same problem the other way,
//     renaming the running image aside, because an installer cannot stop the
//     link it is being run through.)
//  2. Stopping is taskkill, not `schtasks /End` — see windowsStopService.
//  3. The restore stages to a sibling path and Move-Item's it into place, so
//     a copy that dies half way through can never leave the host with a
//     truncated binary and nothing to run. install.ps1's header records what
//     that costs in real life.
//
// Restore before restart is deliberate: the restore is the irreplaceable
// half. If this script is killed after it, the good binary is already on
// disk and Task Scheduler's own RestartOnFailure/LogonTrigger bring THAT up;
// killed before it, a rollback would simply not have happened.
func windowsRollbackScript(p *Pending, pendingPath string, timeout time.Duration) string {
	staged := p.CurrentPath + ".rollback"
	return strings.Join([]string{
		// Continue, not Stop: taskkill exits non-zero when the image it was
		// given is not running, and PowerShell 7.4+ turns a native non-zero
		// exit into a terminating error under Stop — which would abandon the
		// rollback over an entirely expected message.
		"$ErrorActionPreference = 'Continue'",
		fmt.Sprintf("Start-Sleep -Seconds %d", int(timeout.Seconds())),
		"if (Test-Path -LiteralPath " + powerShellQuote(pendingPath) + ") {",
		windowsStopService,
		"try {",
		"Copy-Item -LiteralPath " + powerShellQuote(p.BackupPath) +
			" -Destination " + powerShellQuote(staged) + " -Force -ErrorAction Stop",
		"Move-Item -LiteralPath " + powerShellQuote(staged) +
			" -Destination " + powerShellQuote(p.CurrentPath) + " -Force -ErrorAction Stop",
		"} catch { }",
		windowsStartService,
		"}",
	}, "\n")
}

// StartServiceRestart launches a detached "settle for a second, then bounce
// this host's service" script. ops.SelfUpdate calls it once the new binary
// is in place, after the command reply has gone back to the control plane —
// so the caller gets a result instead of losing the tunnel mid-frame.
func StartServiceRestart(slug string) error {
	return startDetached(serviceRestartScript(slug))
}

func serviceRestartScript(slug string) string {
	if runtime.GOOS == "windows" {
		return "Start-Sleep -Seconds 1\n" + restartCommand(slug)
	}
	return "sleep 1; " + restartCommand(slug)
}

// startDetached runs script through this host's shell without waiting for
// it. Both callers have to outlive the process that starts them, and on
// Windows there is no `sh` — which is the whole reason self-update was
// refused there rather than merely failing.
//
// powershell.exe rather than the faster pwsh.exe that ops.pickShell probes
// for: 5.1 is the one shell every Windows box has, and these are one-shot
// scripts whose first act is to sleep, so start-up cost buys nothing here.
func startDetached(script string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Start()
	}
	return exec.Command("sh", "-c", script).Start()
}

func InstallDirFor(currentPath string) string {
	if dir := strings.TrimSpace(os.Getenv("AW_REMOTE_HOST_INSTALL_DIR")); dir != "" {
		return dir
	}
	if currentPath != "" {
		return filepath.Dir(currentPath)
	}
	home, err := homedir.Dir()
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

func PowerShellQuote(value string) string {
	return powerShellQuote(value)
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
	return restartCommandFor(runtime.GOOS, slug)
}

// restartCommandFor takes goos explicitly so a test on any host can assert
// every platform's spelling — the same reason servicemgr.New does. The
// Windows branch in particular shipped broken precisely because nothing on
// the Linux CI runner could reach it.
func restartCommandFor(goos, slug string) string {
	switch goos {
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
		// Reachable as of the self-update port — serviceRestartScript feeds
		// this to `powershell.exe -Command`, so it must be valid PowerShell
		// AND must not kill its own caller. The previous spelling,
		// `schtasks /End /TN … & schtasks /Run /TN …`, was neither:
		//
		//  1. `&` is a RESERVED operator in PowerShell, not cmd.exe's command
		//     separator. `a & b` is a parse error ("The ampersand (&)
		//     character is not allowed"), so the whole script would have died
		//     before restarting anything — and since callers only Start()
		//     these scripts and never read the exit code, silently.
		//  2. `schtasks /End` terminates the task's entire process tree, and
		//     the script issuing it is a detached grandchild of that tree. It
		//     would have killed itself before reaching the /Run half. This is
		//     the same trap windowsStopService documents at length.
		//
		// So reuse those two constants rather than restating them: taskkill
		// by image name ends the daemon without ending this script, and
		// they are already newline-joined statements.
		return windowsStopService + "\n" + windowsStartService
	default:
		return "true"
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// powerShellQuote is the PowerShell counterpart of shellQuote: it renders
// value as a single-quoted PowerShell literal, doubling any embedded single
// quote. Same contract — the result is one argument, and nothing inside it
// is interpreted.
//
// Single quotes and not double: inside a double-quoted PowerShell string,
// `$` still expands. A Windows install path is a prime carrier of that
// problem, because every one of them has a username in it and `$` is a
// legal character in a Windows username — so `C:\Users\$dev\...` under
// double quotes silently becomes `C:\Users\...`, pointing the installer or
// a rollback at the wrong file. Backtick escaping has no effect in a
// single-quoted string, so doubling the quote is the whole escape rule.
func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
