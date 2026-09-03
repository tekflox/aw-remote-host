package updater

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareWritesPendingAndBackup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	current := filepath.Join(t.TempDir(), "aw-remote-host")
	if err := os.WriteFile(current, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	p, err := Prepare(current, "build-new", "acme")
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if p.Version != "build-new" || p.Slug != "acme" || p.CurrentPath != current {
		t.Fatalf("unexpected pending data: %+v", p)
	}

	backup, err := os.ReadFile(p.BackupPath)
	if err != nil {
		t.Fatalf("expected backup binary: %v", err)
	}
	if string(backup) != "old-binary" {
		t.Fatalf("unexpected backup content: %q", backup)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".aw-remote-host", "self-update", pendingFileName)); err != nil {
		t.Fatalf("expected pending marker: %v", err)
	}
}

func TestClearPendingRemovesMarker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	current := filepath.Join(t.TempDir(), "aw-remote-host")
	if err := os.WriteFile(current, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(current, "build-new", "acme"); err != nil {
		t.Fatal(err)
	}

	if err := ClearPending(); err != nil {
		t.Fatalf("ClearPending failed: %v", err)
	}
	path, err := PendingPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected pending marker to be removed, got %v", err)
	}
}

func TestStartRollbackMonitorCanBeSkipped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_REMOTE_HOST_SKIP_ROLLBACK_MONITOR", "1")
	err := StartRollbackMonitor(&Pending{Slug: "acme"}, time.Second)
	if err != nil {
		t.Fatalf("StartRollbackMonitor failed with skip enabled: %v", err)
	}
}

func TestRestartCommandIncludesSlugForLaunchdLabels(t *testing.T) {
	cmd := RestartCommand("acme")
	if strings.Contains(cmd, "launchctl") && !strings.Contains(cmd, "'com.tekflox.aw-remote-host.acme'") {
		t.Fatalf("launchd restart command should quote the service label: %s", cmd)
	}
}

// A Windows path carries a username, and `$` is legal in one. Under a
// DOUBLE-quoted PowerShell string `C:\Users\$dev\bin` silently becomes
// `C:\Users\bin` — a rollback that restores over the wrong path, or an
// installer that writes outside the install dir, with no error either way.
func TestPowerShellQuoteDoesNotExpand(t *testing.T) {
	got := powerShellQuote(`C:\Users\$dev\bin`)
	if got != `'C:\Users\$dev\bin'` {
		t.Errorf("powerShellQuote = %s, want the value single-quoted verbatim", got)
	}
	if strings.HasPrefix(got, `"`) {
		t.Error("must not use double quotes — $ expands inside them")
	}
}

// The one escape rule single quoting has. A path or slug containing an
// apostrophe would otherwise terminate the literal early and turn the rest
// of it into PowerShell code.
func TestPowerShellQuoteDoublesEmbeddedQuote(t *testing.T) {
	if got, want := powerShellQuote("it's"), "'it''s'"; got != want {
		t.Errorf("powerShellQuote = %s, want %s", got, want)
	}
	// Backticks are PowerShell's escape character everywhere EXCEPT inside a
	// single-quoted string, where they are literal — so they must be left
	// exactly as they are rather than doubled or stripped.
	if got, want := powerShellQuote("a`b"), "'a`b'"; got != want {
		t.Errorf("powerShellQuote = %s, want %s", got, want)
	}
}

func TestPowerShellQuoteEmpty(t *testing.T) {
	if got, want := powerShellQuote(""), "''"; got != want {
		t.Errorf("powerShellQuote = %s, want %s", got, want)
	}
}

// The bug this repo shipped: restartCommand's Windows branch is fed to
// `powershell.exe -Command`, and `&` is a RESERVED operator there, not
// cmd.exe's separator. `a & b` is a parse error, so the script died before
// restarting anything — silently, because callers only Start() it.
//
// The second half matters as much: `schtasks /End` terminates the task's
// whole process tree, and the detached script issuing it is a member of
// that tree, so it would have killed itself before reaching /Run.
func TestWindowsRestartCommandIsValidPowerShellAndDoesNotKillItself(t *testing.T) {
	cmd := restartCommandFor("windows", "acme")

	if strings.Contains(cmd, "&") {
		t.Errorf("`&` is not a valid PowerShell statement separator: %s", cmd)
	}
	if strings.Contains(cmd, "schtasks /End") {
		t.Errorf("schtasks /End kills the calling script's own process tree: %s", cmd)
	}
	if !strings.Contains(cmd, "taskkill /F /IM aw-remote-host.exe") {
		t.Errorf("must stop the console-build image by name: %s", cmd)
	}
	// The Scheduled Task prefers the windowless sibling when it exists
	// (servicemgr.taskExePath), so stopping only one image leaves the old
	// binary running and the update invisible.
	if !strings.Contains(cmd, "taskkill /F /IM aw-remote-hostw.exe") {
		t.Errorf("must also stop the windowless build: %s", cmd)
	}
	if !strings.Contains(cmd, "schtasks /Run /TN aw-remote-host") {
		t.Errorf("must start the task again: %s", cmd)
	}
	if strings.Index(cmd, "taskkill") > strings.Index(cmd, "schtasks /Run") {
		t.Errorf("stop must precede start: %s", cmd)
	}
}

// The task name is a cross-package contract: servicemgr registers the task
// under schtasksName and this restarts it by name. A drift between the two
// leaves a host that stops itself and never comes back.
func TestWindowsTaskNameMatchesServicemgr(t *testing.T) {
	if windowsTaskName != "aw-remote-host" {
		t.Errorf("windowsTaskName = %q, want the servicemgr.schtasksName value", windowsTaskName)
	}
}

// Windows locks a running image, so the restore has to happen with the
// daemon already stopped, and the good binary has to be on disk before
// anything tries to start again. Ordering IS the behaviour here.
func TestWindowsRollbackScriptStopsRestoresThenStarts(t *testing.T) {
	p := &Pending{
		CurrentPath: `C:\bin\aw-remote-host.exe`,
		BackupPath:  `C:\bin\aw-remote-host.previous`,
		Slug:        "acme",
	}
	script := windowsRollbackScript(p, `C:\state\pending.json`, 75*time.Second)

	stop := strings.Index(script, "taskkill")
	move := strings.Index(script, "Move-Item")
	start := strings.Index(script, "schtasks /Run")
	if stop < 0 || move < 0 || start < 0 {
		t.Fatalf("script is missing a stage:\n%s", script)
	}
	if !(stop < move && move < start) {
		t.Errorf("want stop → restore → start, got %d/%d/%d:\n%s", stop, move, start, script)
	}

	// Copy to a sibling then rename into place: a copy that dies half way
	// must never leave the host with a truncated binary and nothing to run.
	if !strings.Contains(script, powerShellQuote(p.CurrentPath+".rollback")) {
		t.Errorf("restore must stage to a sibling path before Move-Item:\n%s", script)
	}
	// Guarded on the marker, or the rollback also fires on top of a
	// SUCCESSFUL update and reverts it.
	if !strings.Contains(script, "Test-Path -LiteralPath "+powerShellQuote(`C:\state\pending.json`)) {
		t.Errorf("rollback must be conditional on the pending marker:\n%s", script)
	}
	if !strings.Contains(script, "Start-Sleep -Seconds 75") {
		t.Errorf("must wait out the validation timeout:\n%s", script)
	}
	// taskkill exits non-zero when an image is not running, which under
	// PowerShell 7.4+'s Stop preference becomes a terminating error and
	// abandons the rollback over an entirely expected message.
	if !strings.Contains(script, "$ErrorActionPreference = 'Continue'") {
		t.Errorf("must not abort on taskkill's expected non-zero exit:\n%s", script)
	}
}

// Every path interpolated into the script goes through powerShellQuote, or
// a username with a `$` or an apostrophe in it breaks the rollback on the
// one host that most needs it to work.
func TestWindowsRollbackScriptQuotesAwkwardPaths(t *testing.T) {
	p := &Pending{
		CurrentPath: `C:\Users\o'$dev\aw-remote-host.exe`,
		BackupPath:  `C:\Users\o'$dev\aw-remote-host.previous`,
	}
	script := windowsRollbackScript(p, `C:\Users\o'$dev\pending.json`, time.Second)
	for _, want := range []string{
		powerShellQuote(p.CurrentPath),
		powerShellQuote(p.BackupPath),
		powerShellQuote(`C:\Users\o'$dev\pending.json`),
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing quoted path %s in:\n%s", want, script)
		}
	}
}

// The POSIX script must keep its own shape — the Windows twin was added
// alongside it, not in place of it.
func TestPosixRollbackScriptIsUnchangedInShape(t *testing.T) {
	p := &Pending{CurrentPath: "/usr/local/bin/aw-remote-host", BackupPath: "/b/prev", Slug: "acme"}
	script := posixRollbackScript(p, "/s/pending.json", 75*time.Second)
	for _, want := range []string{"sleep 75", "test -f", "cp ", "chmod 755"} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in:\n%s", want, script)
		}
	}
}

// SelfUpdate returns its reply over the tunnel that this restart tears
// down, so the delay is what makes the caller get a result instead of a
// dropped frame.
func TestServiceRestartScriptDelaysBeforeRestarting(t *testing.T) {
	script := serviceRestartScript("acme")
	if !strings.Contains(script, "sleep 1") && !strings.Contains(script, "Start-Sleep -Seconds 1") {
		t.Errorf("restart must be delayed so the reply lands first: %s", script)
	}
	if !strings.Contains(script, restartCommand("acme")) {
		t.Errorf("must carry this platform's restart command: %s", script)
	}
}
