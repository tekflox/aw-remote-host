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
