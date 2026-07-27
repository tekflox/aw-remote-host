package servicemgr

import (
	"strings"
	"testing"
)

func TestNewReturnsExpectedManagerPerGOOS(t *testing.T) {
	linux, err := New("linux")
	if err != nil {
		t.Fatalf("New(linux): %v", err)
	}
	if linux.Name() != "systemd" {
		t.Errorf("New(linux).Name() = %q, want systemd", linux.Name())
	}

	darwin, err := New("darwin")
	if err != nil {
		t.Fatalf("New(darwin): %v", err)
	}
	if darwin.Name() != "launchd" {
		t.Errorf("New(darwin).Name() = %q, want launchd", darwin.Name())
	}

	if _, err := New("windows"); err == nil {
		t.Error("New(windows): expected an error, got nil")
	}
}

func TestGenerateSystemdUnit(t *testing.T) {
	cfg := Config{Slug: "acme", ExePath: "/home/u/.local/bin/aw-remote-host", ControlPlane: "https://api.aw.tekflox.com"}
	unit := GenerateSystemdUnit(cfg)

	wantExec := "ExecStart=/home/u/.local/bin/aw-remote-host bootstrap-workspace --control-plane https://api.aw.tekflox.com --yes --foreground"
	if !strings.Contains(unit, wantExec) {
		t.Errorf("unit missing ExecStart line, want substring:\n%s\ngot:\n%s", wantExec, unit)
	}
	if !strings.Contains(unit, "acme") {
		t.Errorf("unit should reference the workspace slug in its description")
	}
	if !strings.Contains(unit, "Restart=always") {
		t.Error("unit should auto-restart")
	}
}

func TestGenerateSystemdUnitDefaultsSlugWhenEmpty(t *testing.T) {
	unit := GenerateSystemdUnit(Config{ExePath: "/x", ControlPlane: "https://y"})
	if !strings.Contains(unit, "unknown") {
		t.Error("expected a placeholder slug when Config.Slug is empty")
	}
}

func TestGenerateLaunchdPlist(t *testing.T) {
	cfg := Config{Slug: "acme", ExePath: "/usr/local/bin/aw-remote-host", ControlPlane: "https://api.aw.tekflox.com"}
	plist, err := GenerateLaunchdPlist(cfg)
	if err != nil {
		t.Fatalf("GenerateLaunchdPlist: %v", err)
	}

	if !strings.Contains(plist, "<string>com.tekflox.aw-remote-host.acme</string>") {
		t.Error("plist missing slug-scoped Label")
	}
	for _, arg := range []string{"/usr/local/bin/aw-remote-host", "bootstrap-workspace", "--control-plane", "https://api.aw.tekflox.com", "--yes", "--foreground"} {
		if !strings.Contains(plist, "<string>"+arg+"</string>") {
			t.Errorf("plist ProgramArguments missing %q", arg)
		}
	}
	if !strings.Contains(plist, "<key>KeepAlive</key>") || !strings.Contains(plist, "<true/>") {
		t.Error("plist should KeepAlive so a crash gets relaunched")
	}
	// launchd runs services with cwd=/ — a WorkingDirectory (dir of the
	// binary) is required so a relative ExePath/cwd doesn't fail (exit 78).
	if !strings.Contains(plist, "<key>WorkingDirectory</key>") ||
		!strings.Contains(plist, "<string>/usr/local/bin</string>") {
		t.Error("plist missing WorkingDirectory set to the binary's dir")
	}
}

func TestLaunchdPathIsSlugScoped(t *testing.T) {
	mgr := &launchdManager{}

	pathA, err := mgr.Path(Config{Slug: "acme"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	pathB, err := mgr.Path(Config{Slug: "widgets"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if pathA == pathB {
		t.Errorf("expected distinct paths per slug, both got %q", pathA)
	}
	if !strings.HasSuffix(pathA, "com.tekflox.aw-remote-host.acme.plist") {
		t.Errorf("unexpected plist path: %q", pathA)
	}
	if !strings.Contains(pathA, "Library/LaunchAgents") {
		t.Errorf("expected LaunchAgents dir in path: %q", pathA)
	}
}

func TestSystemdPathIsNotSlugScoped(t *testing.T) {
	mgr := &systemdManager{}

	pathA, err := mgr.Path(Config{Slug: "acme"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	pathB, err := mgr.Path(Config{Slug: "widgets"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if pathA != pathB {
		t.Errorf("systemd unit path should be fixed regardless of slug, got %q vs %q", pathA, pathB)
	}
	if !strings.HasSuffix(pathA, ".config/systemd/user/aw-remote-host.service") {
		t.Errorf("unexpected unit path: %q", pathA)
	}
}
