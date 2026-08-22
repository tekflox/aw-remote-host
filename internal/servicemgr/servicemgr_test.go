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

	windows, err := New("windows")
	if err != nil {
		t.Fatalf("New(windows): %v", err)
	}
	if windows.Name() != "schtasks" {
		t.Errorf("New(windows).Name() = %q, want schtasks", windows.Name())
	}

	if _, err := New("plan9"); err == nil {
		t.Error("New(plan9): expected an error, got nil")
	}
}

func TestGenerateSchtasksTaskXML(t *testing.T) {
	cfg := Config{
		Slug:         "acme",
		ExePath:      `C:\Users\fred\.local\bin\aw-remote-host.exe`,
		ControlPlane: "https://api.aw.tekflox.com",
	}
	doc := GenerateSchtasksTaskXML(cfg)

	if !strings.HasPrefix(doc, `<?xml version="1.0" encoding="UTF-16"?>`) {
		t.Error("declaration must say UTF-16 — schtasks /XML reads it literally")
	}
	if !strings.Contains(doc, "<Command>"+cfg.ExePath+"</Command>") {
		t.Errorf("missing <Command> with the exe path, got:\n%s", doc)
	}
	wantArgs := "<Arguments>bootstrap-workspace --control-plane https://api.aw.tekflox.com --yes --foreground</Arguments>"
	if !strings.Contains(doc, wantArgs) {
		t.Errorf("missing <Arguments>, want substring:\n%s", wantArgs)
	}
	if !strings.Contains(doc, "<LogonTrigger>") {
		t.Error("task must be triggered at logon, or a reboot leaves the host unlinked")
	}
	// The Windows default is 3 days; this task holds a WebSocket for as
	// long as the box is up, so an unlimited run time is load-bearing.
	if !strings.Contains(doc, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
		t.Error("ExecutionTimeLimit must be PT0S (unlimited)")
	}
	if !strings.Contains(doc, "acme") {
		t.Error("description should reference the workspace slug")
	}
}

// A Windows username with an XML metacharacter in it lands straight in
// <Command> via the profile path — unescaped, that is a malformed document
// and schtasks rejects the whole task.
func TestGenerateSchtasksTaskXMLEscapesMetacharacters(t *testing.T) {
	doc := GenerateSchtasksTaskXML(Config{
		Slug:         "a&b",
		ExePath:      `C:\Users\R&D <team>\aw-remote-host.exe`,
		ControlPlane: "https://x/?a=1&b=2",
	})
	if strings.Contains(doc, "R&D") || strings.Contains(doc, "<team>") {
		t.Errorf("exe path was not XML-escaped:\n%s", doc)
	}
	if !strings.Contains(doc, "R&amp;D") || !strings.Contains(doc, "&lt;team&gt;") {
		t.Errorf("expected escaped entities in <Command>:\n%s", doc)
	}
	if !strings.Contains(doc, "a=1&amp;b=2") {
		t.Errorf("control-plane URL was not XML-escaped:\n%s", doc)
	}
}

func TestGenerateSchtasksTaskXMLDefaultsSlugWhenEmpty(t *testing.T) {
	doc := GenerateSchtasksTaskXML(Config{ExePath: `C:\x.exe`, ControlPlane: "https://y"})
	if !strings.Contains(doc, "unknown") {
		t.Error("expected a placeholder slug when Config.Slug is empty")
	}
}

func TestUTF16LEWithBOM(t *testing.T) {
	got := utf16LEWithBOM("AB")
	want := []byte{0xFF, 0xFE, 'A', 0x00, 'B', 0x00}
	if len(got) != len(want) {
		t.Fatalf("length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = %#x, want %#x (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestSchtasksPathIsNotSlugScoped(t *testing.T) {
	mgr := &schtasksManager{}

	pathA, err := mgr.Path(Config{Slug: "acme"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	pathB, err := mgr.Path(Config{Slug: "widgets"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if pathA != pathB {
		t.Errorf("task path should be fixed regardless of slug, got %q vs %q", pathA, pathB)
	}
	if !strings.HasSuffix(pathA, "aw-remote-host.xml") {
		t.Errorf("unexpected task xml path: %q", pathA)
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
