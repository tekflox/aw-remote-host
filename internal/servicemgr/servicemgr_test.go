package servicemgr

import (
	"os"
	"path/filepath"
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

// A dropped link must come back on its own — the machine is not somewhere
// anyone can go and restart a service by hand.
func TestGenerateSchtasksTaskXMLRestartsOnFailure(t *testing.T) {
	doc := GenerateSchtasksTaskXML(Config{ExePath: `C:\x.exe`, ControlPlane: "https://y"})
	if !strings.Contains(doc, "<RestartOnFailure>") {
		t.Fatalf("task must restart on failure:\n%s", doc)
	}
	if !strings.Contains(doc, "<Interval>PT1M</Interval>") {
		t.Error("expected a 1-minute restart interval")
	}
	// RestartOnFailure sits after Priority in the sequence Task Scheduler
	// itself emits. Order is load-bearing here — a misplaced element is a
	// hard "incorrectly formatted" rejection from schtasks /Create.
	if strings.Index(doc, "<RestartOnFailure>") < strings.Index(doc, "<Priority>") {
		t.Error("RestartOnFailure must come after Priority")
	}
	if strings.Index(doc, "<RestartOnFailure>") > strings.Index(doc, "</Settings>") {
		t.Error("RestartOnFailure must stay inside Settings")
	}
}

func TestTaskExePathPrefersTheWindowlessBuild(t *testing.T) {
	dir := t.TempDir()
	console := filepath.Join(dir, "aw-remote-host.exe")
	windowless := filepath.Join(dir, "aw-remote-hostw.exe")

	if err := os.WriteFile(console, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	// No `w` binary yet — a host that installed before it existed must keep
	// working rather than get a task pointing at a missing file.
	if got := taskExePath(console); got != console {
		t.Errorf("with no windowless build, want %q, got %q", console, got)
	}

	if err := os.WriteFile(windowless, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := taskExePath(console); got != windowless {
		t.Errorf("want the windowless build %q, got %q", windowless, got)
	}
}

func TestTaskExePathHandlesEdgeCases(t *testing.T) {
	if got := taskExePath(""); got != "" {
		t.Errorf("empty path should stay empty, got %q", got)
	}
	// A directory named like the sibling must not be mistaken for it.
	dir := t.TempDir()
	console := filepath.Join(dir, "aw-remote-host.exe")
	if err := os.WriteFile(console, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "aw-remote-hostw.exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := taskExePath(console); got != console {
		t.Errorf("a directory is not a binary; want %q, got %q", console, got)
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

func TestGenerateSchtasksTaskXMLRunLevel(t *testing.T) {
	base := Config{ExePath: `C:\x.exe`, ControlPlane: "https://y"}

	// Unprivileged is the default and must stay the default: everything the
	// lean link exists to do works without admin, and an install that
	// silently demands it is the worse failure.
	plain := GenerateSchtasksTaskXML(base)
	if !strings.Contains(plain, "<RunLevel>LeastPrivilege</RunLevel>") {
		t.Fatalf("default install must stay unprivileged:\n%s", plain)
	}
	if strings.Contains(plain, "HighestAvailable") {
		t.Error("a default install must never ask for elevation")
	}

	elevated := base
	elevated.Elevated = true
	doc := GenerateSchtasksTaskXML(elevated)
	if !strings.Contains(doc, "<RunLevel>HighestAvailable</RunLevel>") {
		t.Fatalf("Elevated=true must raise the run level:\n%s", doc)
	}
	if strings.Contains(doc, "LeastPrivilege") {
		t.Error("both run levels present — the template substituted the wrong slot")
	}

	// Order is load-bearing: Task Scheduler validates against a fixed
	// sequence, and a RunLevel outside Principal is a hard rejection from
	// schtasks /Create rather than a task that merely lacks rights.
	if strings.Index(doc, "<RunLevel>") < strings.Index(doc, "<LogonType>") {
		t.Error("RunLevel must follow LogonType inside Principal")
	}
	if strings.Index(doc, "<RunLevel>") > strings.Index(doc, "</Principals>") {
		t.Error("RunLevel must stay inside Principals")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Instances. The tests above already pin the DEFAULT instance's rendered
// content; everything below pins what a NAMED one changes, and — more
// importantly — what it must not.
// ────────────────────────────────────────────────────────────────────────

// wantDefaultSystemdUnit / wantDefaultLaunchdPlist are golden copies of what
// every host in the field already has on disk, written out in full rather
// than assembled from the templates under test.
//
// A test that rebuilt them from serviceArgs() would agree with any change
// serviceArgs() made, which is precisely the failure mode that matters here:
// the default instance's unit is not "a rendering", it is a file already
// installed on machines this change must not touch.
const wantDefaultSystemdUnit = `[Unit]
Description=aw-remote-host — Agentic Workspace BYOD workspace-host link (acme)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/home/u/.local/bin/aw-remote-host bootstrap-workspace --control-plane https://api.aw.tekflox.com --yes --foreground
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`

func TestDefaultInstanceSystemdUnitIsByteIdentical(t *testing.T) {
	cfg := Config{Slug: "acme", ExePath: "/home/u/.local/bin/aw-remote-host", ControlPlane: "https://api.aw.tekflox.com"}
	if got := GenerateSystemdUnit(cfg); got != wantDefaultSystemdUnit {
		t.Errorf("the default instance's unit content changed — every Linux BYOD host already has the old one installed.\ngot:\n%s\nwant:\n%s", got, wantDefaultSystemdUnit)
	}
}

func TestDefaultInstanceLaunchdPlistProgramArgumentsAreByteIdentical(t *testing.T) {
	cfg := Config{Slug: "acme", ExePath: "/usr/local/bin/aw-remote-host", ControlPlane: "https://api.aw.tekflox.com"}
	plist, err := GenerateLaunchdPlist(cfg)
	if err != nil {
		t.Fatalf("GenerateLaunchdPlist: %v", err)
	}
	want := "\t<key>ProgramArguments</key>\n" +
		"\t<array>\n" +
		"\t\t<string>/usr/local/bin/aw-remote-host</string>\n" +
		"\t\t<string>bootstrap-workspace</string>\n" +
		"\t\t<string>--control-plane</string>\n" +
		"\t\t<string>https://api.aw.tekflox.com</string>\n" +
		"\t\t<string>--yes</string>\n" +
		"\t\t<string>--foreground</string>\n" +
		"\t</array>\n"
	if !strings.Contains(plist, want) {
		t.Errorf("the default instance's ProgramArguments block changed — every Mac in the field already has the old plist loaded.\ngot:\n%s\nwant substring:\n%s", plist, want)
	}
	if strings.Contains(plist, "--instance") {
		t.Error("the default instance's plist must not carry --instance: a host linked before instances existed runs a binary that would reject the flag")
	}
}

// TestNamedInstanceUnitCarriesInstanceAndNeverHome is the regression for the
// credential leak this whole feature exists to close.
//
// The leak: a second identity was set up by hand by overriding $HOME. The
// generated plist has no EnvironmentVariables key at all, so that override
// survived only the operator's foreground shell — on the next launchd
// respawn homedir.Dir() read the real $HOME and loaded the FIRST account's
// credentials.json, with no error anywhere. The fix is an argument, not an
// environment variable, and this asserts both halves.
func TestNamedInstanceUnitCarriesInstanceAndNeverHome(t *testing.T) {
	cfg := Config{Slug: "acme", Instance: "work", ExePath: "/usr/local/bin/aw-remote-host", ControlPlane: "https://api.aw.tekflox.com"}

	plist, err := GenerateLaunchdPlist(cfg)
	if err != nil {
		t.Fatalf("GenerateLaunchdPlist: %v", err)
	}
	for _, want := range []string{"<string>--instance</string>", "<string>work</string>"} {
		if !strings.Contains(plist, want) {
			t.Errorf("named instance plist missing %s — the respawned job would load the default instance's credentials:\n%s", want, plist)
		}
	}
	for _, forbidden := range []string{"EnvironmentVariables", "HOME"} {
		if strings.Contains(plist, forbidden) {
			t.Errorf("named instance plist sets %s — HOME also moves podman's storage root, the Go cache and ssh, which is what made the manual workaround unsafe:\n%s", forbidden, plist)
		}
	}
	// A named instance is lean-only, so its service must run the command
	// that structurally cannot provision.
	if !strings.Contains(plist, "<string>link</string>") || strings.Contains(plist, "<string>bootstrap-workspace</string>") {
		t.Errorf("a named instance's service must run 'link', not 'bootstrap-workspace':\n%s", plist)
	}

	unit := GenerateSystemdUnit(cfg)
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/aw-remote-host link --instance work --control-plane https://api.aw.tekflox.com --yes --foreground") {
		t.Errorf("named instance ExecStart does not pass --instance:\n%s", unit)
	}
	if strings.Contains(unit, "Environment") {
		t.Errorf("named instance unit sets an environment variable; the instance must travel as an argument:\n%s", unit)
	}
}

// TestSystemdIsInstanceScopedEverywhere is the regression for the silent
// mutual clobbering on Linux: Path/Start/Stop/Uninstall used to ignore
// their Config entirely and act on one fixed unit name, so a second
// `link --background` overwrote the first identity's unit file and an
// unlink of either removed the other's service.
func TestSystemdIsInstanceScopedEverywhere(t *testing.T) {
	mgr := &systemdManager{}

	def, err := mgr.Path(Config{Slug: "acme"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	// The highest-stakes assertion in this file: renaming this orphans every
	// existing Linux BYOD host (old unit still enabled, new name never
	// started).
	if !strings.HasSuffix(def, ".config/systemd/user/aw-remote-host.service") {
		t.Fatalf("the DEFAULT instance's unit path moved: %q", def)
	}

	named, err := mgr.Path(Config{Slug: "acme", Instance: "work"})
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if named == def {
		t.Fatalf("a named instance writes the SAME unit file as the default one (%q) — the second link would overwrite the first", def)
	}
	if !strings.HasSuffix(named, ".config/systemd/user/aw-remote-host-work.service") {
		t.Errorf("unexpected named unit path: %q", named)
	}

	// The unit NAME is what systemctl enable/disable/stop act on, and it is
	// the half that was ignored. Asserted directly so the systemctl-driven
	// methods cannot regress without this failing.
	if got := systemdUnit(Config{}); got != "aw-remote-host" {
		t.Errorf("default unit name is %q, want aw-remote-host", got)
	}
	if got := systemdUnit(Config{Instance: "work"}); got != "aw-remote-host-work" {
		t.Errorf("named unit name is %q, want aw-remote-host-work", got)
	}
}

func TestLaunchdLabelDefaultUnchangedNamedSuffixed(t *testing.T) {
	if got := LaunchdLabel("acme", ""); got != "com.tekflox.aw-remote-host.acme" {
		t.Errorf("the default instance's launchd label moved: %q", got)
	}
	if got := LaunchdLabel("acme", "work"); got != "com.tekflox.aw-remote-host.acme.work" {
		t.Errorf("named instance label = %q", got)
	}

	mgr := &launchdManager{}
	def, err := mgr.Path(Config{Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	named, err := mgr.Path(Config{Slug: "acme", Instance: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if def == named {
		t.Fatalf("a named instance writes the same plist as the default one: %q", def)
	}
	if !strings.HasSuffix(def, "com.tekflox.aw-remote-host.acme.plist") {
		t.Errorf("the default instance's plist filename moved: %q", def)
	}
}

// TestSchtasksRefusesANamedInstance pins the product decision that Windows
// is explicitly refused rather than half-supported: the Scheduled Task name
// is a single fixed string there, so a named instance would overwrite the
// first one's task. Every method refuses, not just Install, so no path can
// reach schtasks with an instance it would silently drop.
func TestSchtasksRefusesANamedInstance(t *testing.T) {
	mgr := &schtasksManager{}
	named := Config{Slug: "acme", Instance: "work", ExePath: `C:\x.exe`, ControlPlane: "https://y"}

	if _, err := mgr.Path(named); err == nil {
		t.Error("Path accepted a named instance on Windows")
	}
	if _, err := mgr.Install(named); err == nil {
		t.Error("Install accepted a named instance on Windows")
	}
	if err := mgr.Start(named); err == nil {
		t.Error("Start accepted a named instance on Windows")
	}
	if err := mgr.Stop(named); err == nil {
		t.Error("Stop accepted a named instance on Windows")
	}
	if _, err := mgr.Uninstall(named); err == nil {
		t.Error("Uninstall accepted a named instance on Windows")
	}

	// The default instance must be entirely unaffected by that refusal.
	if _, err := mgr.Path(Config{Slug: "acme"}); err != nil {
		t.Errorf("the default instance must still work on Windows: %v", err)
	}
}
