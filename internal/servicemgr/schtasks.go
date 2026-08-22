package servicemgr

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf16"
)

// schtasksName is the single, fixed Scheduled Task name — same choice as
// systemdUnitName, for the same reason (one workspace-host link per box).
const schtasksName = "aw-remote-host"

// schtasksXMLTemplate is a Task Scheduler task definition, registered with
// `schtasks /Create /XML`.
//
// Why XML and not the far shorter `schtasks /Create /TR "<command line>"`:
// /TR takes the whole command line as ONE string, and Task Scheduler's own
// parser re-splits it with rules that disagree with Windows' normal argv
// quoting. An exe path containing a space (C:\Program Files\... — the
// default install location for most things) needs embedded quotes inside an
// already-quoted argument, and that combination is the classic way this
// silently registers a task that can never start. The XML form keeps the
// command and its arguments in separate elements, so no quoting question
// exists at all.
//
// Element ORDER here is not cosmetic — Task Scheduler validates against a
// schema with a fixed sequence, and a reordered element is a hard "the task
// XML contains a value which is incorrectly formatted" on /Create. This is
// the exact order Task Scheduler itself emits when you export a task.
//
// ExecutionTimeLimit PT0S means "no limit": this task holds a WebSocket open
// for as long as the machine is up, and the Windows default of 3 days would
// otherwise silently terminate the link on day four.
const schtasksXMLTemplate = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>aw-remote-host — Agentic Workspace BYOD host link (%s)</Description>
    <URI>\%s</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>bootstrap-workspace --control-plane %s --yes --foreground</Arguments>
    </Exec>
  </Actions>
</Task>
`

type schtasksManager struct{}

func (m *schtasksManager) Name() string { return "schtasks" }

// GenerateSchtasksTaskXML renders the task definition — split out from
// Install for the same reason GenerateSystemdUnit is, and doubly so here:
// this is the one piece of Windows-shaped output that can be asserted on
// from a Linux test run.
func GenerateSchtasksTaskXML(cfg Config) string {
	slug := cfg.Slug
	if slug == "" {
		slug = "unknown"
	}
	return fmt.Sprintf(schtasksXMLTemplate,
		xmlEscape(slug), schtasksName, xmlEscape(cfg.ExePath), xmlEscape(cfg.ControlPlane))
}

// xmlEscape makes a value safe to drop between XML tags. The exe path is
// the one that matters in practice — a Windows username with an "&" in it
// puts an "&" straight into <Command>, which is a malformed document.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// utf16LEWithBOM re-encodes the rendered XML the way `schtasks /Create
// /XML` insists on reading it. The declaration says encoding="UTF-16" and
// schtasks believes it literally: hand it the same bytes as UTF-8 and it
// fails with a formatting error that names no encoding and points at no
// line, which is a genuinely awful thing to debug on someone else's laptop.
func utf16LEWithBOM(s string) []byte {
	codes := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+len(codes)*2)
	buf = append(buf, 0xFF, 0xFE) // little-endian BOM
	for _, c := range codes {
		buf = append(buf, byte(c), byte(c>>8))
	}
	return buf
}

func (m *schtasksManager) Path(_ Config) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	// Alongside credentials.json and state.json (see internal/link and
	// internal/state) rather than in a Windows-specific location — one
	// directory holds everything this CLI owns, on every platform.
	return filepath.Join(home, ".aw-remote-host", schtasksName+".xml"), nil
}

func (m *schtasksManager) Install(cfg Config) (string, error) {
	path, err := m.Path(cfg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, utf16LEWithBOM(GenerateSchtasksTaskXML(cfg)), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	// /F overwrites an existing task of the same name, making this
	// idempotent the way the systemd and launchd branches already are.
	if err := runCmd("schtasks", "/Create", "/TN", schtasksName, "/XML", path, "/F"); err != nil {
		return path, err
	}
	return path, nil
}

// Start runs the task immediately. Unlike `systemctl enable --now`, this is
// only the "now" half — the task is already enabled by Install (its
// LogonTrigger is what brings it back after a reboot).
func (m *schtasksManager) Start(_ Config) error {
	return runCmd("schtasks", "/Run", "/TN", schtasksName)
}

func (m *schtasksManager) Stop(_ Config) error {
	_ = runCmd("schtasks", "/End", "/TN", schtasksName) // best-effort
	return nil
}

func (m *schtasksManager) Uninstall(cfg Config) (string, error) {
	_ = runCmd("schtasks", "/End", "/TN", schtasksName)          // best-effort
	_ = runCmd("schtasks", "/Delete", "/TN", schtasksName, "/F") // best-effort
	path, err := m.Path(cfg)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove %s: %w", path, err)
	}
	return path, nil
}
