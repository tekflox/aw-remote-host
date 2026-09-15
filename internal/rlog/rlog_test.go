package rlog

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// resetState clears the package-level state between tests — Init is
// normally called exactly once, by main(), but the tests need a clean slate
// each time.
func resetState(t *testing.T) {
	t.Helper()
	mu.Lock()
	if file != nil {
		file.Close()
	}
	console = os.Stdout
	file = nil
	path = ""
	size = 0
	mu.Unlock()
}

var rfc3339Prefix = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z `)

func TestPrintfWritesTimestampedLineToConsoleAndFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("HOME is not what homedir.Dir reads on Windows")
	}
	resetState(t)
	t.Setenv("HOME", t.TempDir())

	var console bytes.Buffer
	Init(&console)
	Printf("host-power: %s", "granted kvm")

	if !rfc3339Prefix.MatchString(console.String()) {
		t.Fatalf("console output missing an RFC3339 UTC prefix: %q", console.String())
	}
	if !strings.Contains(console.String(), "host-power: granted kvm") {
		t.Fatalf("console output missing the logged message: %q", console.String())
	}

	p, err := LogPath()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	if got := string(got); !rfc3339Prefix.MatchString(got) || !strings.Contains(got, "host-power: granted kvm") {
		t.Fatalf("client.log = %q, want a timestamped copy of the same line", got)
	}
}

func TestPrintlnAddsExactlyOneTrailingNewline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("HOME is not what homedir.Dir reads on Windows")
	}
	resetState(t)
	t.Setenv("HOME", t.TempDir())

	var console bytes.Buffer
	Init(&console)
	Println("link: registered")

	if n := strings.Count(console.String(), "\n"); n != 1 {
		t.Fatalf("want exactly one newline, got %d in %q", n, console.String())
	}
}

func TestInitFailureDoesNotBlockConsoleLogging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits don't work the same way on Windows")
	}
	resetState(t)
	// A HOME whose .aw-remote-host cannot be created — read-only parent —
	// must cost this process the durable file, not its ability to log at
	// all. Mirrors the swallow-every-init-failure policy documented on
	// Init and on windowless.go's own redirect.
	home := t.TempDir()
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(home, 0o700) })
	t.Setenv("HOME", home)

	var console bytes.Buffer
	Init(&console)
	Printf("link: %s", "connected")

	if !strings.Contains(console.String(), "link: connected") {
		t.Fatalf("console logging must survive a file-open failure, got %q", console.String())
	}
}

func TestRotationCapsFileCountAndKeepsNewestLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("HOME is not what homedir.Dir reads on Windows")
	}
	resetState(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	var console bytes.Buffer
	Init(&console)

	// Each line is long enough that a handful of writes cross maxLogSize
	// several times over, forcing multiple rotations.
	long := strings.Repeat("x", 64*1024)
	for i := 0; i < 400; i++ {
		Printf("%s", long)
	}

	dir := filepath.Join(home, ".aw-remote-host")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var logFiles []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "client.log") {
			logFiles = append(logFiles, e.Name())
		}
	}
	// current + up to maxLogBackups rotated generations, never more.
	if want := maxLogBackups + 1; len(logFiles) > want {
		t.Fatalf("got %d client.log* files (%v), want at most %d", len(logFiles), logFiles, want)
	}
	if len(logFiles) < 2 {
		t.Fatalf("expected at least one rotation to have happened, got %v", logFiles)
	}

	p, err := LogPath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > maxLogSize {
		t.Fatalf("current client.log is %d bytes, over the %d cap", info.Size(), maxLogSize)
	}
}
