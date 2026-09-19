// Package rlog is this client's operational logger: every line gets an
// RFC3339 UTC timestamp, and a copy goes to a size-capped rotating file
// under the client's own state dir (~/.aw-remote-host/client.log) in
// addition to the console — so a container/service install that has no
// terminal anyone is watching still leaves a durable, time-correlatable
// trail.
//
// It exists because this client used to log with plain fmt.Println: no
// timestamps anywhere, and on Linux/container installs (docker logs is the
// only capture, nothing durable on disk) nothing survived past the
// container's own log retention. Two independent incident investigations
// on 2026-09-15 both hit that exact wall — one had lines but no way to
// place them on a clock against aw-backend's UTC logs, the other had
// nothing durable at all once docker's own log buffer rolled over.
package rlog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tekflox/aw-remote-host/internal/instance"
)

// maxLogSize is how big client.log is allowed to grow before it rotates.
// maxLogBackups is how many rotated generations are kept alongside it
// (client.log.1 .. client.log.N, oldest dropped first), so the worst case
// on disk is roughly (maxLogBackups+1) * maxLogSize — 20MB at these values.
const (
	maxLogSize    = 5 * 1024 * 1024
	maxLogBackups = 3
)

var (
	mu      sync.Mutex
	console io.Writer = os.Stdout
	file    *os.File
	path    string
	size    int64
)

// LogPathFor returns instance name's client.log. Per-IDENTITY state: a
// second account's link on the same machine keeps its own operational log,
// under ~/.aw-remote-host/instances/<name>/ — see internal/instance.
func LogPathFor(name string) (string, error) {
	dir, err := instance.Dir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "client.log"), nil
}

// LogPath returns the client.log of the instance this process is running
// as — ~/.aw-remote-host/client.log for the default one, which is where it
// has always been. Exported so a command (or a doc) can tell an operator
// where to look without hardcoding the path a second time.
func LogPath() (string, error) {
	return LogPathFor(instance.Active())
}

// Reopen re-points the durable copy at the ACTIVE instance's own log file.
//
// It exists because of an ordering problem with no nicer answer: main()
// calls Init before it knows which command is running, let alone which
// --instance it was given, so the first open always lands on the default
// instance's path. A named instance calls this once, immediately after
// instance.SetActive — nothing has been written yet at that point, so
// nothing is lost, and every later line goes to the right identity's file.
//
// A no-op for the default instance (the common case), where the path Init
// already opened is the right one.
func Reopen() {
	mu.Lock()
	next, err := LogPath()
	if err != nil || next == path {
		mu.Unlock()
		return
	}
	if file != nil {
		file.Close()
		file = nil
	}
	path = ""
	size = 0
	mu.Unlock()
	Init(nil)
}

// Init opens the rotating log file and sets consoleOut — normally
// os.Stdout, captured by the caller before any later redirect (e.g. the
// windowless build's own stdout swap in cmd/aw-remote-host/windowless.go,
// which points os.Stdout at its own file first) — as the second write
// target for every Printf/Println call after this.
//
// Every failure here is swallowed, the same policy windowless.go already
// uses for its own file: a read-only or missing home directory must not
// stop this host from linking, it only costs the durable copy of the log —
// Printf/Println still reach consoleOut.
func Init(consoleOut io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if consoleOut != nil {
		console = consoleOut
	}
	if file != nil {
		return
	}
	p, err := LogPath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	path = p
	file = f
	size = st.Size()
}

// Printf formats and logs a line, RFC3339 UTC timestamp first, to both the
// console target and the rotating file — same call shape as fmt.Printf, so
// migrating a call site is a mechanical rename.
func Printf(format string, a ...any) {
	write(fmt.Sprintf(format, a...))
}

// Println logs a line the same way Printf does, space-joining its
// arguments the way fmt.Println does.
func Println(a ...any) {
	write(fmt.Sprintln(a...))
}

func write(msg string) {
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	line := time.Now().UTC().Format(time.RFC3339) + " " + msg

	mu.Lock()
	defer mu.Unlock()
	if console != nil {
		io.WriteString(console, line)
	}
	if file != nil {
		rotateIfNeededLocked(int64(len(line)))
		if file != nil {
			if n, err := file.WriteString(line); err == nil {
				size += int64(n)
			}
		}
	}
}

// rotateIfNeededLocked must be called with mu held. It rotates
// client.log -> client.log.1 -> ... -> client.log.maxLogBackups (oldest
// generation dropped) before a write that would push the current file past
// maxLogSize. Sets file to nil on an error reopening, so the caller falls
// back to console-only logging rather than losing every line after.
func rotateIfNeededLocked(next int64) {
	if size+next <= maxLogSize {
		return
	}
	file.Close()
	for i := maxLogBackups; i >= 1; i-- {
		if i == maxLogBackups {
			os.Remove(rotatedPath(i))
			continue
		}
		os.Rename(rotatedPath(i), rotatedPath(i+1))
	}
	os.Rename(path, rotatedPath(1))

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		file = nil
		return
	}
	file = f
	size = 0
}

func rotatedPath(n int) string {
	return fmt.Sprintf("%s.%d", path, n)
}
