package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// LogPath is where the windowless Windows build sends everything it would
// otherwise have printed to a console. Same directory as credentials.json
// and state.json, so one folder holds everything this CLI owns.
func logPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aw-remote-host", "aw-remote-host.log"), nil
}

// redirectOutputIfWindowless points os.Stdout and os.Stderr at a log file
// when this is the -H=windowsgui build (see the `windowless` var in
// main.go). A no-op for every normal build, on every platform.
//
// Appending rather than truncating is deliberate: the service restarts on
// failure (RestartOnFailure in the task definition) and at every logon, and
// the interesting question is almost always "what happened just before the
// last restart" — which a truncating open would have thrown away.
//
// Every failure here is swallowed. A read-only home directory must not stop
// the host from linking; it only costs logs, and dying instead would turn a
// cosmetic problem into an outage.
func redirectOutputIfWindowless() {
	if windowless != "true" {
		return
	}
	path, err := logPath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	os.Stdout = f
	os.Stderr = f
	fmt.Printf("--- aw-remote-host %s starting (windowless) ---\n", version)
}
