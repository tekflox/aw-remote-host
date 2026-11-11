package bootstrap

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tekflox/aw-remote-host/internal/instance"
)

// degradationsDirName is the per-MACHINE (not per-instance) directory shell
// verify.sh scripts write marker files into when a bootstrap health check
// goes degraded, and remove them from once it clears — see
// bootstrap/lib/README.md for the SET+CLEAR convention this starts, and
// bootstrap/podman/verify.sh for the first consumer (an undersized podman
// machine on macOS).
//
// Marker files, not state.json: state.json is Go-owned read-modify-write
// (internal/state.Save), so a shell writer risks a torn/corrupted file. One
// file per condition instead, with the shell script that owns a condition
// being the only writer of its own marker.
const degradationsDirName = "degradations"

// DegradationsDir returns the per-machine degradations directory —
// ~/.aw-remote-host/degradations for every instance on this host, by
// design: a host running two linked identities still has exactly one
// physical podman machine, so the marker is host-level, not scoped per
// instance.
func DegradationsDir() (string, error) {
	root, err := instance.MachineDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, degradationsDirName), nil
}

// ReadDegradations returns the content of every marker file in the
// degradations directory, one entry per file, in the order os.ReadDir
// returns them (lexical by filename — stable, not meaningful on its own).
//
// Deliberately tolerant: a directory that doesn't exist yet (the common
// case — most hosts have never been degraded) returns an empty, never nil,
// slice and no error, matching this repo's existing "warnings: []" payload
// convention (see internal/vpn.OrEmptyStrings) rather than surfacing
// "degradations unknown" as if it were itself a failure.
func ReadDegradations() ([]string, error) {
	dir, err := DegradationsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dir, e.Name()))
		if readErr != nil {
			continue
		}
		out = append(out, strings.TrimSpace(string(data)))
	}
	return out, nil
}
