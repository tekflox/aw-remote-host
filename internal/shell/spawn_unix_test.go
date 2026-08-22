//go:build !windows

package shell

import "testing"

// The POSIX default must stay the workspace container: the console sends no
// target, and flipping this would silently move every existing browser
// terminal session from the container onto the metal.
func TestDefaultTargetIsTheWorkspaceOnPOSIX(t *testing.T) {
	if defaultTarget != TargetWorkspace {
		t.Errorf("defaultTarget = %q, want %q", defaultTarget, TargetWorkspace)
	}
	got, err := resolveTarget("")
	if err != nil || got != TargetWorkspace {
		t.Errorf("resolveTarget(\"\") = %q, %v; want %q, nil", got, err, TargetWorkspace)
	}
}

func TestWithTermOnlyFillsAMissingOne(t *testing.T) {
	// A shell spawned from a systemd unit or container entrypoint inherits no
	// TERM, and bash then falls back to `dumb` — no arrow keys, no colour, no
	// vim. But an inherited TERM must be left alone.
	if got := withTerm([]string{"PATH=/bin", "TERM=screen"}); len(got) != 2 {
		t.Errorf("withTerm overrode an existing TERM: %v", got)
	}
	got := withTerm([]string{"PATH=/bin"})
	if len(got) != 2 || got[1] != "TERM=xterm-256color" {
		t.Errorf("withTerm = %v, want a TERM appended", got)
	}
	// TERM= (set but empty) is as useless as absent.
	if got := withTerm([]string{"TERM="}); len(got) != 2 {
		t.Errorf("withTerm left an empty TERM in place: %v", got)
	}
}
