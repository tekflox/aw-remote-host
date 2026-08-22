//go:build !windows

package shell

import "testing"

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
