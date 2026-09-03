package main

import (
	"os"
	"runtime"
	"testing"
)

// processIsElevated must agree with a direct computation of the platform
// rule it wraps — this pins the GOOS branch instead of just calling the
// function once and hoping nothing panics. On Windows it has to defer to
// isElevated() (the token's own elevation flag); everywhere else it has to
// be os.Geteuid() == 0, not os.Getuid() — a setuid-root binary invoked by a
// non-root user is running elevated right now regardless of its real uid.
func TestProcessIsElevatedMatchesPlatformRule(t *testing.T) {
	got := processIsElevated()

	var want bool
	if runtime.GOOS == "windows" {
		want = isElevated()
	} else {
		want = os.Geteuid() == 0
	}

	if got != want {
		t.Fatalf("processIsElevated() = %v, want %v", got, want)
	}
}
