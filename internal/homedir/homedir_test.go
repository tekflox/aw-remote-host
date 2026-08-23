package homedir

import (
	"os"
	"runtime"
	"testing"
)

func TestDirPrefersHOME(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("HOME is not what os.UserHomeDir reads on Windows")
	}
	t.Setenv("HOME", "/tmp/some-explicit-home")

	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir(): %v", err)
	}
	// An explicitly-set HOME must win over the account database — that is
	// how a service definition or a test points this CLI somewhere else.
	if got != "/tmp/some-explicit-home" {
		t.Errorf("Dir() = %q, want the explicit HOME", got)
	}
}

// The regression this package exists for: a systemd SYSTEM unit runs with no
// HOME at all, and os.UserHomeDir() alone then fails with "$HOME is not
// defined", killing the process before it opens a connection.
func TestDirFallsBackWhenHOMEIsUnset(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the empty-HOME failure mode is Unix-specific")
	}
	t.Setenv("HOME", "")

	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir still resolved with an empty HOME on this platform")
	}

	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir() must not fail just because HOME is unset: %v", err)
	}
	if got == "" {
		t.Error("Dir() returned an empty path with no error")
	}
}
