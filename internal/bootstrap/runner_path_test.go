package bootstrap

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeVendoredPodman creates <home>/podman-dist/podman/bin/podman — the
// exact layout install_vendored_podman() (bootstrap/podman/install.sh) lays
// down on a brew-less macOS host — as a real, executable shell script that
// prints a recognizable line and exits 0, so a test can tell "the real
// podman binary actually ran" apart from "LookPath found something named
// podman and ran a no-op". Returns the vendored bin dir.
func writeFakeVendoredPodman(t *testing.T, home string) string {
	t.Helper()
	dir := filepath.Join(home, "podman-dist", "podman", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho fake-podman-ran \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestApplyVendoredPodmanPATHPrependsTheVendoredDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vendorDir := writeFakeVendoredPodman(t, home)
	base := t.TempDir()
	t.Setenv("PATH", base)

	dir, ok := ApplyVendoredPodmanPATH()

	if !ok || dir != vendorDir {
		t.Fatalf("ApplyVendoredPodmanPATH() = (%q, %v), want (%q, true)", dir, ok, vendorDir)
	}
	got := os.Getenv("PATH")
	if !strings.HasPrefix(got, vendorDir+string(os.PathListSeparator)) {
		t.Fatalf("PATH = %q, want it to start with %q", got, vendorDir+string(os.PathListSeparator))
	}
	if !strings.Contains(got, base) {
		t.Fatalf("PATH = %q, want it to still contain the original base %q", got, base)
	}
}

func TestApplyVendoredPodmanPATHNoopWithoutAVendoredInstall(t *testing.T) {
	home := t.TempDir() // no podman-dist under here
	t.Setenv("HOME", home)
	base := t.TempDir()
	t.Setenv("PATH", base)

	dir, ok := ApplyVendoredPodmanPATH()

	if ok || dir != "" {
		t.Fatalf("ApplyVendoredPodmanPATH() = (%q, %v), want (\"\", false) with no vendored install", dir, ok)
	}
	if got := os.Getenv("PATH"); got != base {
		t.Fatalf("PATH = %q, want unchanged %q", got, base)
	}
}

// TestApplyVendoredPodmanPATHFixesTheRealLookPathTimingBug is the regression
// test for the bug this card exists for: execRunner.Run and
// startTrackedProcess both pass a bare "podman" straight to
// exec.CommandContext, which resolves it via LookPath AT CONSTRUCTION TIME
// against the process's own os.Getenv("PATH") — a cmd.Env override set
// afterward (what the code used to do) is too late to matter, because it
// only affects what the child sees once started, not how the executable
// itself was found.
//
// A fake Runner can't catch this class of bug at all — it bypasses
// exec.Command entirely. This test exercises the real os/exec call these
// production call sites make, in an environment that reproduces the actual
// failure (podman genuinely absent from the base PATH, only reachable via
// the vendored dir — the exact shape confirmed live on Mac.Home,
// PATH=/usr/bin:/bin:/usr/sbin:/sbin with podman nowhere on it).
func TestApplyVendoredPodmanPATHFixesTheRealLookPathTimingBug(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFakeVendoredPodman(t, home)
	base := t.TempDir() // empty — simulates a bare PATH with no podman at all
	t.Setenv("PATH", base)
	ctx := context.Background()

	// First, prove the simulated environment really does reproduce the bug:
	// a bare "podman" exec.Command, constructed BEFORE the fix runs, fails
	// LookPath — the same failure Health()/Stop()/Restart() hit on the real
	// host, every time, before ever forking a process.
	if _, err := exec.CommandContext(ctx, "podman", "inspect").CombinedOutput(); err == nil {
		t.Fatalf("exec.Command(\"podman\") unexpectedly succeeded against a bare PATH with no podman on it (%q) — test setup is not reproducing the bug", os.Getenv("PATH"))
	}

	// Now apply the fix, exactly as main() does once at startup, before any
	// verb runs.
	if _, ok := ApplyVendoredPodmanPATH(); !ok {
		t.Fatal("ApplyVendoredPodmanPATH() reported no vendored install — test fixture is wrong")
	}

	// A FRESH exec.Command, constructed the same way execRunner.Run and
	// startTrackedProcess do (a bare name, no cmd.Env patch at all) — this is
	// the exact call shape production makes, not an approximation of it.
	out, err := exec.CommandContext(ctx, "podman", "inspect", "aw-remote-host-workspace").CombinedOutput()
	if err != nil {
		t.Fatalf("exec.Command(\"podman\", ...) failed after ApplyVendoredPodmanPATH: %v (output: %q)", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "fake-podman-ran inspect aw-remote-host-workspace" {
		t.Fatalf("output = %q, want the fake vendored podman's own output — LookPath may have resolved a different binary", got)
	}
}
