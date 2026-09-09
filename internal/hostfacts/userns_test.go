package hostfacts

import (
	"os"
	"path/filepath"
	"testing"
)

func withUIDMap(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "uid_map")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := uidMapPath
	uidMapPath = path
	t.Cleanup(func() { uidMapPath = orig })
}

func TestUsernsContainedInitialNamespace(t *testing.T) {
	// Exactly what a container in the INITIAL user namespace reads — the
	// shape measured inside a current workspace container before this
	// change. Must NOT be reported as contained.
	withUIDMap(t, "         0          0 4294967295\n")

	contained, ok := UsernsContained()
	if !ok {
		t.Fatal("expected the map to be measurable")
	}
	if contained {
		t.Fatal("identity map must not read as contained")
	}
	if got := UIDMap(); got != "0 0 4294967295" {
		t.Fatalf("uid_map not normalised: %q", got)
	}
}

func TestUsernsContainedRemapped(t *testing.T) {
	// What the driver's own per-workspace range produces.
	withUIDMap(t, "         0    1000000      65536\n")

	contained, ok := UsernsContained()
	if !ok || !contained {
		t.Fatalf("remapped map must read as contained (contained=%v ok=%v)", contained, ok)
	}
	if got := UIDMap(); got != "0 1000000 65536" {
		t.Fatalf("uid_map not normalised: %q", got)
	}
}

func TestUsernsNotMeasurable(t *testing.T) {
	// No /proc/self/uid_map — every non-Linux host. "Not measured" must be
	// distinguishable from "measured, not contained", because only the
	// second one is a finding.
	orig := uidMapPath
	uidMapPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { uidMapPath = orig })

	contained, ok := UsernsContained()
	if ok {
		t.Fatal("a missing uid_map must report ok=false, not a measurement")
	}
	if contained {
		t.Fatal("unmeasurable must not report contained")
	}
	if got := UIDMap(); got != "" {
		t.Fatalf("expected empty uid_map, got %q", got)
	}
}
