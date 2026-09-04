package state

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestProvisionedRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	st, err := Load(path)
	if err != nil {
		t.Fatalf("Load (missing file): %v", err)
	}
	if st.Provisioned {
		t.Fatalf("Provisioned should default false, got true")
	}

	st.Provisioned = true
	st.WorkspaceSlug = "acme"
	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load (after save): %v", err)
	}
	if !reloaded.Provisioned {
		t.Fatalf("Provisioned did not round-trip: got false, want true")
	}
	if reloaded.WorkspaceSlug != "acme" {
		t.Fatalf("WorkspaceSlug = %q, want acme", reloaded.WorkspaceSlug)
	}
}

// Zero (never configured) must fall back to 1, the Dockerfile's own baked
// default — not 0 workers, which would break the container.
func TestEffectiveWorkersDefaultsToOne(t *testing.T) {
	st := &State{}
	if got := st.EffectiveWorkers(); got != 1 {
		t.Fatalf("EffectiveWorkers() = %d, want 1", got)
	}
}

func TestEffectiveWorkersReturnsConfiguredValue(t *testing.T) {
	st := &State{Workers: 4}
	if got := st.EffectiveWorkers(); got != 4 {
		t.Fatalf("EffectiveWorkers() = %d, want 4", got)
	}
}

// The daemon holds a State loaded at startup and can run for days. Saving that
// struct whole erases anything a VERB recorded in the meantime — measured on
// the production bare metal 2026-09-02, where an external route confirmed at
// 17:51 was gone from state.json by 17:58 while still installed in the kernel,
// leaving Reassert nothing to restore after a flush. Update must read the file
// first so the two writers cannot erase each other.
func TestUpdateDoesNotClobberAnotherWritersFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	// The daemon's view, captured at startup.
	stale := &State{WorkspaceSlug: "aw"}
	if err := Save(path, stale); err != nil {
		t.Fatal(err)
	}

	// A verb records an external route directly to the file.
	if err := Update(path, func(s *State) {
		s.VPN = &VPNState{ExternalRoute: &ExternalRouteState{Container: "aw-remote-host", SourceIP: "172.18.0.4"}}
	}); err != nil {
		t.Fatal(err)
	}

	// The daemon reconnects and records the slug from its STALE struct.
	if err := Update(path, func(s *State) { s.WorkspaceSlug = stale.WorkspaceSlug }); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.VPN == nil || got.VPN.ExternalRoute == nil {
		t.Fatal("the daemon's save erased the external route the verb had recorded")
	}
	if got.VPN.ExternalRoute.SourceIP != "172.18.0.4" || got.WorkspaceSlug != "aw" {
		t.Fatalf("both writers' fields must survive: %+v", got)
	}
}

func TestRecordBootstrapVersionSkipsDevAndBlank(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	for _, v := range []string{"", "dev", "  "} {
		if err := RecordBootstrapVersion(path, v); err != nil {
			t.Fatalf("RecordBootstrapVersion(%q): %v", v, err)
		}
	}
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastBootstrapVersion != "" {
		t.Fatalf("dev/blank versions must not be recorded, got %q", st.LastBootstrapVersion)
	}

	if err := RecordBootstrapVersion(path, "v0.1.66"); err != nil {
		t.Fatal(err)
	}
	st, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastBootstrapVersion != "v0.1.66" {
		t.Fatalf("LastBootstrapVersion = %q, want v0.1.66", st.LastBootstrapVersion)
	}
}

// This is the exact scenario from incident:byod-postgres-lost-bind-mount-2026-09-02:
// a host that had already bootstrapped with v0.1.72 got a full bootstrap
// re-run by a pre-fix binary reverted to whatever an unrebuilt docker image
// had baked in. The guard must refuse that, loudly, unless forced.
func TestCheckDowngradeRefusesAnOlderBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := RecordBootstrapVersion(path, "v0.1.72"); err != nil {
		t.Fatal(err)
	}

	err := CheckDowngrade(path, "v0.1.66", false)
	if err == nil {
		t.Fatal("expected an error for a binary older than the last recorded bootstrap")
	}
	if !strings.Contains(err.Error(), "v0.1.66") || !strings.Contains(err.Error(), "v0.1.72") {
		t.Fatalf("error should name both versions, got: %v", err)
	}

	if err := CheckDowngrade(path, "v0.1.66", true); err != nil {
		t.Fatalf("force=true must bypass the guard, got: %v", err)
	}
}

func TestCheckDowngradeAllowsSameOrNewer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := RecordBootstrapVersion(path, "v0.1.72"); err != nil {
		t.Fatal(err)
	}

	for _, v := range []string{"v0.1.72", "v0.1.73", "v0.2.0", "v1.0.0"} {
		if err := CheckDowngrade(path, v, false); err != nil {
			t.Fatalf("CheckDowngrade(%q) should not block a same-or-newer version: %v", v, err)
		}
	}
}

func TestCheckDowngradeNeverBlocksWithNothingToCompare(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	// Nothing recorded yet — a host's very first bootstrap.
	if err := CheckDowngrade(path, "v0.1.66", false); err != nil {
		t.Fatalf("no prior recording should never block: %v", err)
	}

	if err := RecordBootstrapVersion(path, "v0.1.72"); err != nil {
		t.Fatal(err)
	}
	// A dev build, or an unparsable recorded/running value, is not a
	// meaningful comparison — must not block either.
	for _, v := range []string{"", "dev", "not-a-version"} {
		if err := CheckDowngrade(path, v, false); err != nil {
			t.Fatalf("CheckDowngrade(%q) should not block: %v", v, err)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.1.66", "v0.1.72", -1, true},
		{"v0.1.72", "v0.1.66", 1, true},
		{"v0.1.72", "v0.1.72", 0, true},
		{"v1.0.0", "v0.9.9", 1, true},
		{"v0.1", "v0.1.0", 0, true},
		{"v0.2", "v0.1.9", 1, true},
		{"dev", "v0.1.72", 0, false},
		{"v0.1.72", "", 0, false},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		if ok != c.ok {
			t.Errorf("compareVersions(%q, %q) ok = %v, want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
