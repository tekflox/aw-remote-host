package state

import (
	"path/filepath"
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
