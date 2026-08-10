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
