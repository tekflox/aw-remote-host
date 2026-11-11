package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDegradationsEmptyWhenDirAbsent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows

	got, err := ReadDegradations()
	if err != nil {
		t.Fatalf("ReadDegradations: %v", err)
	}
	if got == nil {
		t.Fatal("expected an empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected no degradations, got %v", got)
	}
}

func TestReadDegradationsRelaysMarkerContent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir, err := DegradationsDir()
	if err != nil {
		t.Fatalf("DegradationsDir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	want := "podman machine is undersized — resize it with: podman machine stop && podman machine set --memory 8192 --cpus 7 && podman machine start"
	if err := os.WriteFile(filepath.Join(dir, "podman-machine-undersized"), []byte(want+"\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	got, err := ReadDegradations()
	if err != nil {
		t.Fatalf("ReadDegradations: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected [%q], got %v", want, got)
	}
}
