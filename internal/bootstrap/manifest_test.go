package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifest(t *testing.T) {
	m, err := LoadManifest(filepath.Join("..", "..", "bootstrap", "manifest.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.Modules) == 0 {
		t.Fatal("expected at least one module")
	}
	for _, mod := range m.Modules {
		if mod.Name == "" {
			t.Error("module with empty name")
		}
		if mod.VerifyCommand == "" {
			t.Errorf("module %q has no verify_command", mod.Name)
		}
	}
}

func TestLoadEmbeddedManifest(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}
	want := []string{"podman", "postgres", "redis", "workspace"}
	if len(m.Modules) != len(want) {
		t.Fatalf("expected %d modules, got %d", len(want), len(m.Modules))
	}
	for i, name := range want {
		if m.Modules[i].Name != name {
			t.Errorf("module %d = %q, want %q (manifest order matters: podman before postgres/redis/workspace)", i, m.Modules[i].Name, name)
		}
	}
}

func TestPlan(t *testing.T) {
	m := &Manifest{Modules: []Module{
		{Name: "redis", Version: "7", Image: "docker.io/library/redis", Digest: "sha256:abc", VerifyCommand: "bootstrap/redis/verify.sh"},
	}}
	actions := Plan(m)
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions (detect/install/verify), got %d", len(actions))
	}
	if actions[1].Detail != "pull docker.io/library/redis@sha256:abc" {
		t.Errorf("unexpected install detail: %q", actions[1].Detail)
	}
}

func TestExceptAndOnly(t *testing.T) {
	m := &Manifest{Modules: []Module{
		{Name: "podman"}, {Name: "postgres"}, {Name: "redis"}, {Name: "workspace"},
	}}

	infra := m.Except("workspace")
	if len(infra.Modules) != 3 {
		t.Fatalf("Except(workspace): expected 3 modules, got %d", len(infra.Modules))
	}
	for _, mod := range infra.Modules {
		if mod.Name == "workspace" {
			t.Error("Except(workspace) should have dropped it")
		}
	}

	ws := m.Only("workspace")
	if len(ws.Modules) != 1 || ws.Modules[0].Name != "workspace" {
		t.Fatalf("Only(workspace): got %+v", ws.Modules)
	}
}

func TestExtractScriptsMakesShellScriptsExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractScripts(dir); err != nil {
		t.Fatalf("ExtractScripts: %v", err)
	}
	path := filepath.Join(dir, "redis", "verify.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode()&0o100 == 0 {
		t.Errorf("%s: expected executable bit set, got mode %v", path, info.Mode())
	}
	// manifest.json is parsed straight from the embed, not written to disk.
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); !os.IsNotExist(err) {
		t.Errorf("expected manifest.json NOT to be extracted, stat err = %v", err)
	}
}
