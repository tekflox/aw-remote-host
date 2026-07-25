package bootstrap

import (
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

func TestRunPlanMode(t *testing.T) {
	m := &Manifest{Modules: []Module{{Name: "x", VerifyCommand: "v"}}}
	if err := Run(m, true); err != nil {
		t.Errorf("Run(plan=true) should not error, got %v", err)
	}
	if err := Run(m, false); err == nil {
		t.Error("Run(plan=false) should error until card 4 implements it")
	}
}
