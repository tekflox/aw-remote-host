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
	// The default set — what a plain bootstrap installs. vpn is in the
	// manifest too but is opt-in, so it is deliberately absent here.
	want := []string{"podman", "postgres", "redis", "workspace"}
	got := m.Default()
	if len(got.Modules) != len(want) {
		t.Fatalf("expected %d default modules, got %d", len(want), len(got.Modules))
	}
	for i, name := range want {
		if got.Modules[i].Name != name {
			t.Errorf("module %d = %q, want %q (manifest order matters: podman before postgres/redis/workspace)", i, got.Modules[i].Name, name)
		}
	}
}

// Enrolling a machine in a network must never be a side effect of
// provisioning a workspace. If vpn ever loses its "optional" flag, every
// --with-workspace run starts trying to install tailscale and then fails the
// whole bootstrap on the pre-auth key it was never given.
func TestVPNModuleIsOptInOnly(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatal(err)
	}
	var vpn *Module
	for i := range m.Modules {
		if m.Modules[i].Name == "vpn" {
			vpn = &m.Modules[i]
		}
	}
	if vpn == nil {
		t.Fatal("the vpn module should be in the manifest")
	}
	if !vpn.Optional {
		t.Fatal("the vpn module must be optional")
	}
	for _, mod := range m.Default().Modules {
		if mod.Name == "vpn" {
			t.Fatal("Default() must not include vpn")
		}
	}
	// Naming a module IS the opt-in, so Only() has to reach it.
	if only := m.Only("vpn"); len(only.Modules) != 1 {
		t.Fatalf("Only(vpn) should still find it, got %+v", only.Modules)
	}
	// The root README promises nothing is fetched from an undisclosed
	// source. This module runs an upstream installer, so it has to say where.
	if vpn.Source == "" {
		t.Fatal("a module that does not install from the distro's own repositories must disclose its source")
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

func TestDefaultDropsOptionalModules(t *testing.T) {
	m := &Manifest{Modules: []Module{
		{Name: "podman"}, {Name: "workspace"}, {Name: "vpn", Optional: true},
	}}
	got := m.Default()
	if len(got.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %+v", got.Modules)
	}
	// Composes with Except in either order — the infra run does
	// Default().Except("workspace").
	if infra := got.Except("workspace"); len(infra.Modules) != 1 || infra.Modules[0].Name != "podman" {
		t.Fatalf("Default().Except(workspace): got %+v", infra.Modules)
	}
}

func TestInstallDetailDisclosesAnUpstreamSource(t *testing.T) {
	got := installDetail(Module{Name: "vpn", Package: "tailscale", Source: "https://tailscale.com/install.sh"})
	if got != "install package tailscale from https://tailscale.com/install.sh" {
		t.Fatalf("--plan has to name where a package comes from, got %q", got)
	}
}

// bootstrap/embed.go lists module directories by name rather than by
// wildcard, so a module added to manifest.json but not to that list compiles
// fine and then dies on the target machine with "script not found:
// .../vpn/install.sh". Found exactly that way on a real host, 2026-08-25 —
// which is one host too late.
func TestEveryManifestModuleIsEmbedded(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ExtractScripts(dir); err != nil {
		t.Fatal(err)
	}
	for _, mod := range m.Modules {
		for _, script := range []string{"install.sh", "verify.sh"} {
			path := moduleScriptPath(dir, mod.VerifyCommand, script)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("module %q: %s was not embedded — add its directory to the //go:embed line in bootstrap/embed.go", mod.Name, script)
			}
		}
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
