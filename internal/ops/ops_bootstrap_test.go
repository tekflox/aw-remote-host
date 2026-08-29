package ops

import (
	"context"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
)

// stubRunModule swaps the package's module runner for one that records the
// modules a pass selected and reports every one of them healthy, so a test
// exercises the real Handler entry point without running an install script.
func stubRunModule(t *testing.T) *[]string {
	t.Helper()
	var ran []string
	prev := runModule
	runModule = func(_ context.Context, mod bootstrap.Module, _ bootstrap.RunOptions) bootstrap.ModuleStatus {
		ran = append(ran, mod.Name)
		return bootstrap.ModuleStatus{Module: mod.Name, AlreadyOK: true, OK: true}
	}
	t.Cleanup(func() { runModule = prev })
	return &ran
}

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// A full bootstrap means "every module this host is supposed to have", which
// is NOT the raw manifest — opt-in modules are excluded. This is the
// control-plane "bootstrap" verb's own call site (Dispatch -> Bootstrap ->
// runModules(full=true)); manifest_test.go only covers Manifest.Default() in
// isolation, so a Bootstrap that forgot to call it stayed green for a whole
// release. The failure it hides is total: vpn's install.sh exits 1 on the
// missing AW_VPN_LOGIN_SERVER that BootstrapOpts has no field for, and the
// loop turns that into a failed bootstrap even though every real module
// already came up.
func TestBootstrapSkipsOptionalModules(t *testing.T) {
	ran := stubRunModule(t)

	// Through Dispatch, not Bootstrap directly: "bootstrap" is a verb the
	// control plane sends over the /link tunnel, and the routing is part of
	// what regressed unnoticed.
	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, _ := collectEmits()
	if _, err := h.Dispatch(context.Background(), "bootstrap", nil, emit); err != nil {
		t.Fatalf("Dispatch(bootstrap): %v", err)
	}

	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}
	var optional, required []string
	for _, mod := range m.Modules {
		if mod.Optional {
			optional = append(optional, mod.Name)
		} else {
			required = append(required, mod.Name)
		}
	}
	if len(optional) == 0 {
		t.Fatal("manifest has no optional module — this test can no longer prove anything")
	}
	for _, name := range optional {
		if contains(*ran, name) {
			t.Errorf("full bootstrap ran optional module %q; ran=%v", name, *ran)
		}
	}
	for _, name := range required {
		if !contains(*ran, name) {
			t.Errorf("full bootstrap skipped required module %q; ran=%v", name, *ran)
		}
	}
}

// Reinstall/Update take the non-full path: workspace only, and an optional
// module must not sneak in there either.
func TestReinstallRunsWorkspaceModuleOnly(t *testing.T) {
	ran := stubRunModule(t)

	h := &Handler{Runner: newFakeRunner()}
	emit, _ := collectEmits()
	if _, err := h.Reinstall(context.Background(), BootstrapOpts{ExtractDir: t.TempDir()}, emit); err != nil {
		t.Fatalf("Reinstall: %v", err)
	}
	if len(*ran) != 1 || (*ran)[0] != "workspace" {
		t.Fatalf("Reinstall should run only the workspace module, ran=%v", *ran)
	}
}
