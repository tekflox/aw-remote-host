package ops

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/state"
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

// This is the control-plane path for incident:byod-postgres-lost-bind-mount-2026-09-02:
// the "bootstrap" verb, dispatched against a host whose running binary is
// older than the one that already bootstrapped it, must be refused rather
// than silently re-running every module from scratch.
func TestBootstrapRefusesADowngrade(t *testing.T) {
	ran := stubRunModule(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := state.RecordBootstrapVersion(statePath, "v0.1.72"); err != nil {
		t.Fatal(err)
	}

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{
		ExtractDir: t.TempDir(),
		StatePath:  statePath,
		CLIVersion: "v0.1.66",
	}}
	emit, _ := collectEmits()
	_, err := h.Dispatch(context.Background(), "bootstrap", nil, emit)
	if err == nil {
		t.Fatal("expected Dispatch(bootstrap) to refuse a downgrade")
	}
	if !strings.Contains(err.Error(), "v0.1.66") || !strings.Contains(err.Error(), "v0.1.72") {
		t.Fatalf("error should name both versions, got: %v", err)
	}
	if len(*ran) != 0 {
		t.Fatalf("no module should have run once the guard refused, ran=%v", *ran)
	}
}

// args["force"] must bypass the guard for exactly the one call it was set
// on — mirroring the CLI's --force flag.
func TestBootstrapForceArgBypassesTheGuard(t *testing.T) {
	ran := stubRunModule(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := state.RecordBootstrapVersion(statePath, "v0.1.72"); err != nil {
		t.Fatal(err)
	}

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{
		ExtractDir: t.TempDir(),
		StatePath:  statePath,
		CLIVersion: "v0.1.66",
	}}
	emit, _ := collectEmits()
	if _, err := h.Dispatch(context.Background(), "bootstrap", map[string]any{"force": true}, emit); err != nil {
		t.Fatalf("Dispatch(bootstrap) with force=true: %v", err)
	}
	if len(*ran) == 0 {
		t.Fatal("force=true should have let the manifest run")
	}
}

// A successful full bootstrap must record ITS OWN version, not just flip
// Provisioned once — an in-place upgrade has to move the recorded version
// forward too, or a later downgrade back to the PREVIOUS release would look
// like same-or-newer and slip past the guard.
func TestBootstrapRecordsItsOwnVersionOnSuccess(t *testing.T) {
	stubRunModule(t)
	statePath := filepath.Join(t.TempDir(), "state.json")

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{
		ExtractDir: t.TempDir(),
		StatePath:  statePath,
		CLIVersion: "v0.1.72",
	}}
	emit, _ := collectEmits()
	if _, err := h.Dispatch(context.Background(), "bootstrap", nil, emit); err != nil {
		t.Fatalf("Dispatch(bootstrap): %v", err)
	}

	st, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastBootstrapVersion != "v0.1.72" {
		t.Fatalf("LastBootstrapVersion = %q, want v0.1.72", st.LastBootstrapVersion)
	}
	if !st.Provisioned {
		t.Fatal("Provisioned should also be set true, as before this change")
	}
}
