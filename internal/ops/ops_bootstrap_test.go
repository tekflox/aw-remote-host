package ops

import (
	"context"
	"fmt"
	"os"
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

// copyingRunner wraps fakeRunner and makes the "podman cp" call that seeds
// Update()'s staging dir actually write files — a real redeploy's `podman
// cp` populates that dir for real, and Update's post-sync chown scoping
// (core:workspace-redeploy-chowns-app-data-dirs) is only exercised if
// syncWorkspaceSource has real entries to read there.
type copyingRunner struct {
	*fakeRunner
}

func (c *copyingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "podman" && len(args) == 3 && args[0] == "cp" {
		dst := args[2]
		if err := os.MkdirAll(filepath.Join(dst, "src"), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dst, "src", "app.py"), []byte("new"), 0o644); err != nil {
			return "", err
		}
	}
	return c.fakeRunner.Run(ctx, name, args...)
}

// TestUpdateScopesPostSyncChownToSyncedEntriesOnly is the regression test for
// core:workspace-redeploy-chowns-app-data-dirs: Update() used to chown -R the
// entire host bind-mount after syncing the freshly-pulled source in, sweeping
// .aw-workspace/data/<app> (each Tier-2 app's own bind-mounted /config,
// living outside syncWorkspaceSource's own writes) right along with it on
// every redeploy. The chown must now be scoped to exactly the entries
// syncWorkspaceSource wrote.
func TestUpdateScopesPostSyncChownToSyncedEntriesOnly(t *testing.T) {
	stubRunModule(t)

	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	appData := filepath.Join(hostDir, ".aw-workspace", "data", "blender")
	if err := os.MkdirAll(appData, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(appData, "marker")
	if err := os.WriteFile(marker, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, _ := collectEmits()

	if _, err := h.Update(context.Background(), h.Opts, nil, emit); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected app data dir to survive untouched: %v", err)
	}

	var chownCall []string
	for _, call := range r.calls {
		for _, a := range call {
			if a == "chown" {
				chownCall = call
				break
			}
		}
	}
	if chownCall == nil {
		t.Fatalf("expected a chown call, calls=%v", r.calls)
	}
	for _, a := range chownCall {
		if a == hostDir {
			t.Fatalf("chown call must not target the whole hostDir directly, call=%v", chownCall)
		}
		if strings.Contains(a, ".aw-workspace") {
			t.Fatalf("chown call must never reference .aw-workspace, call=%v", chownCall)
		}
	}
	wantTarget := filepath.Join(hostDir, "src")
	found := false
	for _, a := range chownCall {
		if a == wantTarget {
			found = true
		}
	}
	if !found {
		t.Fatalf("chown call should target the synced entry %q, call=%v", wantTarget, chownCall)
	}
}

// TestUpdateRefusesWhenHostHeadIsAheadOfImage is the regression test for
// aw-workspace:host-tree-reverted-by-stale-image-sync: Update() used to sync
// the freshly-pulled image's baked source over the host tree with no check
// at all, silently reverting committed host work when the host had moved
// ahead of whatever commit the image was built from. The image's own commit
// is provably an ancestor of the host's HEAD here (a real "host is ahead"
// case), so Update() must refuse rather than sync.
func TestUpdateRefusesWhenHostHeadIsAheadOfImage(t *testing.T) {
	stubRunModule(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	r.on("hostsha123", "git", "-C", hostDir, "rev-parse", "HEAD")
	r.on("AW_WORKSPACE_VERSION=imagesha456", "podman", "image", "inspect",
		WorkspaceImage, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
	r.on("", "git", "-C", hostDir, "merge-base", "--is-ancestor", "imagesha456", "hostsha123")

	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	_, err := h.Update(context.Background(), h.Opts, nil, emit)
	if err == nil {
		t.Fatal("expected Update to refuse when host HEAD is ahead of the image")
	}
	if !strings.Contains(err.Error(), "hostsha123") || !strings.Contains(err.Error(), "imagesha456") {
		t.Fatalf("error should name both commits, got: %v", err)
	}
	for _, call := range r.calls {
		if len(call) >= 2 && call[0] == "podman" && call[1] == "cp" {
			t.Fatalf("must not have staged the image source once the guard refused, calls=%v", r.calls)
		}
	}
	found := false
	for _, l := range *lines {
		if strings.Contains(l, "error/update") && strings.Contains(l, "refusing to sync") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a loud error/update emit, got lines=%v", *lines)
	}
}

// force=true must bypass the ahead-of-image guard for an intentional
// rollback, mirroring the bootstrap downgrade guard's own force arg.
func TestUpdateForceArgBypassesTheAheadOfImageGuard(t *testing.T) {
	stubRunModule(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	r.on("hostsha123", "git", "-C", hostDir, "rev-parse", "HEAD")
	r.on("AW_WORKSPACE_VERSION=imagesha456", "podman", "image", "inspect",
		WorkspaceImage, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
	r.on("", "git", "-C", hostDir, "merge-base", "--is-ancestor", "imagesha456", "hostsha123")

	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, _ := collectEmits()

	if _, err := h.Update(context.Background(), h.Opts, map[string]any{"force": true}, emit); err != nil {
		t.Fatalf("Update with force=true: %v", err)
	}
	staged := false
	for _, call := range r.calls {
		if len(call) >= 2 && call[0] == "podman" && call[1] == "cp" {
			staged = true
		}
	}
	if !staged {
		t.Fatal("force=true should have let the sync proceed")
	}
}

// When the image's commit can't be placed in the host's own git history at
// all (shallow clone, unrelated history — merge-base errors rather than
// answering "no"), the guard cannot prove the host is ahead. It must not
// block a legitimate update on that uncertainty — it can only refuse a
// PROVEN case.
func TestUpdateProceedsWhenAncestryCannotBeDetermined(t *testing.T) {
	stubRunModule(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	r.on("hostsha123", "git", "-C", hostDir, "rev-parse", "HEAD")
	r.on("AW_WORKSPACE_VERSION=imagesha456", "podman", "image", "inspect",
		WorkspaceImage, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
	r.fail(fmt.Errorf("fatal: not a valid object name"),
		"git", "-C", hostDir, "merge-base", "--is-ancestor", "imagesha456", "hostsha123")

	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	if _, err := h.Update(context.Background(), h.Opts, nil, emit); err != nil {
		t.Fatalf("Update should proceed when ancestry is undeterminable: %v", err)
	}
	found := false
	for _, l := range *lines {
		if strings.Contains(l, "warning/update") && strings.Contains(l, "could not confirm") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a loud warning/update emit, got lines=%v", *lines)
	}
}
