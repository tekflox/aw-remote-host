package ops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner is an injectable Runner — records every invocation and returns
// scripted output/errors per command name, so tests never touch a real
// podman/curl/df binary.
type fakeRunner struct {
	calls   [][]string
	outputs map[string]string // "name arg1 arg2" -> output
	errs    map[string]error  // "name arg1 arg2" -> error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]string{}, errs: map[string]error{}}
}

func (f *fakeRunner) key(name string, args ...string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (f *fakeRunner) on(output string, name string, args ...string) {
	f.outputs[f.key(name, args...)] = output
}

func (f *fakeRunner) fail(err error, name string, args ...string) {
	f.errs[f.key(name, args...)] = err
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	k := f.key(name, args...)
	if err, ok := f.errs[k]; ok {
		return f.outputs[k], err
	}
	return f.outputs[k], nil
}

func collectEmits() (Emit, *[]string) {
	var lines []string
	return func(level, phase, message string) {
		lines = append(lines, fmt.Sprintf("%s/%s: %s", level, phase, message))
	}, &lines
}

func TestStopOK(t *testing.T) {
	r := newFakeRunner()
	h := &Handler{Runner: r}
	emit, lines := collectEmits()

	data, err := h.Stop(context.Background(), emit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["stopped"] != true {
		t.Errorf("expected stopped=true, got %v", data)
	}
	if len(r.calls) != 1 || r.calls[0][0] != "podman" || r.calls[0][1] != "stop" || r.calls[0][2] != WorkspaceContainer {
		t.Errorf("unexpected podman call: %v", r.calls)
	}
	if len(*lines) == 0 {
		t.Error("expected at least one activity emit")
	}
}

func TestStopFailurePropagatesError(t *testing.T) {
	r := newFakeRunner()
	r.fail(fmt.Errorf("no such container"), "podman", "stop", WorkspaceContainer)
	h := &Handler{Runner: r}
	emit, lines := collectEmits()

	_, err := h.Stop(context.Background(), emit)
	if err == nil {
		t.Fatal("expected an error when podman stop fails")
	}
	found := false
	for _, l := range *lines {
		if strings.HasPrefix(l, "error/stop:") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an error-level activity emit, got %v", *lines)
	}
}

func TestRestartOK(t *testing.T) {
	r := newFakeRunner()
	h := &Handler{Runner: r}
	data, err := h.Restart(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["restarted"] != true {
		t.Errorf("expected restarted=true, got %v", data)
	}
}

func TestWorkspaceImageUsesEnvironmentOverride(t *testing.T) {
	t.Setenv("AW_WORKSPACE_IMAGE", "localhost:5000/aw-workspace:e2e")

	if got := workspaceImage(); got != "localhost:5000/aw-workspace:e2e" {
		t.Fatalf("workspaceImage() = %q, want environment override", got)
	}
}

func TestWorkspaceImageFallsBackToDefault(t *testing.T) {
	t.Setenv("AW_WORKSPACE_IMAGE", " ")

	if got := workspaceImage(); got != WorkspaceImage {
		t.Fatalf("workspaceImage() = %q, want %q", got, WorkspaceImage)
	}
}

func TestWorkspaceImageForVersionPinsTag(t *testing.T) {
	t.Setenv("AW_WORKSPACE_IMAGE", "ghcr.io/fredericowu/aw-workspace:latest")

	if got := workspaceImageForVersion("abc1234"); got != "ghcr.io/fredericowu/aw-workspace:abc1234" {
		t.Fatalf("workspaceImageForVersion() = %q, want pinned tag", got)
	}
}

func TestWorkspaceImageForVersionPreservesDigest(t *testing.T) {
	t.Setenv("AW_WORKSPACE_IMAGE", "ghcr.io/fredericowu/aw-workspace@sha256:deadbeef")

	if got := workspaceImageForVersion("abc1234"); got != "ghcr.io/fredericowu/aw-workspace@sha256:deadbeef" {
		t.Fatalf("workspaceImageForVersion() = %q, want digest image unchanged", got)
	}
}

func TestPodmanPullArgsDisablesTLSForLocalhostRegistry(t *testing.T) {
	got := podmanPullArgs("localhost:5000/aw-workspace:e2e")
	want := []string{"pull", "--tls-verify=false", "localhost:5000/aw-workspace:e2e"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("podmanPullArgs(localhost) = %v, want %v", got, want)
	}
}

func TestPodmanPullArgsDisablesTLSForLocalhostRepository(t *testing.T) {
	got := podmanPullArgs("localhost/aw-workspace:e2e")
	want := []string{"pull", "--tls-verify=false", "localhost/aw-workspace:e2e"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("podmanPullArgs(localhost repository) = %v, want %v", got, want)
	}
}

func TestPodmanPullArgsKeepsDefaultRegistryStrict(t *testing.T) {
	got := podmanPullArgs("ghcr.io/fredericowu/aw-workspace:latest")
	want := []string{"pull", "ghcr.io/fredericowu/aw-workspace:latest"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("podmanPullArgs(ghcr) = %v, want %v", got, want)
	}
}

func TestSyncWorkspaceSourcePreservesRuntimeDataAndRemovesStaleFiles(t *testing.T) {
	dst := t.TempDir()
	src := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dst, ".aw-workspace", "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, ".aw-workspace", "apps", "keep.txt"), []byte("runtime"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "stale.py"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "src", "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "src", "api", "app.py"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := syncWorkspaceSource(src, dst); err != nil {
		t.Fatalf("syncWorkspaceSource failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".aw-workspace", "apps", "keep.txt")); err != nil {
		t.Fatalf("expected runtime data to survive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "stale.py")); !os.IsNotExist(err) {
		t.Fatalf("expected stale source file to be removed, got err=%v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "src", "api", "app.py"))
	if err != nil {
		t.Fatalf("expected new source file: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("unexpected copied source content: %q", got)
	}
}

func TestUninstallRemovesAllContainersAndVolumes(t *testing.T) {
	r := newFakeRunner()
	h := &Handler{Runner: r}

	data, err := h.Uninstall(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["uninstalled"] != true {
		t.Errorf("expected uninstalled=true, got %v", data)
	}

	wantRemoved := map[string]bool{
		WorkspaceContainer: false, PostgresContainer: false, RedisContainer: false,
	}
	wantVolRemoved := map[string]bool{PostgresVolume: false, RedisVolume: false}
	for _, call := range r.calls {
		if len(call) >= 3 && call[0] == "podman" && call[1] == "rm" {
			wantRemoved[call[3]] = true
		}
		if len(call) >= 5 && call[0] == "podman" && call[1] == "volume" && call[2] == "rm" {
			wantVolRemoved[call[4]] = true
		}
	}
	for name, seen := range wantRemoved {
		if !seen {
			t.Errorf("expected podman rm -f %s to have been called", name)
		}
	}
	for name, seen := range wantVolRemoved {
		if !seen {
			t.Errorf("expected podman volume rm -f %s to have been called", name)
		}
	}
}

func TestUninstallReportsPartialFailure(t *testing.T) {
	r := newFakeRunner()
	r.fail(fmt.Errorf("boom"), "podman", "rm", "-f", PostgresContainer)
	h := &Handler{Runner: r}

	_, err := h.Uninstall(context.Background(), nil)
	if err == nil {
		t.Fatal("expected an error when one container removal fails")
	}
	if !strings.Contains(err.Error(), PostgresContainer) {
		t.Errorf("expected error to mention %s, got %v", PostgresContainer, err)
	}
}

func TestHealthOfflineWhenContainerNotRunning(t *testing.T) {
	r := newFakeRunner()
	r.fail(fmt.Errorf("no such container"), "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	h := &Handler{Runner: r}

	got := h.Health(context.Background())
	if got["offline"] != true || got["healthy"] != false {
		t.Errorf("expected offline result, got %v", got)
	}
	for _, key := range []string{"uptime_s", "disk", "cpu_pct", "mem"} {
		if got[key] != nil {
			t.Errorf("expected %s to be nil when offline, got %v", key, got[key])
		}
	}
}

func TestHealthOfflineWhenContainerStopped(t *testing.T) {
	r := newFakeRunner()
	r.on("false\t2026-07-20T10:00:00.000000000Z", "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	h := &Handler{Runner: r}

	got := h.Health(context.Background())
	if got["offline"] != true {
		t.Errorf("expected offline=true for a stopped container, got %v", got)
	}
}

func TestHealthRunningAndHTTPHealthy(t *testing.T) {
	r := newFakeRunner()
	r.on("true\t2020-01-01T00:00:00.000000000Z", "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	r.on("", "curl", "-fsS", "--max-time", probeTimeout, HealthURL)
	r.on("12.5%\t123.4MiB / 987.6MiB", "podman", "stats", "--no-stream", "--format",
		"{{.CPUPerc}}\t{{.MemUsage}}", WorkspaceContainer)
	r.on("Filesystem 1024-blocks Used Available Capacity Mounted\n"+
		"/dev/disk1 1000000 400000 600000 40% /", "df", "-Pk", "/")
	h := &Handler{Runner: r}

	got := h.Health(context.Background())
	if got["offline"] != false || got["healthy"] != true {
		t.Errorf("expected online+healthy, got %v", got)
	}
	uptime, ok := got["uptime_s"].(int64)
	if !ok || uptime <= 0 {
		t.Errorf("expected a positive uptime_s, got %v", got["uptime_s"])
	}
	cpu, ok := got["cpu_pct"].(float64)
	if !ok || cpu != 12.5 {
		t.Errorf("expected cpu_pct=12.5, got %v", got["cpu_pct"])
	}
	mem, ok := got["mem"].(map[string]any)
	if !ok {
		t.Fatalf("expected mem map, got %v", got["mem"])
	}
	wantUsedF := 123.4 * 1024 * 1024
	wantUsed := int64(wantUsedF)
	if mem["used"] != wantUsed {
		t.Errorf("expected mem.used=%d, got %v", wantUsed, mem["used"])
	}
	disk, ok := got["disk"].(map[string]any)
	if !ok {
		t.Fatalf("expected disk map, got %v", got["disk"])
	}
	if disk["total"] != int64(1000000*1024) || disk["used"] != int64(400000*1024) {
		t.Errorf("unexpected disk usage: %v", disk)
	}
}

func TestHealthKeepsSemverWorkspaceVersion(t *testing.T) {
	r := newFakeRunner()
	r.on("true\t2020-01-01T00:00:00.000000000Z", "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	r.on(`{"status":"ok","version":"v0.12.10"}`, "curl", "-fsS", "--max-time", probeTimeout, HealthURL)
	h := &Handler{Runner: r}

	got := h.Health(context.Background())
	if got["workspace_version"] != "v0.12.10" {
		t.Errorf("expected full semver workspace_version, got %v", got["workspace_version"])
	}
}

func TestHealthShortensLongSHAWorkspaceVersion(t *testing.T) {
	r := newFakeRunner()
	r.on("true\t2020-01-01T00:00:00.000000000Z", "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	r.on(`{"status":"ok","version":"abcdef1234567890"}`, "curl", "-fsS", "--max-time", probeTimeout, HealthURL)
	h := &Handler{Runner: r}

	got := h.Health(context.Background())
	if got["workspace_version"] != "abcdef1" {
		t.Errorf("expected shortened SHA workspace_version, got %v", got["workspace_version"])
	}
}

func TestHealthWhenHTTPProbeFails(t *testing.T) {
	r := newFakeRunner()
	r.on("true\t2020-01-01T00:00:00.000000000Z", "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	r.fail(fmt.Errorf("connection refused"), "curl", "-fsS", "--max-time", probeTimeout, HealthURL)
	h := &Handler{Runner: r}

	got := h.Health(context.Background())
	if got["offline"] != false {
		t.Errorf("expected offline=false (container is running, just unhealthy), got %v", got)
	}
	if got["healthy"] != false {
		t.Errorf("expected healthy=false when the HTTP probe fails, got %v", got)
	}
}

func TestParseBytes(t *testing.T) {
	mib := 123.4 * 1024 * 1024
	cases := map[string]int64{
		// IEC binary suffixes (docker)
		"123.4MiB": int64(mib),
		"1GiB":     1024 * 1024 * 1024,
		"512KiB":   512 * 1024,
		"10B":      10,
		// SI decimal suffixes (podman) — "GB"/"MB" must match before bare "B"
		"45.2MB":  int64(45.2 * 1e6),
		"7.657GB": int64(7.657 * 1e9),
		"512KB":   512 * 1e3,
		"1TB":     1e12,
	}
	for raw, want := range cases {
		got, ok := parseBytes(raw)
		if !ok {
			t.Errorf("parseBytes(%q): expected ok=true", raw)
			continue
		}
		if got != want {
			t.Errorf("parseBytes(%q) = %d, want %d", raw, got, want)
		}
	}
	if _, ok := parseBytes("garbage"); ok {
		t.Error("expected parseBytes to fail on an unrecognized unit")
	}
}

func TestParseMemUsage(t *testing.T) {
	mib := func(v float64) int64 { return int64(v * 1024 * 1024) }
	gib := func(v float64) int64 { return int64(v * 1024 * 1024 * 1024) }
	cases := []struct {
		raw               string
		wantUsed, wantTot int64
	}{
		{"45.2MB / 7.657GB", int64(45.2 * 1e6), int64(7.657 * 1e9)}, // podman/SI
		{"45.2MiB / 7.5GiB", mib(45.2), gib(7.5)},                   // docker/IEC
	}
	for _, c := range cases {
		used, total, ok := parseMemUsage(c.raw)
		if !ok {
			t.Errorf("parseMemUsage(%q): expected ok=true", c.raw)
			continue
		}
		if used != c.wantUsed || total != c.wantTot {
			t.Errorf("parseMemUsage(%q) = (%d, %d), want (%d, %d)", c.raw, used, total, c.wantUsed, c.wantTot)
		}
	}
}

func TestDispatchUnknownVerb(t *testing.T) {
	h := &Handler{Runner: newFakeRunner()}
	_, err := h.Dispatch(context.Background(), "frobnicate", nil, nil)
	if err == nil {
		t.Fatal("expected an error for an unknown verb")
	}
}

func TestDispatchRoutesToStop(t *testing.T) {
	r := newFakeRunner()
	h := &Handler{Runner: r}
	data, err := h.Dispatch(context.Background(), "stop", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok || m["stopped"] != true {
		t.Errorf("expected {stopped:true}, got %v", data)
	}
}

func TestSelfUpdateInstallsRequestedVersion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_REMOTE_HOST_SKIP_SERVICE_RESTART", "1")
	t.Setenv("AW_REMOTE_HOST_SKIP_ROLLBACK_MONITOR", "1")
	r := newFakeRunner()
	h := &Handler{Runner: r, Opts: BootstrapOpts{WorkspaceSlug: "demo"}}

	data, err := h.SelfUpdate(context.Background(), map[string]any{"version": "build-abc1234"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["updated"] != true || data["version"] != "build-abc1234" || data["rollback_armed"] != true {
		t.Fatalf("unexpected self-update result: %v", data)
	}
	if len(r.calls) != 1 || r.calls[0][0] != "sh" || r.calls[0][1] != "-c" {
		t.Fatalf("unexpected install command: %v", r.calls)
	}
	cmd := r.calls[0][2]
	if !strings.Contains(cmd, "AW_REMOTE_HOST_VERSION='build-abc1234'") {
		t.Fatalf("install command does not pin requested version: %s", cmd)
	}
	if !strings.Contains(cmd, "AW_REMOTE_HOST_INSTALL_DIR=") {
		t.Fatalf("install command does not pin install dir: %s", cmd)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".aw-remote-host", "self-update", "pending.json")); err != nil {
		t.Fatalf("expected pending rollback marker: %v", err)
	}
}

func TestDispatchRoutesToSelfUpdate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_REMOTE_HOST_SKIP_SERVICE_RESTART", "1")
	t.Setenv("AW_REMOTE_HOST_SKIP_ROLLBACK_MONITOR", "1")
	r := newFakeRunner()
	h := &Handler{Runner: r}
	data, err := h.Dispatch(context.Background(), "self-update", map[string]any{"version": "build-def5678"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok || m["version"] != "build-def5678" {
		t.Errorf("expected self-update result, got %v", data)
	}
}

func TestDispatchRoutesToHealth(t *testing.T) {
	r := newFakeRunner()
	r.fail(fmt.Errorf("no such container"), "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	h := &Handler{Runner: r}
	data, err := h.Dispatch(context.Background(), "health", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok || m["offline"] != true {
		t.Errorf("expected offline health result, got %v", data)
	}
}
