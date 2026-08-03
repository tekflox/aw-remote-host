// Package ops implements the lifecycle/health verbs dispatched over the
// /link tunnel's "cmd" frames (see internal/link's cmd/cmd_result handling
// and aw-backend's src/api/placement/remote_host_driver.py, the control-
// plane side that sends them). Every verb shells out to podman against the
// same container/volume names bootstrap/{postgres,redis,workspace}/install.sh
// create, so a control-plane-issued "stop" is exactly what a user typing
// `podman stop aw-remote-host-workspace` themselves would do.
package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/updater"
)

const (
	WorkspaceContainer = "aw-remote-host-workspace"
	WorkspaceImage     = "ghcr.io/fredericowu/aw-workspace:latest"
	ContainerWorkdir   = "/opt/aw-workspace"
	PostgresContainer  = "aw-remote-host-postgres"
	RedisContainer     = "aw-remote-host-redis"
	PostgresVolume     = "aw-remote-host-postgres-data"
	RedisVolume        = "aw-remote-host-redis-data"
	HealthURL          = "http://127.0.0.1:9030/api/health"

	// WorkspaceUID/WorkspaceGID match the `ubuntu` user the image's
	// Dockerfile creates (useradd -u 1001 -g 1001) and runs the workspace
	// process as. hostDir is a plain (non-idmapped) bind mount, so whatever
	// numeric owner lands on the host is exactly what the container sees —
	// anything copied/written here as this host's own user (root or
	// otherwise, via a `--user` systemd unit) must be rechowned to 1001 or
	// the container's `ubuntu` loses write access to its own tree.
	WorkspaceUID = "1001"
	WorkspaceGID = "1001"

	probeTimeout = "5"
)

// Runner abstracts the podman/curl/df shellouts so tests can inject a fake
// instead of touching a real container runtime.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (output string, err error)
}

// execRunner is the production Runner — a real os/exec shellout.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// DefaultRunner is the production Runner (real shellouts).
var DefaultRunner Runner = execRunner{}

// Emit sends an unsolicited activity event back over the /link tunnel —
// wired to link.go's frameWriter by whoever constructs a Handler.
type Emit func(level, phase, message string)

func noopEmit(string, string, string) {}

// BootstrapOpts carries what Bootstrap/Reinstall need to re-run the module
// manifest — the same values runBootstrapWorkspace (cmd/aw-remote-host)
// already assembles for the CLI's own first-run path.
type BootstrapOpts struct {
	ExtractDir       string
	WorkspaceSlug    string
	PostgresPassword string
	ControlPlane     string
	HostCredential   string
}

// Handler executes lifecycle/health verbs against the local podman runtime.
// DataDir defaults to "/" (disk usage is a rough host-level signal, not a
// precise per-workspace quota) if left empty.
type Handler struct {
	Runner  Runner
	DataDir string
	Opts    BootstrapOpts // used by the reinstall/bootstrap verbs — see Dispatch
}

// Dispatch executes one verb ("stop"|"restart"|"reinstall"|"bootstrap"|"update"|
// "self-update"|"uninstall"|"health"|"exec_start"|"exec_status"|"exec_wait"|
// "exec_kill"|"list_processes") — the switchboard link.go's cmd-frame handling
// calls into. args carries optional per-verb parameters such as the exact
// aw-workspace image version to install for workspace updates, or the shell
// command/timeout/job_id the exec_* verbs take (see ops_exec.go).
func (h *Handler) Dispatch(ctx context.Context, verb string, args map[string]any, emit Emit) (any, error) {
	switch verb {
	case "stop":
		return h.Stop(ctx, emit)
	case "restart":
		return h.Restart(ctx, emit)
	case "uninstall":
		return h.Uninstall(ctx, emit)
	case "reinstall":
		return h.Reinstall(ctx, h.Opts, emit)
	case "bootstrap":
		return h.Bootstrap(ctx, h.Opts, emit)
	case "update":
		return h.Update(ctx, h.Opts, args, emit)
	case "self-update":
		return h.SelfUpdate(ctx, args, emit)
	case "health":
		return h.Health(ctx), nil
	case "exec_start":
		return h.ExecStart(ctx, args, emit)
	case "exec_status":
		return h.ExecStatus(ctx, args)
	case "exec_wait":
		return h.ExecWait(ctx, args)
	case "exec_kill":
		return h.ExecKill(ctx, args, emit)
	case "list_processes":
		return h.ListProcesses(ctx), nil
	default:
		return nil, fmt.Errorf("unknown verb %q", verb)
	}
}

func (h *Handler) runner() Runner {
	if h.Runner != nil {
		return h.Runner
	}
	return DefaultRunner
}

func (h *Handler) dataDir() string {
	if h.DataDir != "" {
		return h.DataDir
	}
	return "/"
}

func workspaceImage() string {
	if image := strings.TrimSpace(os.Getenv("AW_WORKSPACE_IMAGE")); image != "" {
		return image
	}
	return WorkspaceImage
}

func workspaceImageForVersion(version string) string {
	image := workspaceImage()
	version = strings.TrimSpace(version)
	if version == "" {
		return image
	}
	if at := strings.Index(image, "@"); at >= 0 {
		return image
	}
	if colon := strings.LastIndex(image, ":"); colon >= 0 && !strings.Contains(image[colon+1:], "/") {
		return image[:colon+1] + version
	}
	return image + ":" + version
}

func commandError(prefix string, err error, out string) error {
	msg := strings.TrimSpace(out)
	if msg == "" {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w: %s", prefix, err, msg)
}

func podmanPullArgs(image string) []string {
	args := []string{"pull"}
	if strings.HasPrefix(image, "localhost/") ||
		strings.HasPrefix(image, "localhost:") ||
		strings.HasPrefix(image, "127.0.0.1/") ||
		strings.HasPrefix(image, "127.0.0.1:") {
		args = append(args, "--tls-verify=false")
	}
	return append(args, image)
}

// Stop stops the workspace container. Idempotent — podman stop on an
// already-stopped/missing container just returns non-zero, which is
// reported as an error to the caller (same as the docker driver's
// container.stop() would raise on a missing container).
func (h *Handler) Stop(ctx context.Context, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	emit("info", "stop", "stopping workspace container")
	if _, err := h.runner().Run(ctx, "podman", "stop", WorkspaceContainer); err != nil {
		emit("error", "stop", "stop failed: "+err.Error())
		return nil, fmt.Errorf("podman stop %s: %w", WorkspaceContainer, err)
	}
	emit("info", "stop", "workspace container stopped")
	return map[string]any{"stopped": true}, nil
}

// Restart restarts the workspace container in place.
func (h *Handler) Restart(ctx context.Context, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	emit("info", "restart", "restarting workspace container")
	if _, err := h.runner().Run(ctx, "podman", "restart", WorkspaceContainer); err != nil {
		emit("error", "restart", "restart failed: "+err.Error())
		return nil, fmt.Errorf("podman restart %s: %w", WorkspaceContainer, err)
	}
	emit("info", "restart", "workspace container restarted")
	return map[string]any{"restarted": true}, nil
}

// Uninstall permanently tears down the workspace runtime AND its data —
// stops/removes all three containers (workspace, postgres, redis) and the
// postgres/redis data volumes. Mirrors docker_driver.uninstall's
// destructive contract; unlike stop/restart this is not meant to be
// reversible via a later bootstrap.
func (h *Handler) Uninstall(ctx context.Context, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	emit("warning", "uninstall", "removing workspace runtime and data")
	var errs []string
	for _, name := range []string{WorkspaceContainer, PostgresContainer, RedisContainer} {
		_, _ = h.runner().Run(ctx, "podman", "stop", name)
		if _, err := h.runner().Run(ctx, "podman", "rm", "-f", name); err != nil {
			errs = append(errs, fmt.Sprintf("remove container %s: %v", name, err))
		}
	}
	for _, vol := range []string{PostgresVolume, RedisVolume} {
		if _, err := h.runner().Run(ctx, "podman", "volume", "rm", "-f", vol); err != nil {
			errs = append(errs, fmt.Sprintf("remove volume %s: %v", vol, err))
		}
	}
	if len(errs) > 0 {
		emit("error", "uninstall", strings.Join(errs, "; "))
		return nil, fmt.Errorf("uninstall: %s", strings.Join(errs, "; "))
	}
	emit("info", "uninstall", "workspace runtime and data removed")
	return map[string]any{"uninstalled": true}, nil
}

// Reinstall recreates the workspace container from the image while leaving
// postgres/redis (and their data) untouched — a fresh runtime, not a fresh
// workspace, matching docker_driver.reinstall's contract.
func (h *Handler) Reinstall(ctx context.Context, opts BootstrapOpts, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	emit("info", "reinstall", "removing workspace container for a fresh recreate")
	_, _ = h.runner().Run(ctx, "podman", "rm", "-f", WorkspaceContainer)
	return h.runModules(ctx, opts, false, emit)
}

// Update pulls the latest aw-workspace image, syncs the baked source tree into
// the host bind-mount, and recreates the workspace container. Mutable runtime
// state under .aw-workspace is preserved; source files are replaced so deletes
// in the image actually take effect on already-installed hosts.
func (h *Handler) Update(ctx context.Context, opts BootstrapOpts, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	hostDir, err := workspaceHostDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace host dir %s: %w", hostDir, err)
	}

	version, _ := args["version"].(string)
	version = strings.TrimSpace(version)
	image := workspaceImageForVersion(version)
	if version != "" {
		emit("info", "update", "pulling aw-workspace image "+version)
	} else {
		emit("info", "update", "pulling latest aw-workspace image")
	}
	if out, err := h.runner().Run(ctx, "podman", podmanPullArgs(image)...); err != nil {
		pullErr := commandError("podman pull "+image, err, out)
		if _, existsErr := h.runner().Run(ctx, "podman", "image", "exists", image); existsErr == nil {
			emit("warning", "update", "image pull failed; using existing local image "+image)
		} else {
			if strings.HasPrefix(image, "ghcr.io/") {
				_, _ = h.runner().Run(ctx, "podman", "logout", "ghcr.io")
				if out, retryErr := h.runner().Run(ctx, "podman", podmanPullArgs(image)...); retryErr == nil {
					err = nil
				} else {
					pullErr = commandError("podman pull "+image, retryErr, out)
				}
			}
			if err != nil && version != "" {
				latestImage := workspaceImage()
				if latestImage != image {
					emit("warning", "update", "pinned image pull failed; trying "+latestImage)
					if out, latestErr := h.runner().Run(ctx, "podman", podmanPullArgs(latestImage)...); latestErr == nil {
						image = latestImage
						err = nil
					} else {
						pullErr = commandError("podman pull "+latestImage, latestErr, out)
					}
				}
			}
			if err != nil {
				emit("error", "update", "image pull failed: "+pullErr.Error())
				return nil, pullErr
			}
		}
	}

	staging := filepath.Join(hostDir, fmt.Sprintf(".aw-workspace-update-%d", time.Now().UnixNano()))
	if err := os.RemoveAll(staging); err != nil {
		return nil, fmt.Errorf("remove stale staging dir: %w", err)
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(staging)

	seedContainer := WorkspaceContainer + "-update"
	_, _ = h.runner().Run(ctx, "podman", "rm", "-f", seedContainer)
	if _, err := h.runner().Run(ctx, "podman", "create", "--name", seedContainer, image); err != nil {
		return nil, fmt.Errorf("podman create update seed: %w", err)
	}
	defer h.runner().Run(ctx, "podman", "rm", "-f", seedContainer)

	emit("info", "update", "copying workspace source from image")
	if _, err := h.runner().Run(ctx, "podman", "cp", seedContainer+":"+ContainerWorkdir+"/.", staging); err != nil {
		return nil, fmt.Errorf("podman cp workspace source: %w", err)
	}
	if err := syncWorkspaceSource(staging, hostDir); err != nil {
		return nil, err
	}
	// copyPath (inside syncWorkspaceSource) writes as this process's own
	// user, which leaves the just-synced entries owned by someone the
	// `ubuntu` user inside the container can't write to. Two cases:
	//
	//   - This process runs as host root (a privileged container/rootFUL
	//     podman host, e.g. this project's own aw-remote-host deployment —
	//     confirmed live 2026-08-03, `podman info` reports Rootless=false
	//     here): a plain `chown -R` lands directly, no user-namespace tricks
	//     needed or possible.
	//   - This process runs unprivileged (a `--user` systemd unit on a
	//     rootless-podman host): host root can't chown at all, but
	//     `podman unshare chown` runs inside this user's own rootless
	//     user-namespace mapping, landing as the UID the container's
	//     `ubuntu` resolves to.
	//
	// Found live 2026-08-03: this always used the rootless path, which
	// fails outright ("must be run with rootless") on a rootFUL host —
	// silently swallowed as a best-effort warning, leaving every synced
	// entry root-owned and unwritable by the workspace's own `ubuntu`
	// process (surfaced as "Permission denied" installing any app).
	chownArgs := []string{"unshare", "chown", "-R", WorkspaceUID + ":" + WorkspaceGID, hostDir}
	chownLabel := "podman unshare chown"
	if os.Geteuid() == 0 {
		chownArgs = []string{"-R", WorkspaceUID + ":" + WorkspaceGID, hostDir}
		chownLabel = "chown"
		if out, err := h.runner().Run(ctx, "chown", chownArgs...); err != nil {
			emit("warning", "update", "could not normalize workspace ownership: "+commandError(chownLabel, err, out).Error())
		}
	} else if out, err := h.runner().Run(ctx, "podman", chownArgs...); err != nil {
		emit("warning", "update", "could not normalize workspace ownership: "+commandError(chownLabel, err, out).Error())
	}

	emit("info", "update", "recreating workspace container")
	_, _ = h.runner().Run(ctx, "podman", "rm", "-f", WorkspaceContainer)
	if _, err := h.runModulesWithEnv(ctx, opts, false, emit, []string{"AW_WORKSPACE_IMAGE=" + image}); err != nil {
		return nil, err
	}
	emit("info", "update", "workspace code updated")
	data := map[string]any{"updated": true}
	if version != "" {
		data["version"] = version
	}
	return data, nil
}

// SelfUpdate installs the requested aw-remote-host release through the public
// installer, then asks the platform service manager to restart this process.
// The restart is started after the command reply has been written back to the
// control plane so the caller gets a deterministic result instead of losing
// the tunnel mid-frame.
func (h *Handler) SelfUpdate(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	version, _ := args["version"].(string)
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}

	emit("info", "self-update", "installing aw-remote-host "+version)
	currentPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve current executable: %w", err)
	}
	if currentPath, err = filepath.Abs(currentPath); err != nil {
		return nil, fmt.Errorf("resolve current executable path: %w", err)
	}
	pending, err := updater.Prepare(currentPath, version, h.Opts.WorkspaceSlug)
	if err != nil {
		return nil, err
	}
	installDir := updater.InstallDirFor(currentPath)
	installCmd := fmt.Sprintf(
		"curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | AW_REMOTE_HOST_VERSION=%s AW_REMOTE_HOST_INSTALL_DIR=%s sh",
		updater.ShellQuote(version),
		updater.ShellQuote(installDir),
	)
	if out, err := h.runner().Run(ctx, "sh", "-c", installCmd); err != nil {
		emit("error", "self-update", "install failed: "+err.Error())
		_ = updater.ClearPending()
		return nil, fmt.Errorf("install aw-remote-host %s: %w: %s", version, err, strings.TrimSpace(out))
	}

	if err := updater.StartRollbackMonitor(pending, updater.DefaultValidationTimeout); err != nil {
		emit("warning", "self-update", "installed but rollback monitor was not scheduled: "+err.Error())
	}
	if err := restartHostServiceSoon(h.Opts.WorkspaceSlug); err != nil {
		emit("warning", "self-update", "installed but service restart was not scheduled: "+err.Error())
		return map[string]any{"updated": true, "version": version, "restart_scheduled": false}, nil
	}
	emit("info", "self-update", "aw-remote-host installed; restarting service; rollback armed until registration succeeds")
	return map[string]any{
		"updated":            true,
		"version":            version,
		"restart_scheduled":  true,
		"rollback_armed":     true,
		"validation_timeout": int(updater.DefaultValidationTimeout.Seconds()),
	}, nil
}

func restartHostServiceSoon(slug string) error {
	if os.Getenv("AW_REMOTE_HOST_SKIP_SERVICE_RESTART") == "1" {
		return nil
	}
	cmd := "sleep 1; " + updater.RestartCommand(slug)
	return exec.Command("sh", "-c", cmd).Start()
}

// Bootstrap brings the runtime up from nothing (idempotent — safe to call
// on an already-running workspace): the full manifest (podman, postgres,
// redis, workspace), each module skipped if its own verify.sh already
// passes.
func (h *Handler) Bootstrap(ctx context.Context, opts BootstrapOpts, emit Emit) (map[string]any, error) {
	return h.runModules(ctx, opts, true, emit)
}

func workspaceHostDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("AW_WORKSPACE_HOST_DIR")); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	next := filepath.Join(home, "aw-workspace")
	if _, err := os.Stat(next); err == nil {
		return next, nil
	}
	legacy := filepath.Join(home, "agentic-workspace")
	if _, err := os.Stat(legacy); err == nil {
		return legacy, nil
	}
	return next, nil
}

// syncWorkspaceSource overwrites dstDir with whatever the freshly-pulled
// image (staged at srcDir) ships — but only entries the image actually
// ships. It never deletes anything else already in dstDir: a user's own
// repos/ dir, ~/.claude, or any other file/dir some tool wrote there over
// time is left completely untouched, with no allowlist/exclusion needed to
// protect it (Frederico decision 2026-08-01 — Update replaces, it never
// prunes). ".aw-workspace" is still skipped explicitly: it's not something
// the image ships, but a defensive belt-and-braces in case an older
// install still has one from before AW_WORKSPACE_HOME moved elsewhere.
func syncWorkspaceSource(srcDir, dstDir string) error {
	srcEntries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read staged workspace source: %w", err)
	}
	for _, entry := range srcEntries {
		name := entry.Name()
		// .aw-workspace holds mutable runtime state (see the function
		// docstring); apps/ holds locally-installed workspace apps — also
		// mutable, and NOT something the image's own baked scaffold (just a
		// README) should ever overwrite. Found live 2026-08-03: every
		// Update() wiped every installed app back down to that bare README,
		// because this exclusion list only covered .aw-workspace.
		if name == ".aw-workspace" || name == "apps" {
			continue
		}
		dst := filepath.Join(dstDir, name)
		// Remove the old entry first (handles a type change, e.g. a file
		// becoming a directory between versions) then copy the fresh one
		// in — this only ever touches names the image itself brought.
		if err := os.RemoveAll(dst); err != nil {
			return fmt.Errorf("remove old workspace entry %s: %w", name, err)
		}
		if err := copyPath(filepath.Join(srcDir, name), dst); err != nil {
			return err
		}
	}
	return nil
}

func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return fmt.Errorf("mkdir %s: %w", dst, err)
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return fmt.Errorf("read dir %s: %w", src, err)
		}
		for _, entry := range entries {
			if err := copyPath(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return fmt.Errorf("readlink %s: %w", src, err)
		}
		if err := os.Symlink(target, dst); err != nil {
			return fmt.Errorf("symlink %s: %w", dst, err)
		}
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}

func (h *Handler) runModules(ctx context.Context, opts BootstrapOpts, full bool, emit Emit) (map[string]any, error) {
	return h.runModulesWithEnv(ctx, opts, full, emit, nil)
}

func (h *Handler) runModulesWithEnv(ctx context.Context, opts BootstrapOpts, full bool, emit Emit, extraEnv []string) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}
	if err := bootstrap.ExtractScripts(opts.ExtractDir); err != nil {
		return nil, fmt.Errorf("extract bootstrap scripts: %w", err)
	}
	manifest := m.Only("workspace")
	if full {
		manifest = m
	}
	runOpts := bootstrap.RunOptions{
		ExtractDir: opts.ExtractDir,
		Env:        runModuleEnv(opts, extraEnv),
	}
	for _, mod := range manifest.Modules {
		emit("info", mod.Name, fmt.Sprintf("bootstrapping %s...", mod.Name))
		st := bootstrap.RunModule(ctx, mod, runOpts)
		if !st.OK {
			emit("error", mod.Name, fmt.Sprintf("%s failed: %s", mod.Name, st.Output))
			return nil, fmt.Errorf("module %q failed", mod.Name)
		}
		emit("info", mod.Name, fmt.Sprintf("%s ok", mod.Name))
	}
	return map[string]any{"bootstrapped": true}, nil
}

func runModuleEnv(opts BootstrapOpts, extraEnv []string) []string {
	env := append(bootstrap.EnvPassthrough("AW_WORKSPACE_IMAGE", "XDG_RUNTIME_DIR"),
		"AW_WORKSPACE_SLUG="+opts.WorkspaceSlug,
		"AW_POSTGRES_PASSWORD="+opts.PostgresPassword,
		"AW_BACKEND_URL="+opts.ControlPlane,
		"AW_WORKSPACE_HOST_TOKEN="+opts.HostCredential,
	)
	return append(env, extraEnv...)
}

// Health gathers {healthy, uptime_s, disk, cpu_pct, mem, offline} — the
// same contract src/api/placement/base.py's PlacementDriver.health()
// documents and docker_driver.py's health() already returns for managed
// workspaces. Returns the "offline" shape (every field nil/false except
// offline=true) whenever the workspace container isn't running, gracefully
// rather than erroring — a BYOD host being asleep/off is an expected state,
// not a failure.
func (h *Handler) Health(ctx context.Context) map[string]any {
	offline := map[string]any{
		"healthy": false, "uptime_s": nil, "disk": nil,
		"cpu_pct": nil, "mem": nil, "offline": true,
	}

	out, err := h.runner().Run(ctx, "podman", "inspect", "--format",
		"{{.State.Running}}\t{{.State.StartedAt}}", WorkspaceContainer)
	if err != nil {
		return offline
	}
	parts := strings.SplitN(strings.TrimSpace(out), "\t", 2)
	if len(parts) != 2 || parts[0] != "true" {
		return offline
	}

	var uptimeS any
	if started, uErr := parseStartedAt(parts[1]); uErr == nil {
		uptimeS = started
	}

	healthy, workspaceVersion := h.probeHealth(ctx)
	cpuPct, mem := h.containerStats(ctx)
	return map[string]any{
		"healthy":           healthy,
		"uptime_s":          uptimeS,
		"disk":              h.diskUsage(ctx),
		"cpu_pct":           cpuPct,
		"mem":               mem,
		"offline":           false,
		"workspace_version": workspaceVersion,
	}
}

func (h *Handler) probeHealth(ctx context.Context) (bool, any) {
	out, err := h.runner().Run(ctx, "curl", "-fsS", "--max-time", probeTimeout, HealthURL)
	if err != nil {
		return false, nil
	}
	var data map[string]any
	if json.Unmarshal([]byte(out), &data) != nil {
		return true, nil
	}
	version, _ := data["version"].(string)
	if version == "" {
		return true, nil
	}
	if isLongHexSHA(version) {
		version = version[:7]
	}
	return true, version
}

func isLongHexSHA(version string) bool {
	if len(version) < 8 || len(version) > 40 {
		return false
	}
	for _, r := range version {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

func (h *Handler) containerStats(ctx context.Context) (any, any) {
	out, err := h.runner().Run(ctx, "podman", "stats", "--no-stream", "--format",
		"{{.CPUPerc}}\t{{.MemUsage}}", WorkspaceContainer)
	if err != nil {
		return nil, nil
	}
	parts := strings.SplitN(strings.TrimSpace(out), "\t", 2)
	if len(parts) != 2 {
		return nil, nil
	}
	cpuPct, ok := parseFloatPercent(parts[0])
	if !ok {
		return nil, nil
	}
	used, total, ok := parseMemUsage(parts[1])
	if !ok {
		return cpuPct, nil
	}
	return cpuPct, map[string]any{"used": used, "total": total}
}

func (h *Handler) diskUsage(ctx context.Context) any {
	out, err := h.runner().Run(ctx, "df", "-Pk", h.dataDir())
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return nil
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return nil
	}
	totalKB, err1 := strconv.ParseInt(fields[1], 10, 64)
	usedKB, err2 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	return map[string]any{"used": usedKB * 1024, "total": totalKB * 1024}
}

func parseStartedAt(raw string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return 0, err
	}
	uptime := int64(time.Since(t).Seconds())
	if uptime < 0 {
		uptime = 0
	}
	return uptime, nil
}

func parseFloatPercent(raw string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(raw), "%"), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// unitMultipliers covers both IEC binary suffixes (KiB/MiB/GiB/TiB, as
// docker emits) and SI decimal suffixes (kB/MB/GB/TB) — podman reports
// MemUsage in SI units (e.g. "45.2MB / 7.657GB"), so both must parse.
var unitMultipliers = map[string]float64{
	"TIB": 1024 * 1024 * 1024 * 1024,
	"GIB": 1024 * 1024 * 1024,
	"MIB": 1024 * 1024,
	"KIB": 1024,
	"TB":  1e12,
	"GB":  1e9,
	"MB":  1e6,
	"KB":  1e3,
	"B":   1,
}

// Longest-first so GB/MB/KB match before the bare "B" suffix (e.g.
// "7.657GB" must strip "GB", not greedily match "B" leaving "7.657G").
var unitSuffixesLongestFirst = []string{"TIB", "GIB", "MIB", "KIB", "TB", "GB", "MB", "KB", "B"}

func parseBytes(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	upper := strings.ToUpper(raw)
	for _, suf := range unitSuffixesLongestFirst {
		if strings.HasSuffix(upper, suf) {
			n, err := strconv.ParseFloat(strings.TrimSpace(raw[:len(raw)-len(suf)]), 64)
			if err != nil {
				return 0, false
			}
			return int64(n * unitMultipliers[suf]), true
		}
	}
	return 0, false
}

func parseMemUsage(raw string) (int64, int64, bool) {
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	used, ok1 := parseBytes(parts[0])
	total, ok2 := parseBytes(parts[1])
	return used, total, ok1 && ok2
}
