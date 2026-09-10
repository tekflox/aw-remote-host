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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/homedir"
	"github.com/tekflox/aw-remote-host/internal/hostpower"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/updater"
)

const (
	WorkspaceContainer = "aw-remote-host-workspace"
	WorkspaceImage     = "ghcr.io/fredericowu/aw-workspace:latest"
	ContainerWorkdir   = "/opt/aw-workspace"
	PostgresContainer  = "aw-remote-host-postgres"
	RedisContainer     = "aw-remote-host-redis"
	PostgresVolume     = "aw-remote-host-postgres-data"
	// Postgres/redis data moved out of podman named volumes and onto $HOME —
	// podman's storage lives in the aw-remote-host container's writable layer
	// on a containerised host, so an update's `docker rm -f` destroyed it.
	// Keep these in sync with bootstrap/{postgres,redis}/install.sh.
	PostgresHostDirEnv = "AW_POSTGRES_HOST_DIR"
	PostgresDirName    = "postgres-data"
	RedisHostDirEnv    = "AW_REDIS_HOST_DIR"
	RedisDirName       = "redis-data"
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
	// StatePath, when set, is ~/.aw-remote-host/state.json — a successful
	// FULL runModulesWithEnv (the control-plane-driven "bootstrap" verb, or
	// a local `bootstrap-workspace --with-workspace` re-run) marks
	// state.Provisioned=true there, so `status` reflects reality even when
	// provisioning was triggered remotely rather than by re-running the CLI
	// by hand. Left empty by callers (tests, or any future non-CLI caller)
	// that don't care about persisting this — a no-op, not an error.
	StatePath string
	// CLIVersion is this running binary's own version (main.version) — the
	// value runModulesWithEnv compares against state.LastBootstrapVersion
	// before a FULL bootstrap, so a full manifest re-run from an older
	// binary is refused instead of silently reinitializing everything. See
	// state.CheckDowngrade. Blank/"dev" (a developer's own unreleased
	// build) never blocks anything.
	CLIVersion string
	// Force bypasses the CheckDowngrade guard above for one Bootstrap call.
	// Not part of the standing Handler.Opts a caller assembles once — see
	// Bootstrap, which sets it per-call from the "bootstrap" verb's own
	// args["force"], mirroring the CLI's --force flag.
	Force bool
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
// "exec_kill"|"list_processes"|"fs_stat"|"fs_list"|"fs_mkdir"|"fs_delete"|
// "fs_read_chunk"|"fs_write_chunk"|"firewall_apply"|"firewall_status"|
// "vpn_status"|"vpn_bootstrap"|"vpn_advertise_exit"|"vpn_use_exit"|
// "vpn_clear_exit"|"vpn_public_ip"|"vpn_external_route"|
// "vpn_external_unroute"|"vpn_external_up"|"vpn_external_down"|
// "vpn_external_status") — the
// switchboard link.go's cmd-frame handling calls into. args carries optional
// per-verb parameters such as the exact aw-workspace image version to
// install for workspace updates, the shell command/timeout/job_id the
// exec_* verbs take (see ops_exec.go), the path/offset/chunk the fs_* verbs
// take (see ops_fs.go), or the rules/lockdown/revision firewall_apply takes
// (see ops_firewall.go).
func (h *Handler) Dispatch(ctx context.Context, verb string, args map[string]any, emit Emit) (any, error) {
	if !workspaceRuntimeSupported && workspaceLifecycleVerbs[verb] {
		return nil, fmt.Errorf("verb %q needs the local workspace runtime (podman + a Linux container image), "+
			"which does not exist on this host — it is linked lean. "+
			"exec_*, list_processes and fs_* are the verbs this host serves", verb)
	}
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
		return h.Bootstrap(ctx, h.Opts, args, emit)
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
	case "fs_stat":
		return h.FsStat(ctx, args)
	case "fs_list":
		return h.FsList(ctx, args)
	case "fs_mkdir":
		return h.FsMkdir(ctx, args)
	case "fs_delete":
		return h.FsDelete(ctx, args)
	case "fs_read_chunk":
		return h.FsReadChunk(ctx, args)
	case "fs_write_chunk":
		return h.FsWriteChunk(ctx, args)
	case "firewall_apply":
		return h.FirewallApply(ctx, args, emit)
	case "firewall_status":
		return h.FirewallStatus(ctx)
	case "vpn_status":
		return h.VPNStatus(ctx)
	case "vpn_bootstrap":
		return h.VPNBootstrap(ctx, args, emit)
	case "vpn_advertise_exit":
		return h.VPNAdvertiseExit(ctx, args, emit)
	case "vpn_use_exit":
		return h.VPNUseExit(ctx, args, emit)
	case "vpn_clear_exit":
		return h.VPNClearExit(ctx, args, emit)
	case "vpn_public_ip":
		return h.VPNPublicIP(ctx)
	case "vpn_external_route":
		return h.VPNExternalRoute(ctx, args, emit)
	case "vpn_external_unroute":
		return h.VPNExternalUnroute(ctx, args, emit)
	case "vpn_external_up":
		return h.VPNExternalUp(ctx, args, emit)
	case "vpn_external_down":
		return h.VPNExternalDown(ctx, args, emit)
	case "vpn_external_status":
		return h.VPNExternalStatus(ctx, args)
	default:
		return nil, fmt.Errorf("unknown verb %q", verb)
	}
}

// workspaceLifecycleVerbs are the verbs that drive the podman-managed
// workspace container. On a host with no local runtime they can only ever
// fail; the point of naming them is that they fail SAYING SO, instead of
// bubbling up a bare "exec: podman: executable file not found in $PATH"
// that reads like a broken PATH rather than a host that was never meant to
// have podman in the first place. workspaceRuntimeSupported is the
// build-tagged switch — see proc_unix.go / proc_windows.go.
var workspaceLifecycleVerbs = map[string]bool{
	"stop":      true,
	"restart":   true,
	"uninstall": true,
	"reinstall": true,
	"bootstrap": true,
	"update":    true,
}

// "self-update" is deliberately NOT in that list, and this is the whole
// reason a lean host could not be updated from the console. It drives the
// aw-remote-host BINARY — download a release, swap the executable, bounce
// the service — while every verb above drives the podman workspace
// CONTAINER. The two only looked alike because "update" and "self-update"
// share a word.
//
// Gating it on workspaceRuntimeSupported made a Windows host permanently
// unupdatable: it refused with "needs the local workspace runtime (podman +
// a Linux container image), which does not exist on this host", which is
// true of the workspace and irrelevant to replacing a binary. A lean LINUX
// host hit the same refusal for the same wrong reason.
//
// The other verbs still need that gate and still have it — this removal
// narrows it to the verbs it actually describes rather than switching it
// off.

// "health" is deliberately NOT in that list. It already degrades correctly
// on its own — a failed `podman inspect` returns {"healthy": false,
// "offline": true} rather than an error — and that is exactly the right
// answer for a host with no workspace to report on. Erroring instead would
// turn a lean host's honest "no workspace here" into a tunnel-level failure
// on the control plane's dashboard. A lean LINUX host already behaves this
// way today; Windows just inherits it.

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

// workspaceStatePath is state.DefaultPath, indirected so a test can point the
// image resolution/persistence pair below at a temp file rather than the
// developer's real ~/.aw-remote-host/state.json — same reason vpnStatePath
// (ops_vpn_bootstrap.go) exists.
var workspaceStatePath = state.DefaultPath

// workspaceImage is the STEADY-STATE image: what bootstrap/reinstall recreate
// the container from when no explicit update target was asked for.
//
// Precedence is state.json > AW_WORKSPACE_IMAGE > the :latest const above.
// state.json wins because only Update writes it, and only after the pulled
// image's digest was checked against the registry (verifyImageDigest). Without
// that, the env pin whoever created the aw-remote-host container set — on this
// project's own deployment, repos/aw-stack/docker-compose.yml pins a DIGEST
// there deliberately, for rollback/reproducibility — would re-assert itself on
// the very next container recreate and undo the update that had just proven a
// newer image good. That is how the 2026-09-10 incident perpetuated itself.
//
// A deliberate rollback is still expressible, just not by leaving a stale env
// var lying around: `update` with the older version resolves it by tag,
// verifies it and rewrites state.json.
func workspaceImage() string {
	if path, err := workspaceStatePath(); err == nil {
		if st, err := state.Load(path); err == nil {
			if image := strings.TrimSpace(st.WorkspaceImage); image != "" {
				return image
			}
		}
	}
	if image := strings.TrimSpace(os.Getenv("AW_WORKSPACE_IMAGE")); image != "" {
		return image
	}
	return WorkspaceImage
}

// workspaceImageForVersion resolves the UPDATE TARGET, which is deliberately
// NOT the same concept as workspaceImage above: "install version X" has to
// reach the registry for X, so whatever digest or tag the configured reference
// carries is dropped and only the repository is kept.
//
// Returning the configured reference unchanged when it was digest-pinned (what
// this did until 2026-09-10) silently DISCARDED the requested version: the pull
// of an already-local digest succeeded instantly, the guard passed, and the
// update reinstalled a 5-day-old image while reporting success — a permanent
// no-op that also reverted the host tree to that image's baked copy.
func workspaceImageForVersion(version string) string {
	image := workspaceImage()
	version = strings.TrimSpace(version)
	if version == "" {
		return image
	}
	return imageRepository(image) + ":" + version
}

// imageRepository strips a "@sha256:…" digest and/or a ":tag" off a reference,
// leaving the repository. The colon check only fires when nothing after it
// looks like a path element, so a registry PORT ("localhost:5000/aw-workspace")
// survives instead of being mangled into "localhost".
func imageRepository(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	if colon := strings.LastIndex(image, ":"); colon >= 0 && !strings.Contains(image[colon+1:], "/") {
		image = image[:colon]
	}
	return image
}

func commandError(prefix string, err error, out string) error {
	msg := strings.TrimSpace(out)
	if msg == "" {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w: %s", prefix, err, msg)
}

// verifyImageDigest proves the image now in local storage is the one the
// registry currently serves for that reference, and returns the digest that
// was installed so Update can persist it.
//
// This is the "structurally impossible to proceed on a stale image" half of
// the 2026-09-10 fix: resolving the update target by tag (above) closes the
// one path that was known to install a stale image, and this closes every
// other one, including any future path that re-introduces a stale reference.
// A PROVEN mismatch is a hard failure naming both digests. "Can't tell" —
// no local digest, an unreadable registry manifest, a single-manifest image
// with no index to compare against — is a loud warning that proceeds, the
// same shape guardHostNotAheadOfImage uses, because a false refusal here
// would strand every future update on hosts this check cannot speak about.
func (h *Handler) verifyImageDigest(ctx context.Context, image string, emit Emit) (string, error) {
	local := h.localImageDigests(ctx, image)
	if len(local) == 0 {
		emit("warning", "update", "could not read a local digest for "+image+
			" — proceeding without the registry cross-check")
		return "", nil
	}
	// local[0] is the image's own manifest digest (podman's .Digest); the rest
	// are its RepoDigests, which on a by-tag pull of a multi-arch image also
	// carry the index digest. Compare on the whole set, report the first.
	installed := local[0]

	if strings.Contains(image, "@") {
		emit("info", "update", "update target "+image+" is an immutable digest reference (local digest "+installed+")")
		return installed, nil
	}

	remote := h.registryImageDigests(ctx, image)
	if len(remote) == 0 {
		emit("warning", "update", "could not read the registry manifest for "+image+
			" — proceeding on local digest "+installed+" without the cross-check")
		return installed, nil
	}
	for _, l := range local {
		for _, r := range remote {
			if l == r {
				emit("info", "update", "verified "+image+" against the registry: digest "+installed)
				return installed, nil
			}
		}
	}

	emit("error", "update", "refusing to install "+image+": local digest "+installed+
		" is not what the registry serves for that tag ("+strings.Join(remote, ", ")+")")
	return "", fmt.Errorf(
		"refusing to install a stale image: %s in local storage is %s, but the registry now serves %s "+
			"for that tag — the pull did not actually refresh it",
		image, installed, strings.Join(remote, ", "))
}

// localImageDigests returns the local image's own manifest digest first,
// followed by the digest half of each of its RepoDigests.
func (h *Handler) localImageDigests(ctx context.Context, image string) []string {
	out, err := h.runner().Run(ctx, "podman", "image", "inspect", image,
		"--format", "{{.Digest}}{{range .RepoDigests}} {{.}}{{end}}")
	if err != nil {
		return nil
	}
	var digests []string
	for _, field := range strings.Fields(out) {
		if at := strings.Index(field, "@"); at >= 0 {
			field = field[at+1:]
		}
		if strings.HasPrefix(field, "sha256:") {
			digests = append(digests, field)
		}
	}
	return digests
}

// registryImageDigests asks the REGISTRY what it currently serves for this
// reference. `podman manifest inspect` only reads local storage for manifest
// lists someone built there with `podman manifest create`; for an ordinary
// image reference it fetches from the registry, which is exactly what makes it
// usable as an independent second opinion about a local tag (verified against
// ghcr.io on the affected host, podman 5.4.2).
//
// Returns the per-platform manifest digests of an image index. An image that
// is not an index has none to return — nil, which the caller treats as "can't
// tell" rather than as a mismatch.
func (h *Handler) registryImageDigests(ctx context.Context, image string) []string {
	out, err := h.runner().Run(ctx, "podman", "manifest", "inspect", image)
	if err != nil {
		return nil
	}
	// The Runner combines stdout and stderr, so a progress/warning line can sit
	// in front of the JSON.
	if brace := strings.Index(out, "{"); brace > 0 {
		out = out[brace:]
	}
	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(out), &index); err != nil {
		return nil
	}
	var digests []string
	for _, m := range index.Manifests {
		if strings.HasPrefix(m.Digest, "sha256:") {
			digests = append(digests, m.Digest)
		}
	}
	return digests
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
	// Legacy named volumes: still removed so a host that predates the move to
	// host data dirs (see bootstrap/postgres/install.sh) is torn down fully.
	for _, vol := range []string{PostgresVolume, RedisVolume} {
		if _, err := h.runner().Run(ctx, "podman", "volume", "rm", "-f", vol); err != nil {
			errs = append(errs, fmt.Sprintf("remove volume %s: %v", vol, err))
		}
	}
	// Where postgres/redis data actually lives now. Without this, "uninstall
	// AND its data" would silently leave the databases on disk and a later
	// bootstrap would adopt the old data instead of starting clean.
	for _, d := range []struct{ env, name string }{
		{PostgresHostDirEnv, PostgresDirName},
		{RedisHostDirEnv, RedisDirName},
	} {
		dir, err := dataHostDir(d.env, d.name)
		if err != nil {
			errs = append(errs, fmt.Sprintf("resolve %s dir: %v", d.name, err))
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, fmt.Sprintf("remove data dir %s: %v", dir, err))
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

// guardHostNotAheadOfImage compares the host tree's own committed git HEAD
// against the AW_WORKSPACE_VERSION baked into the freshly-pulled image (set
// from the build's own git SHA — see the Dockerfile's ARG/ENV and the image
// build workflow). syncWorkspaceSource below unconditionally overwrites the
// host tree with whatever the image shipped: if the host has commits the
// image was built without, that overwrite silently reverts them with no
// signal anywhere but a `git status` someone has to think to run — this is
// exactly what happened live 2026-09-10 (Kanban
// aw-workspace:host-tree-reverted-by-stale-image-sync), losing ~35 committed
// files including the very CLI verb (`restart core`) needed to recover.
//
// Both sides of the comparison are best-effort: hostDir may not be a git
// checkout at all (fresh provision) and the image may predate this build arg
// being wired up. Either missing value means "can't tell" — proceed rather
// than block a legitimate update on an unrelated host. When both are known
// but the merge-base check can't place the image commit in the host's own
// history either (shallow clone, force-pushed history, unrelated branch),
// that is ALSO "can't tell" — logged loudly rather than silently, but not
// blocking, since a false refusal here would strand every future update.
// Only a PROVEN case — the image's own commit is a strict ancestor of the
// host's HEAD — refuses outright; args["force"]=true overrides it for an
// intentional rollback.
func (h *Handler) guardHostNotAheadOfImage(ctx context.Context, hostDir, image string, force bool, emit Emit) error {
	hostHead := ""
	headErr := error(nil)
	if out, err := h.runner().Run(ctx, "git", "-C", hostDir, "rev-parse", "HEAD"); err == nil {
		hostHead = strings.TrimSpace(out)
	} else {
		headErr = err
	}
	if hostHead == "" {
		// A guard that CANNOT RUN must never again be mistaken for a guard that
		// passed. Confirmed live 2026-09-10: `git` is absent from the
		// aw-remote-host container image, so this returned nil and guarded
		// nothing on the exact host whose tree the sync had just reverted —
		// and stayed inert through the repeat two hours later. Still non-
		// blocking (failing closed would strand updates on every git-less
		// host), but no longer silent when there is visibly something to guard.
		if _, statErr := os.Stat(filepath.Join(hostDir, ".git")); statErr == nil {
			emit("warning", "update", fmt.Sprintf(
				"%s IS a git checkout but `git rev-parse HEAD` could not run here (%v) — the ahead-of-image "+
					"guard is INERT on this host and is checking nothing; the sync will proceed unguarded and "+
					"can revert committed host work", hostDir, headErr))
		}
		return nil // not a git checkout (or git unavailable) — nothing to guard
	}

	imageHead := ""
	if out, err := h.runner().Run(ctx, "podman", "image", "inspect", image,
		"--format", "{{range .Config.Env}}{{println .}}{{end}}"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "AW_WORKSPACE_VERSION="); ok && v != "" && v != "dev" {
				imageHead = v
			}
		}
	}
	if imageHead == "" || imageHead == hostHead {
		return nil // unknown image version, or already in sync — nothing to guard
	}

	if _, err := h.runner().Run(ctx, "git", "-C", hostDir, "merge-base", "--is-ancestor", imageHead, hostHead); err != nil {
		emit("warning", "update", fmt.Sprintf(
			"could not confirm host HEAD %s is not ahead of image %s (%v) — the image commit is not in this host's git history, so the ordering can't be proven either way; proceeding with sync",
			hostHead, imageHead, err))
		return nil
	}

	if force {
		emit("warning", "update", fmt.Sprintf(
			"host HEAD %s is ahead of image %s but force=true — syncing anyway, this WILL revert the host tree to the image's commit",
			hostHead, imageHead))
		return nil
	}

	emit("error", "update", fmt.Sprintf(
		"refusing to sync: host HEAD %s is ahead of image HEAD %s — syncing would silently revert committed host work. Re-run with force=true to override.",
		hostHead, imageHead))
	return fmt.Errorf("host git HEAD %s is ahead of image HEAD %s: refusing sync without force", hostHead, imageHead)
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
	switch {
	case version != "":
		emit("info", "update", "update target for version "+version+" resolved to "+image)
	case strings.Contains(image, "@"):
		// No version to resolve by tag, so the configured pin is honoured —
		// but say so. "pulling latest aw-workspace image" printed over a digest
		// that cannot move is precisely how the 2026-09-10 no-op looked like a
		// successful update to everyone watching.
		emit("warning", "update", "no version was requested and this host's workspace image is digest-pinned ("+
			image+") — this update can only reinstall that exact digest; pass a version to install a newer one")
	default:
		emit("info", "update", "update target resolved to "+image)
	}
	emit("info", "update", "pulling "+image)
	if out, err := h.runner().Run(ctx, "podman", podmanPullArgs(image)...); err != nil {
		pullErr := commandError("podman pull "+image, err, out)
		emit("warning", "update", "image pull failed ("+pullErr.Error()+") — attempting recovery")
		pulled := false
		// A stale/instance-scoped ghcr.io credential is the one pull failure a
		// retry can actually fix: logout drops it so the retry goes out
		// anonymously, which is how these public images are served anyway.
		if strings.HasPrefix(image, "ghcr.io/") {
			_, _ = h.runner().Run(ctx, "podman", "logout", "ghcr.io")
			if out, retryErr := h.runner().Run(ctx, "podman", podmanPullArgs(image)...); retryErr == nil {
				emit("info", "update", "pull succeeded after dropping the ghcr.io credential")
				pulled = true
			} else {
				pullErr = commandError("podman pull "+image, retryErr, out)
			}
		}
		// Last resort for a requested version that simply is not published:
		// this repository's own :latest TAG. Deliberately a tag and NOT
		// workspaceImage(), which on a pinned host is a digest podman would
		// serve straight out of the local cache — i.e. the stale image this
		// whole path exists to stop installing.
		if !pulled && version != "" {
			latestImage := imageRepository(image) + ":latest"
			if latestImage != image {
				emit("warning", "update", "pull of "+image+" failed; falling back to "+latestImage)
				if out, latestErr := h.runner().Run(ctx, "podman", podmanPullArgs(latestImage)...); latestErr == nil {
					image = latestImage
					pulled = true
				} else {
					pullErr = commandError("podman pull "+latestImage, latestErr, out)
				}
			}
		}
		// No fall-through to whatever is already in local storage. An update
		// exists to install NEW code, so it cannot succeed offline — and the
		// "image pull failed; using existing local image" branch that used to
		// sit here made every recovery step above dead code on any host that
		// already had the image, which is every installed host.
		if !pulled {
			emit("error", "update", "image pull failed: "+pullErr.Error())
			return nil, pullErr
		}
	}
	emit("info", "update", "pull finished for "+image)

	digest, err := h.verifyImageDigest(ctx, image, emit)
	if err != nil {
		return nil, err
	}
	// Recreate from the digest that was just verified rather than from the tag:
	// a tag can move between this point and the container recreate, a digest
	// cannot, and this is also the reference persisted below.
	recreateImage := image
	if digest != "" {
		recreateImage = imageRepository(image) + "@" + digest
	}

	force, _ := args["force"].(bool)
	if err := h.guardHostNotAheadOfImage(ctx, hostDir, recreateImage, force, emit); err != nil {
		return nil, err
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
	if _, err := h.runner().Run(ctx, "podman", "create", "--name", seedContainer, recreateImage); err != nil {
		return nil, fmt.Errorf("podman create update seed: %w", err)
	}
	defer h.runner().Run(ctx, "podman", "rm", "-f", seedContainer)

	emit("info", "update", "copying workspace source from image")
	if _, err := h.runner().Run(ctx, "podman", "cp", seedContainer+":"+ContainerWorkdir+"/.", staging); err != nil {
		return nil, fmt.Errorf("podman cp workspace source: %w", err)
	}
	written, err := syncWorkspaceSource(staging, hostDir)
	if err != nil {
		return nil, err
	}
	emit("info", "update", fmt.Sprintf("synced %d top-level entries from the image into %s", len(written), hostDir))
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
	//
	// Scoped to `written` — the exact entries syncWorkspaceSource just
	// copied — rather than the whole hostDir. hostDir also holds
	// .aw-workspace/data/<app> (each Tier-2 app's own bind-mounted /config,
	// owned by that app's own container user) and .aw-workspace/secrets;
	// syncWorkspaceSource never touches those, but a separate `chown -R
	// hostDir` used to sweep them anyway on every update, stomping their
	// ownership every single redeploy (core:workspace-redeploy-chowns-app-data-dirs).
	if len(written) > 0 {
		chownArgs := append([]string{"unshare", "chown", "-R", WorkspaceUID + ":" + WorkspaceGID}, written...)
		chownLabel := "podman unshare chown"
		if os.Geteuid() == 0 {
			chownArgs = append([]string{"-R", WorkspaceUID + ":" + WorkspaceGID}, written...)
			chownLabel = "chown"
			if out, err := h.runner().Run(ctx, "chown", chownArgs...); err != nil {
				emit("warning", "update", "could not normalize workspace ownership: "+commandError(chownLabel, err, out).Error())
			}
		} else if out, err := h.runner().Run(ctx, "podman", chownArgs...); err != nil {
			emit("warning", "update", "could not normalize workspace ownership: "+commandError(chownLabel, err, out).Error())
		}
	}

	emit("info", "update", "recreating workspace container from "+recreateImage)
	_, _ = h.runner().Run(ctx, "podman", "rm", "-f", WorkspaceContainer)
	if _, err := h.runModulesWithEnv(ctx, opts, false, emit, []string{"AW_WORKSPACE_IMAGE=" + recreateImage}); err != nil {
		return nil, err
	}
	// Only now — a pull that was verified against the registry AND a container
	// that came back up — does this host's steady-state image move. Everything
	// that recreates the container later (reinstall, bootstrap) reads this back
	// through workspaceImage(), so an AW_WORKSPACE_IMAGE env pin set once by
	// whoever created the aw-remote-host container can no longer quietly pull
	// the host back to a stale digest on the next recreate.
	if digest != "" {
		if err := recordInstalledImage(opts, recreateImage); err != nil {
			emit("warning", "update", "installed "+recreateImage+
				" but could not record it in state.json (a later recreate may fall back to the configured image): "+err.Error())
		} else {
			emit("info", "update", "recorded "+recreateImage+" as this host's workspace image")
		}
	}
	emit("info", "update", "workspace code updated")
	data := map[string]any{"updated": true, "image": recreateImage}
	if digest != "" {
		data["digest"] = digest
	}
	if version != "" {
		data["version"] = version
	}
	return data, nil
}

// recordInstalledImage persists the reference an update actually installed, so
// workspaceImage() can prefer it over the environment on every later recreate.
// Writes through state.Update (read-modify-write on disk) rather than saving a
// struct: this runs inside the long-lived daemon, whose own in-memory State is
// hours stale by the time an update lands.
func recordInstalledImage(opts BootstrapOpts, image string) error {
	path := opts.StatePath
	if path == "" {
		var err error
		if path, err = workspaceStatePath(); err != nil {
			return err
		}
	}
	return state.Update(path, func(s *state.State) { s.WorkspaceImage = image })
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
	installName, installArgs := installerCommand(version, installDir)
	if out, err := h.runner().Run(ctx, installName, installArgs...); err != nil {
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

// installerBaseURL is where both installers are fetched from. Kept as one
// constant so a branch rename can't leave the two platforms pointing at
// different refs of the same script.
const installerBaseURL = "https://raw.githubusercontent.com/tekflox/aw-remote-host/main"

// installerCommand returns the argv that runs this platform's public
// installer with the version and install dir pinned. Same shape as
// proc_{unix,windows}.go's shellCommand, but branched at RUNTIME rather
// than by build tag, because the caller is in a file that both platforms
// compile.
//
// The two installers share a contract — read AW_REMOTE_HOST_VERSION and
// AW_REMOTE_HOST_INSTALL_DIR from the environment, verify a SHA-256 against
// the release's checksums.txt, install without admin rights — so only the
// plumbing to hand them those two values differs.
func installerCommand(version, installDir string) (string, []string) {
	return installerCommandFor(runtime.GOOS, version, installDir)
}

// installerCommandFor takes goos explicitly so the Windows branch is
// assertable from the Linux CI runner, matching servicemgr.New's shape.
func installerCommandFor(goos, version, installDir string) (string, []string) {
	if goos == "windows" {
		// install.ps1 handles the one problem that makes updating a live
		// Windows link hard: Windows refuses to overwrite a RUNNING image,
		// and on a linked host one always is — the Scheduled Task is holding
		// the /link socket open as this runs. The installer renames the old
		// exe aside under a TIMESTAMPED name (a fixed ".old" collides with a
		// still-locked previous one and destroyed a working install once;
		// commits e84348b/136df7e), which Windows does permit on a running
		// image, freeing the name for the new binary.
		//
		// Env vars rather than parameters because install.ps1 is piped to
		// Invoke-Expression, and a script consumed that way cannot be passed
		// arguments — there is no param() to bind them to.
		//
		// The TLS line is not redundant with the one inside install.ps1.
		// That one runs too late to protect the request that DOWNLOADS
		// install.ps1: Windows PowerShell 5.1 — still what a stock Win10/11
		// box runs, and what startDetached deliberately targets — does not
		// enable TLS 1.2 by default, so the outer Invoke-RestMethod fails
		// first with "could not create SSL/TLS secure channel".
		script := fmt.Sprintf(
			"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"+
				"$env:AW_REMOTE_HOST_VERSION = %s\n"+
				"$env:AW_REMOTE_HOST_INSTALL_DIR = %s\n"+
				"Invoke-RestMethod -Uri %s -UseBasicParsing | Invoke-Expression",
			updater.PowerShellQuote(version),
			updater.PowerShellQuote(installDir),
			updater.PowerShellQuote(installerBaseURL+"/install.ps1"),
		)
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", script}
	}
	return "sh", []string{"-c", fmt.Sprintf(
		"curl -fsSL %s/install.sh | AW_REMOTE_HOST_VERSION=%s AW_REMOTE_HOST_INSTALL_DIR=%s sh",
		installerBaseURL,
		updater.ShellQuote(version),
		updater.ShellQuote(installDir),
	)}
}

// restartHostServiceSoon bounces this host's own service a beat from now,
// via updater.StartServiceRestart — which picks the right shell and the
// right restart command for the platform. The delay is what lets SelfUpdate
// return its reply over the tunnel before the process carrying that tunnel
// goes away.
func restartHostServiceSoon(slug string) error {
	if os.Getenv("AW_REMOTE_HOST_SKIP_SERVICE_RESTART") == "1" {
		return nil
	}
	return updater.StartServiceRestart(slug)
}

// Bootstrap brings the runtime up from nothing (idempotent — safe to call
// on an already-running workspace): the full manifest (podman, postgres,
// redis, workspace), each module skipped if its own verify.sh already
// passes.
//
// Guarded by state.CheckDowngrade (see runModulesWithEnv) against exactly
// what caused incident:byod-postgres-lost-bind-mount-2026-09-02: the
// control plane dispatching this verb against a host whose running binary
// is older than the one that last bootstrapped it. args["force"] (bool)
// bypasses that guard for this one call, mirroring the CLI's --force flag.
func (h *Handler) Bootstrap(ctx context.Context, opts BootstrapOpts, args map[string]any, emit Emit) (map[string]any, error) {
	if force, _ := args["force"].(bool); force {
		opts.Force = true
	}
	return h.runModules(ctx, opts, true, emit)
}

// dataHostDir resolves a sibling data dir under the same $HOME the workspace
// host dir lives in, honouring an explicit env override first — mirroring the
// ${HOME}/<name> + AW_*_HOST_DIR convention the bootstrap install.sh scripts
// use, so both sides agree on where the data is.
func dataHostDir(envVar, name string) (string, error) {
	if dir := strings.TrimSpace(os.Getenv(envVar)); dir != "" {
		return dir, nil
	}
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, name), nil
}

func workspaceHostDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("AW_WORKSPACE_HOST_DIR")); dir != "" {
		return dir, nil
	}
	home, err := homedir.Dir()
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
//
// CLI credential dirs/files (.claude, .claude.json, .codex, .copilot,
// .cursor) get the SAME belt-and-braces treatment, for a subtler reason
// than .aw-workspace's: aw-app-agents-platform-runners' execute.py uses
// exactly these names, rooted at $AW_WORKSPACE_CONTAINER_DIR (== dstDir
// here, /opt/aw-workspace) as the shared, workspace-persisted source it
// resyncs Workspace Runner CLI logins from before every spawn (see that
// app's `_sync_home_creds_into_workspace` / WORKSPACE_CONTAINER_DIR). The
// docstring above assumed this dir would never collide with anything the
// image itself ships — true in the common case, but aw-workspace's
// Dockerfile has no .dockerignore, so a stray `.claude/` (or similar)
// left in a build runner's checkout gets baked into the image and, once
// baked, this loop's "only entries the image ships get replaced" rule
// stops protecting it: every Update() would silently wipe live Workspace
// Runner CLI credentials and replace them with whatever (mostly-empty,
// dev-time) copy happened to be in that particular image build. Found
// live 2026-08-06 (Frederico: "na hora de atualizar o workspace, a gente
// deve tá apagando as credenciais" — reported after repeated,
// unsuccessful manual attempts to fix it another way). Skipping these
// names outright removes the collision at the root, independent of
// whether any given image build happens to ship them.
//
// Returns the destination paths it actually wrote, so a caller that needs to
// fix up ownership on the fresh copy (see Update) can scope that to exactly
// these entries instead of the whole of dstDir — which also holds mutable,
// non-image-owned state (.aw-workspace/data/<app>, .aw-workspace/secrets)
// that must never be touched here.
func syncWorkspaceSource(srcDir, dstDir string) ([]string, error) {
	srcEntries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, fmt.Errorf("read staged workspace source: %w", err)
	}
	var written []string
	for _, entry := range srcEntries {
		name := entry.Name()
		// .aw-workspace holds mutable runtime state (see the function
		// docstring); apps/ holds locally-installed workspace apps — also
		// mutable, and NOT something the image's own baked scaffold (just a
		// README) should ever overwrite. Found live 2026-08-03: every
		// Update() wiped every installed app back down to that bare README,
		// because this exclusion list only covered .aw-workspace.
		switch name {
		case ".aw-workspace", "apps",
			".claude", ".claude.json", ".codex", ".copilot", ".cursor":
			continue
		}
		dst := filepath.Join(dstDir, name)
		// Remove the old entry first (handles a type change, e.g. a file
		// becoming a directory between versions) then copy the fresh one
		// in — this only ever touches names the image itself brought.
		if err := os.RemoveAll(dst); err != nil {
			return nil, fmt.Errorf("remove old workspace entry %s: %w", name, err)
		}
		if err := copyPath(filepath.Join(srcDir, name), dst); err != nil {
			return nil, err
		}
		written = append(written, dst)
	}
	return written, nil
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

// runModule is bootstrap.RunModule, indirected so a test can observe which
// modules a pass actually selects without executing any install script —
// the manifest selection below is real logic that used to have no coverage
// at this call site at all.
var runModule = bootstrap.RunModule

func (h *Handler) runModules(ctx context.Context, opts BootstrapOpts, full bool, emit Emit) (map[string]any, error) {
	return h.runModulesWithEnv(ctx, opts, full, emit, nil)
}

func (h *Handler) runModulesWithEnv(ctx context.Context, opts BootstrapOpts, full bool, emit Emit, extraEnv []string) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	// Only a FULL run re-initializes podman/postgres/redis from scratch —
	// the risky case the guard exists for. opts.StatePath is empty for
	// tests and any caller that never wired one up; nothing to compare
	// against there, so this is a no-op, not an error.
	if full && opts.StatePath != "" {
		if err := state.CheckDowngrade(opts.StatePath, opts.CLIVersion, opts.Force); err != nil {
			emit("error", "bootstrap", err.Error())
			return nil, err
		}
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
		// Default(), not the raw manifest: "full" means every module this
		// host is supposed to have, which excludes the opt-in ones. An
		// optional module like vpn needs inputs (login server, pre-auth key)
		// BootstrapOpts does not carry, so running it here fails the whole
		// control-plane bootstrap on a module nobody asked for — after
		// podman/postgres/redis/workspace already came up fine.
		manifest = m.Default()
	}
	runOpts := bootstrap.RunOptions{
		ExtractDir: opts.ExtractDir,
		Env:        runModuleEnv(opts, extraEnv),
	}
	for _, mod := range manifest.Modules {
		emit("info", mod.Name, fmt.Sprintf("bootstrapping %s...", mod.Name))
		st := runModule(ctx, mod, runOpts)
		if !st.OK {
			emit("error", mod.Name, fmt.Sprintf("%s failed: %s", mod.Name, st.Output))
			return nil, fmt.Errorf("module %q failed", mod.Name)
		}
		emit("info", mod.Name, fmt.Sprintf("%s ok", mod.Name))
	}
	if full && opts.StatePath != "" {
		if st, err := state.Load(opts.StatePath); err == nil && !st.Provisioned {
			st.Provisioned = true
			_ = state.Save(opts.StatePath, st) // best-effort — a save failure here shouldn't fail the bootstrap that already succeeded
		}
		// Recorded on EVERY successful full bootstrap, not just the first
		// (unlike Provisioned above) — an in-place upgrade must move this
		// forward too, or CheckDowngrade would keep comparing against a
		// stale version from this host's very first bootstrap.
		_ = state.RecordBootstrapVersion(opts.StatePath, opts.CLIVersion) // best-effort, same rationale as above
	}
	return map[string]any{"bootstrapped": true}, nil
}

func runModuleEnv(opts BootstrapOpts, extraEnv []string) []string {
	// AW_WORKSPACE_IMAGE is RESOLVED here rather than passed through from this
	// process's environment: workspaceImage() prefers the image a verified
	// update recorded in state.json over the env pin, and a plain passthrough
	// would hand install.sh that env pin anyway, leaving every recreate after
	// an update back on the stale digest the update had just replaced.
	env := append(bootstrap.EnvPassthrough("XDG_RUNTIME_DIR"),
		"AW_WORKSPACE_IMAGE="+workspaceImage(),
		"AW_WORKSPACE_SLUG="+opts.WorkspaceSlug,
		"AW_POSTGRES_PASSWORD="+opts.PostgresPassword,
		"AW_BACKEND_URL="+opts.ControlPlane,
		"AW_WORKSPACE_HOST_TOKEN="+opts.HostCredential,
		"AW_HOST_POWER="+effectiveHostPower(opts.StatePath),
		"AW_WORKSPACE_WORKERS="+effectiveWorkers(opts.StatePath),
	)
	return append(env, extraEnv...)
}

// effectiveHostPower reads the operator's stored --host-power request and
// re-probes it, so the control-plane-driven "bootstrap" verb grants exactly
// what a local `bootstrap-workspace` re-run would.
//
// Reading it from state rather than taking it as a BootstrapOpts field is the
// point: this path is reached from the cloud, which has no business deciding
// how much access this machine hands out. The grant is a local decision,
// recorded locally, and a remote bootstrap can only honour it.
//
// Re-probed (not read back verbatim) so a host that has since gained
// /dev/kvm starts offering it without the operator re-running the flag.
func effectiveHostPower(statePath string) string {
	if statePath == "" {
		return ""
	}
	st, err := state.Load(statePath)
	if err != nil || len(st.HostPower) == 0 {
		return ""
	}
	return hostpower.Format(hostpower.Resolve(st.HostPower).Effective)
}

// effectiveWorkers reads this host's persisted worker-process count for the
// workspace container, mirroring effectiveHostPower above. Falls back to
// "1" (the Dockerfile's own baked default) when nothing is configured yet,
// including when statePath is empty (tests, or any caller that never wired
// one up) — never "" or "0", which would reach install.sh's
// AW_WORKSPACE_WORKERS and break the int() parse in src/start/workspace.py.
func effectiveWorkers(statePath string) string {
	if statePath == "" {
		return "1"
	}
	st, err := state.Load(statePath)
	if err != nil {
		return "1"
	}
	return strconv.Itoa(st.EffectiveWorkers())
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
