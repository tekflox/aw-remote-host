package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/diagdump"
	"github.com/tekflox/aw-remote-host/internal/firewall"
	"github.com/tekflox/aw-remote-host/internal/hostfacts"
	"github.com/tekflox/aw-remote-host/internal/hostpower"
	"github.com/tekflox/aw-remote-host/internal/instance"
	"github.com/tekflox/aw-remote-host/internal/lanfastpath"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/ops"
	"github.com/tekflox/aw-remote-host/internal/rlog"
	"github.com/tekflox/aw-remote-host/internal/servicemgr"
	"github.com/tekflox/aw-remote-host/internal/shell"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/tcpproxy"
	"github.com/tekflox/aw-remote-host/internal/tunnelproxy"
	"github.com/tekflox/aw-remote-host/internal/updater"
	"github.com/tekflox/aw-remote-host/internal/vpn"
	"github.com/tekflox/aw-remote-host/internal/wsl"
)

// registerTimeout bounds how long bootstrap-workspace waits for the first
// /link registration reply before giving up.
const registerTimeout = 30 * time.Second

// processIsElevated reports whether this process is running with elevated
// privileges right now — the honest answer to "what am I running as", as
// opposed to vpn.Probe's Privileged() which answers "could this host
// escalate". On Windows that means an elevated token (isElevated, which
// checks the token's own flag rather than Administrators group membership).
// Everywhere else it's euid 0 — os.Geteuid(), not os.Getuid(): a setuid-root
// binary invoked by a non-root user is running elevated right now even
// though its real uid says otherwise.
func processIsElevated() bool {
	if runtime.GOOS == "windows" {
		return isElevated()
	}
	return os.Geteuid() == 0
}

// workspaceSelfHealMinBackoff/MaxBackoff bound the retry loop
// bootstrapWorkspaceSelfHeal uses when the workspace module's
// detect->install->verify cycle fails (typically a readiness timeout —
// the container's FastAPI app taking longer than
// AW_WORKSPACE_READINESS_TIMEOUT to come up). Same shape as link.go's
// reconnect backoff (1s->60s cap), just started a bit slower since each
// attempt already includes a multi-minute readiness poll of its own.
const (
	workspaceSelfHealMinBackoff = 5 * time.Second
	workspaceSelfHealMaxBackoff = 2 * time.Minute
)

func commonFlags(fs *flag.FlagSet) (token *string, plan *bool, controlPlane *string) {
	token = fs.String("token", "", "bearer token identifying this machine to the control plane")
	plan = fs.Bool("plan", false, "print planned actions without executing them")
	controlPlane = fs.String("control-plane", defaultControlPlane, "control plane base URL")
	return
}

func extractDirFor(credentialsPath string) string {
	return filepath.Join(filepath.Dir(credentialsPath), "bootstrap-scripts")
}

// instanceFlagHelp is deliberately different on the two commands that carry
// the flag, because only one of them can act on it — see refuseNamedFull.
const (
	instanceFlagHelpLink = "serve a SECOND tenant account from this same machine under its own identity: its credentials, state, service definition and logs live under ~/.aw-remote-host/instances/<name>/ instead of the flat paths. Per-MACHINE state (the firewall, the VPN dead-man switch, the self-updater) stays shared, because those belong to the box and not to an account. Omit it — or pass --instance default — for this machine's original identity, whose paths, systemd unit name and launchd label are exactly what they have always been."
	instanceFlagHelpFull = "NOT supported on this command — a named instance is a LEAN link only. Accepted here solely so that passing it produces an explanation instead of \"flag provided but not defined\". Use 'link --instance <name>'."
)

// resolveInstance validates the parsed --instance value, records it as this
// PROCESS's identity, and re-points the durable log at that identity's own
// file.
//
// The second return value says whether the flag was actually GIVEN, which is
// not the same as whether it resolved to a name: `--instance default`
// normalizes to the default instance while still being an explicit choice.
// That difference is exactly what the second-link refusal hangs on — the
// mistake it catches is an OMITTED --instance, and an operator who typed
// "default" has already answered the question it would ask.
// parseInstance is the PURE half — it validates and normalizes, and writes
// nothing. Split from activateInstance so a command that is going to refuse
// this instance can refuse it before any directory exists: activating
// re-opens the durable log under the instance's own dir, and a refused
// command that has already created ~/.aw-remote-host/instances/<name>/ has
// left exactly the state it claimed not to write.
func parseInstance(fs *flag.FlagSet, raw string) (name string, given bool, err error) {
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "instance" {
			given = true
		}
	})
	name = instance.Normalize(raw)
	if err := instance.Validate(name); err != nil {
		return "", given, err
	}
	// Windows is explicitly refused rather than half-supported: the
	// background Scheduled Task is a single fixed name there, so a second
	// named instance would overwrite the first one's task. Refused for the
	// foreground case too, so the answer does not change depending on which
	// other flags were passed.
	if name != "" && runtime.GOOS == "windows" {
		return "", given, fmt.Errorf("--instance is not supported on Windows: the background Scheduled Task is a single fixed task name, so a second named instance would overwrite the first one's task rather than run alongside it. Serving two tenant accounts from one machine is supported on macOS and Linux")
	}
	return name, given, nil
}

// activateInstance records name as this PROCESS's identity and re-points the
// durable log at that identity's own file.
//
// Must run before anything resolves a per-identity path. Every helper that
// reads instance.Active() — link.DefaultCredentialsPath, state.DefaultPath,
// rlog.LogPath, and everything in internal/vpn and internal/ops that calls
// them — resolves the DEFAULT instance until this has run.
func activateInstance(name string) {
	instance.SetActive(name)
	rlog.Reopen()
}

// resolveInstance is parse-then-activate, for the commands that have
// nothing to refuse first.
func resolveInstance(fs *flag.FlagSet, raw string) (string, bool, error) {
	name, given, err := parseInstance(fs, raw)
	if err != nil {
		return "", given, err
	}
	activateInstance(name)
	return name, given, nil
}

// refuseNamedFull is the first of this feature's two fail-loud refusals: a
// second FULL (--with-workspace) instance, refused before any state is
// written and before any podman command runs.
//
// Everything a full provision creates is a fixed name — the containers
// aw-remote-host-workspace / -postgres / -redis, the published port
// 127.0.0.1:9030, the podman network aw-remote-host (bootstrap/*/install.sh)
// — so a second one does not "mostly work", it takes the first workspace's
// containers away from it. Parameterising all of that is deferred until
// somebody actually asks for two workspaces on one box.
func refuseNamedFull(name string) error {
	return fmt.Errorf(`bootstrap-workspace cannot run as instance %q: a second FULL workspace on one machine collides with the first on every name it needs — the containers aw-remote-host-workspace, aw-remote-host-postgres and aw-remote-host-redis, the published port 127.0.0.1:9030, and the podman network aw-remote-host are all fixed, not per-instance. Refused here rather than half way through 'podman run'.

A second tenant identity on this machine IS supported, as a lean link (no local runtime):

    aw-remote-host link --token <token> --instance %s --background`, name, name)
}

// refuseSecondLinkWithoutInstance is the second refusal, and the more
// important one: this is the ONLY place a user discovers that instances
// exist. The console's "Regenerate link command" does not emit --instance,
// so an operator linking a second account pastes a command with no instance
// in it onto a machine that already has one.
//
// Without this, that paste does not fail — it silently succeeds as the WRONG
// account. link.Client.Run prefers a stored host credential over the --token
// it was given (see internal/link/link.go), so the second account's token is
// ignored and the machine stays registered as the first one, with no error
// anywhere.
func refuseSecondLinkWithoutInstance(cmdName, credPath string) error {
	return fmt.Errorf(`this machine is already linked (credentials at %s), so a --token for a DIFFERENT account would be silently ignored: an existing host credential always wins over a freshly supplied bootstrap token, and this host would stay registered as the account it is linked to now.

To serve a SECOND account from this machine, give it its own instance:

    aw-remote-host link --token <token> --instance <name> --background

To re-link THIS machine's existing identity with a fresh token, say so explicitly:

    aw-remote-host %s --token <token> --instance default`, credPath, cmdName)
}

func reportStatuses(statuses []bootstrap.ModuleStatus) {
	for _, st := range statuses {
		switch {
		case st.AlreadyOK:
			rlog.Printf("%s: already ok, skipped install\n", st.Module)
		case st.OK:
			rlog.Printf("%s: installed and verified\n", st.Module)
		default:
			rlog.Printf("%s: FAILED\n", st.Module)
		}
	}
}

// parseHostPowerFlag reads --host-power. The bool says whether the flag was
// GIVEN, which is different from whether it parsed to something non-empty:
// omitting it must leave a previously stored grant alone, while an explicit
// --host-power=none must revoke it. Collapsing those two into "is the list
// empty" would make every plain re-run silently disarm the host.
func parseHostPowerFlag(fs *flag.FlagSet, raw string) ([]string, bool, error) {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "host-power" {
			given = true
		}
	})
	if !given {
		return nil, false, nil
	}
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "none" || trimmed == "" {
		return nil, true, nil
	}
	grants, err := hostpower.Parse(raw)
	if err != nil {
		return nil, false, err
	}
	return grants, true, nil
}

// parseWorkersFlag reads --workers, mirroring parseHostPowerFlag: the bool
// says whether the flag was GIVEN, so a plain re-run never silently resets
// an already-configured worker count back to the default.
func parseWorkersFlag(fs *flag.FlagSet, raw string) (int, bool, error) {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "workers" {
			given = true
		}
	})
	if !given {
		return 0, false, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 {
		return 0, false, fmt.Errorf("--workers must be a positive integer, got %q", raw)
	}
	return n, true, nil
}

// resolveHostPower probes the requested grants and returns the wire value for
// AW_HOST_POWER — the EFFECTIVE set, never the requested one.
//
// A grant this host cannot deliver is reported and dropped, not fatal:
// --host-power=all on a machine without binder devices should grant the rest.
// What must not happen is the request being passed on as though it succeeded,
// because then the workspace lets an app load that will come up without the
// device it needs.
func resolveHostPower(requested []string) (string, error) {
	if len(requested) == 0 {
		return "", nil
	}
	res := hostpower.Resolve(requested)
	for _, name := range requested {
		if reason, denied := res.Refused[name]; denied {
			rlog.Printf("host-power: %s NOT granted — %s\n", name, reason)
		}
	}
	if len(res.Effective) == 0 {
		return "", fmt.Errorf(
			"host-power: none of %s can be delivered by this host — see the reasons above",
			strings.Join(requested, ","))
	}
	rlog.Printf("host-power: %s\n", hostpower.Describe(res.Effective))
	return hostpower.Format(res.Effective), nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(answer)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

// runLink is the "link" command: a lean link, permanently — it never
// provisions the local runtime, and doesn't even accept --with-workspace/
// --full (fails fast with flag.ContinueOnError's own "flag provided but
// not defined" if someone tries, rather than silently ignoring it). Use
// bootstrap-workspace instead when the local runtime IS wanted.
func runLink(args []string) error {
	return runLinkOrBootstrap("link", args, false)
}

// runBootstrapWorkspace is the "bootstrap-workspace" command: lean by
// default (identical to "link"), but accepts --with-workspace/--full to
// also provision the local runtime — immediately, or later by re-running
// with the flag.
func runBootstrapWorkspace(args []string) error {
	return runLinkOrBootstrap("bootstrap-workspace", args, true)
}

func runLinkOrBootstrap(cmdName string, args []string, allowProvision bool) error {
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	token, plan, controlPlane := commonFlags(fs)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	foreground := fs.Bool("foreground", false, "run attached, holding the /link connection; installs no service (default when neither flag is given)")
	fg := fs.Bool("fg", false, "alias for --foreground")
	background := fs.Bool("background", false, "install and start a background service (launchd on macOS, systemd on Linux), then detach")
	detach := fs.Bool("detach", false, "alias for --background")
	elevated := fs.Bool("elevated", false, "Windows only: register the background task to run with administrative rights (RunLevel=HighestAvailable). Needs an elevated prompt to register — without it the link runs as a standard user, which is enough for exec/file/shell but cannot restart a Windows service or write under C:\\Program Files. Ignored on macOS/Linux.")
	instanceHelp := instanceFlagHelpLink
	if allowProvision {
		instanceHelp = instanceFlagHelpFull
	}
	instanceRaw := fs.String("instance", "", instanceHelp)
	var withWorkspace, full, force *bool
	if allowProvision {
		withWorkspace = fs.Bool("with-workspace", false, "also install/start the full local runtime (podman, postgres+pgvector, redis, the aw-workspace container) — default is a LEAN link: register this machine and hold /link (enables exec_* + control-plane-driven \"bootstrap\") without provisioning anything locally. Re-run with this flag later (no --token needed once linked) to provision, or trigger it remotely via the control plane's own \"bootstrap\" verb (see README) — no need to re-run by hand.")
		full = fs.Bool("full", false, "alias for --with-workspace")
		force = fs.Bool("force", false, "provision anyway even though this binary's version is older than the one that last completed a full bootstrap on this host (state.CheckDowngrade) — a full bootstrap re-runs podman/postgres/redis from scratch, which can silently reset them onto empty storage, so this refusal is the default and --force is an explicit opt-out")
	}
	hostPower := fs.String("host-power", "", "comma-separated elevated host access to grant app containers on this machine (default: none). Grants:\n"+hostpower.Help()+
		"Only what this host can actually deliver is granted — each grant is probed, and anything undeliverable is reported, not silently assumed. An app must ALSO declare it in runtime.host_power and hold the matching host:* permission. Re-run with a different value to change it; pass --host-power=none to revoke.")
	workers := fs.String("workers", "", "worker-process count for this host's workspace container (default: 5, kept in sync with the image's own default — the two live in separate repos and must be bumped together). Persists across a container recreation, the same way --host-power does. Re-run with a different value to change it.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolved first, before ANY path is computed: every per-identity path
	// this function goes on to use reads instance.Active(), so a later
	// resolution would silently touch the default instance's files.
	instanceName, instanceGiven, err := parseInstance(fs, *instanceRaw)
	if err != nil {
		return err
	}
	// Refusal 1 — a second FULL instance. Deliberately BEFORE
	// activateInstance, so this refuses without having created the instance
	// directory it is refusing. allowProvision is exactly "this is
	// bootstrap-workspace", the only command that can provision.
	if allowProvision && instanceName != "" {
		return refuseNamedFull(instanceName)
	}
	activateInstance(instanceName)

	// Parse before anything else touches the disk: a typo'd grant name must
	// abort here, not halfway through provisioning.
	hostPowerRequested, hostPowerChanged, err := parseHostPowerFlag(fs, *hostPower)
	if err != nil {
		return err
	}
	workersRequested, workersChanged, err := parseWorkersFlag(fs, *workers)
	if err != nil {
		return err
	}

	fgMode := *foreground || *fg
	bgMode := *background || *detach
	if fgMode && bgMode {
		return fmt.Errorf("--foreground and --background are mutually exclusive")
	}
	runInBackground := bgMode // default (neither flag given) is foreground

	// Fail here, before anything touches the disk or the network. Letting an
	// unelevated --elevated run get as far as schtasks /Create means the user
	// waits through a full link only to lose it to an "access denied" from a
	// tool they did not invoke — the failure has to name itself at the point
	// the mistake was made.
	if *elevated {
		if runtime.GOOS != "windows" {
			return fmt.Errorf("--elevated is Windows-only (this is %s); on macOS/Linux the service already runs with the rights it needs", runtime.GOOS)
		}
		if !isElevated() {
			return fmt.Errorf("--elevated needs an elevated prompt: re-run this from a PowerShell started with \"Run as administrator\"")
		}
	}
	provisionWorkspace := allowProvision && (*withWorkspace || *full)

	// On Windows, "provision the workspace here" cannot mean what it means
	// everywhere else — the workspace is a Linux container image, so there is
	// nothing for the podman modules to install on this machine. It means
	// "stand up a WSL2 distro and provision it in there", which is a wholly
	// different path and takes over the whole command.
	//
	// The Windows machine itself stays a lean link (see
	// internal/ops.workspaceRuntimeSupported); the distro becomes a second,
	// Linux host of the same workspace, which the control plane models fine.
	if provisionWorkspace && runtime.GOOS == "windows" {
		if *plan {
			rlog.Printf("[plan] would provision the workspace inside a WSL2 distro (%s):\n", wsl.DefaultDistro)
			for _, step := range []string{
				"update the WSL kernel",
				"download the Ubuntu rootfs and import it as " + wsl.DefaultDistro,
				"enable systemd inside it",
				"install aw-remote-host inside it",
				"run bootstrap-workspace --with-workspace in there (podman, postgres, redis, workspace)",
				"install a systemd service inside it, and a Startup-folder keep-alive out here",
			} {
				rlog.Printf("[plan] wsl: %s\n", step)
			}
			return nil
		}
		return wsl.ProvisionWorkspace(wsl.Options{
			Token:        *token,
			ControlPlane: *controlPlane,
			Log:          func(f string, a ...any) { rlog.Printf(f+"\n", a...) },
		})
	}

	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return err
	}

	if *plan {
		if provisionWorkspace {
			rlog.Printf("[plan] would link to %s as this machine, then run:\n", *controlPlane)
			for _, a := range bootstrap.Plan(m.Default()) {
				rlog.Printf("[plan] %s: %s — %s\n", a.Module, a.Step, a.Detail)
			}
		} else {
			rlog.Printf("[plan] would link to %s as this machine (lean: no local provisioning — use 'bootstrap-workspace --with-workspace' to also run):\n", *controlPlane)
			for _, a := range bootstrap.Plan(m.Default()) {
				rlog.Printf("[plan] (skipped — lean %s) %s: %s — %s\n", cmdName, a.Module, a.Step, a.Detail)
			}
		}
		return nil
	}

	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return err
	}
	statePath, err := state.DefaultPath()
	if err != nil {
		return err
	}

	existingCreds, err := link.LoadCredentials(credPath)
	if err != nil {
		return fmt.Errorf("read existing credentials: %w", err)
	}
	alreadyLinked := existingCreds != nil && existingCreds.HostCredential != ""
	if *token == "" && !alreadyLinked {
		return fmt.Errorf("--token is required for first-time linking (or pass --plan to preview without one)")
	}
	// Refusal 2 — see refuseSecondLinkWithoutInstance. Still before anything
	// is written: the only disk read so far is credentials.json.
	if !instanceGiven && *token != "" && alreadyLinked {
		return refuseSecondLinkWithoutInstance(cmdName, credPath)
	}

	if !*yes {
		if provisionWorkspace {
			rlog.Println("This will install/verify: podman, postgres+pgvector, redis, and start the aw-workspace runtime on this machine.")
		} else {
			rlog.Println("This will register this machine with the control plane and hold the /link connection open (enables exec_* + a control-plane-driven \"bootstrap\" later) — no local runtime (podman, postgres, redis, aw-workspace) is installed. Use 'bootstrap-workspace --with-workspace' to also do that now.")
		}
		if !confirm("Continue? [y/N] ") {
			return fmt.Errorf("aborted")
		}
	}

	// Asked separately from the install confirmation above, and asked even
	// under --yes when it is the blunt grant. --yes means "don't make me
	// retype the obvious"; handing every app container on this machine full
	// root-equivalent access to the host is not the obvious.
	if hostPowerChanged && contains(hostPowerRequested, hostpower.Privileged) && !*yes {
		rlog.Println("--host-power=privileged removes container isolation for every app that requests it on this machine: an app container gets every device and every Linux capability, which is root-equivalent access to this host.")
		rlog.Println("Prefer naming the specific grants an app needs (e.g. --host-power=kvm,tun), or --host-power=all for every device grant without dropping isolation.")
		if !confirm("Grant privileged anyway? [y/N] ") {
			return fmt.Errorf("aborted")
		}
	}

	extractDir := extractDirFor(credPath)
	if err := bootstrap.ExtractScripts(extractDir); err != nil {
		return fmt.Errorf("extract bootstrap scripts: %w", err)
	}

	st, err := state.Load(statePath)
	if err != nil {
		return err
	}
	if st.PostgresPassword == "" {
		pw, err := generatePassword()
		if err != nil {
			return err
		}
		st.PostgresPassword = pw
		if err := state.Save(statePath, st); err != nil {
			return err
		}
	}
	// Only rewrite when the flag was actually given, so a plain re-run (or a
	// `--with-workspace` added later) never silently revokes a grant the host
	// is already relying on. Revoking is explicit: --host-power=none.
	if hostPowerChanged {
		st.HostPower = hostPowerRequested
		if err := state.Save(statePath, st); err != nil {
			return err
		}
	}
	hostPowerEnv, err := resolveHostPower(st.HostPower)
	if err != nil {
		return err
	}
	// Same "only rewrite when the flag was actually given" rule as HostPower
	// above, for the same reason: a plain re-run must never silently reset
	// an already-configured worker count back to the default.
	if workersChanged {
		st.Workers = workersRequested
		if err := state.Save(statePath, st); err != nil {
			return err
		}
	}
	workersEnv := strconv.Itoa(st.EffectiveWorkers())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// RODADA 10 D6 item 2 — non-fatal goroutine dump on SIGUSR1. See
	// internal/diagdump's package doc for why this exists instead of just
	// relying on Go's default (process-killing) SIGQUIT handler.
	diagdump.Start(ctx)

	// Lean by default: skip local infra provisioning entirely unless
	// --with-workspace opted in. The /link registration below (and the
	// ops.Handler it wires up) works standalone — exec_* and the
	// control-plane-driven "bootstrap" verb (src/api/placement/
	// remote_host_driver.py) don't need any module installed locally first.
	if provisionWorkspace {
		// See state.CheckDowngrade: refuses to re-run podman/postgres/redis
		// from scratch when this binary is older than the one that last
		// bootstrapped this host, unless --force opted out. force is
		// non-nil here — allowProvision is guaranteed true whenever
		// provisionWorkspace is.
		if err := state.CheckDowngrade(statePath, version, *force); err != nil {
			return err
		}
		// Default() drops the opt-in modules (vpn): provisioning a workspace
		// must never also enrol the machine in a network.
		infra := m.Default().Except("workspace")
		infraOpts := bootstrap.RunOptions{
			ExtractDir: extractDir,
			Env:        []string{"AW_POSTGRES_PASSWORD=" + st.PostgresPassword},
		}
		statuses, err := bootstrap.Run(ctx, infra, infraOpts)
		reportStatuses(statuses)
		if err != nil {
			return err
		}
		if err := state.RecordBootstrapVersion(statePath, version); err != nil {
			rlog.Printf("state: could not record bootstrap version: %v\n", err)
		}
	}

	hostname, _ := os.Hostname()
	usernsContained, usernsMeasured := hostfacts.UsernsContained()
	containerForm, containerID := hostfacts.ContainerForm()
	c := link.New(*controlPlane, *token)
	// Set by the hosted container's entrypoint.sh only — see
	// resilience:hosted-entrypoint-signal-and-hang-supervision. Empty
	// (the default everywhere else, including a plain developer `link`)
	// leaves HeartbeatFile disabled.
	c.HeartbeatFile = strings.TrimSpace(os.Getenv("AW_REMOTE_HOST_HEARTBEAT_FILE"))
	c.Info = link.RegisterInfo{
		Hostname:           hostname,
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		CLIVersion:         version,
		HostPower:          hostPowerEnv,
		HostPowerRequested: hostpower.Format(st.HostPower),
		Elevated:           processIsElevated(),
		// Elevated on its own cannot tell a userns-remapped container-root
		// apart from an uncontained host root — both report true. See
		// hostfacts.UsernsContained.
		UsernsContained: usernsContained,
		UsernsMeasured:  usernsMeasured,
		UIDMap:          hostfacts.UIDMap(),
		// What makes "update" mean the IMAGE on this host form rather than
		// just the binary — see hostfacts.ContainerForm.
		ContainerForm: containerForm,
		ContainerID:   containerID,
	}

	type registration struct {
		slug           string
		remoteHostID   string
		hostCredential string
	}
	registered := make(chan registration, 1)
	runDone := make(chan error, 1)
	var lanOnce sync.Once

	// opsHandler dispatches lifecycle/health "cmd" frames the control plane
	// sends over this same /link connection (see internal/ops). Its Opts
	// (workspace slug) are only known once OnRegistered fires, which the
	// Run loop guarantees happens before pump() can see any cmd frame.
	opsHandler := &ops.Handler{}

	// Reapply whatever firewall state this host last had BEFORE dialing
	// /link — a host that reboots without network should come back up
	// firewalled, not wide open until the control plane happens to
	// reconnect (Card B instructions). Best-effort: a no-op when this host
	// has never had a rule applied, and never fatal — a self-heal failure
	// must not block this process from linking at all.
	if err := firewall.SelfHeal(ctx, ops.DefaultRunner); err != nil {
		rlog.Printf("firewall: self-heal failed (continuing): %v\n", err)
	}

	// Same bargain for the external VPN, and it is not optional here. Two
	// halves, one loop, tunnel first (internal/vpn/selfheal.go):
	//
	// The ROUTE half is a routing POLICY rule, and systemd-networkd flushes
	// every one it does not own whenever it restarts — which on the production
	// bare metal is whatever the daily unattended apt upgrade decides.
	// Measured 2026-09-02: networkd restarted at 06:48:54 and the aw-vpn-hub
	// rules installed at boot were gone, on a container that had not
	// restarted. tailscaled survives that only because it does exactly this.
	//
	// The TUNNEL half had no equivalent at all until now, which is the whole
	// of this card: its handshake was confirmed once, at dial time, from a CLI
	// somebody was watching. A tunnel that died quietly overnight stayed dead
	// until a human noticed.
	//
	// A no-op on every host that has neither recorded.
	reassertRunner := vpn.PrivilegedRunner{Inner: ops.DefaultRunner, Sudo: runtime.GOOS != "darwin" && runtime.GOOS != "windows" && os.Geteuid() != 0}
	go vpn.SelfHealLoop(ctx, reassertRunner, func(restored []string, err error) {
		if err != nil {
			rlog.Printf("vpn: self-heal could not put the external VPN back (continuing): %v\n", err)
			return
		}
		rlog.Printf("vpn: self-heal restored what something had taken away: %s\n", strings.Join(restored, ", "))
	})

	go func() {
		runDone <- c.Run(ctx, credPath, link.RunCallbacks{
			OnRegistered: func(reply *link.RegisteredReply) {
				if reply.WorkspaceSlug != "" {
					st.WorkspaceSlug = reply.WorkspaceSlug
					// Update, not Save: this callback fires on every
					// reconnect, and `st` was loaded when this process
					// started — possibly days ago. Saving it whole erases
					// anything a verb has recorded since (the exit-gate
					// selection, the external route), which is how an
					// external route confirmed at 17:51 vanished from
					// state.json at 17:58 while still installed in the
					// kernel. Only the field this callback actually owns
					// may be written.
					if err := state.Update(statePath, func(s *state.State) { s.WorkspaceSlug = reply.WorkspaceSlug }); err != nil {
						rlog.Printf("state: could not record the workspace slug: %v\n", err)
					}
				}
				if err := updater.ClearPending(); err != nil {
					rlog.Printf("self-update: could not clear rollback marker after registration: %v\n", err)
				}
				hostCredential := reply.HostCredential
				if hostCredential == "" && existingCreds != nil {
					hostCredential = existingCreds.HostCredential
				}
				if hostCredential == "" {
					if creds, _ := link.LoadCredentials(credPath); creds != nil {
						hostCredential = creds.HostCredential
					}
				}
				opsHandler.Opts = ops.BootstrapOpts{
					ExtractDir:       extractDir,
					WorkspaceSlug:    reply.WorkspaceSlug,
					PostgresPassword: st.PostgresPassword,
					ControlPlane:     *controlPlane,
					HostCredential:   hostCredential,
					StatePath:        statePath,
					CLIVersion:       version,
				}
				rlog.Printf("link: registered (remote_host_id=%s, workspace=%s)\n", reply.RemoteHostID, reply.WorkspaceSlug)
				if reply.WorkspaceSlug != "" {
					lanOnce.Do(func() { startLANFastPath(ctx, reply.WorkspaceSlug) })
				}
				select {
				case registered <- registration{
					slug: reply.WorkspaceSlug, remoteHostID: reply.RemoteHostID,
					hostCredential: hostCredential,
				}:
				default:
				}
			},
			OnDisconnect: func(err error) {
				if err != nil {
					rlog.Printf("link: disconnected: %v\n", err)
				}
			},
			OnCommand: func(ctx context.Context, verb string, args map[string]any, emit link.Emit) (any, error) {
				return opsHandler.Dispatch(ctx, verb, args, ops.Emit(emit))
			},
			OnShell: func(emit func(id, dataB64 string)) link.ShellManager {
				return shell.NewManager(nil, shell.EmitFunc(emit))
			},
			OnTunnelProxy: func() link.TunnelProxy {
				return newLinkProxy()
			},
		})
	}()

	var reg registration
	select {
	case reg = <-registered:
	case runErr := <-runDone:
		if runErr != nil {
			return fmt.Errorf("link: %w", runErr)
		}
		return fmt.Errorf("link: exited before registering")
	case <-time.After(registerTimeout):
		stop()
		return fmt.Errorf("timed out waiting for /link registration")
	case <-ctx.Done():
		return ctx.Err()
	}

	if reg.slug == "" {
		return fmt.Errorf("registered but the control plane didn't return a workspace_slug")
	}

	// Runs for the lifetime of this process, independent of provisionWorkspace
	// (--with-workspace) — that flag only governs whether THIS invocation does
	// the initial install; a host provisioned by an EARLIER run still needs
	// its nested containers watched. selfHealTick itself is the no-op guard
	// for a lean host that has never had a local runtime at all (see
	// internal/ops/selfheal.go's incident writeup for why this exists).
	go opsHandler.ZombieHealLoop(ctx, func(level, phase, message string) {
		rlog.Printf("selfheal[%s/%s]: %s\n", level, phase, message)
	})

	if provisionWorkspace {
		wsOpts := bootstrap.RunOptions{
			ExtractDir: extractDir,
			Env: append(bootstrap.EnvPassthrough("AW_WORKSPACE_IMAGE", "XDG_RUNTIME_DIR"),
				"AW_WORKSPACE_SLUG="+reg.slug,
				"AW_POSTGRES_PASSWORD="+st.PostgresPassword,
				"AW_BACKEND_URL="+*controlPlane,
				"AW_WORKSPACE_HOST_TOKEN="+reg.hostCredential,
				"AW_HOST_POWER="+hostPowerEnv,
				"AW_WORKSPACE_WORKERS="+workersEnv,
			),
		}
		// Run the workspace module's bootstrap in the background with its
		// own retry loop instead of inline: this same function/process
		// holds the /link tunnel connection (started above), and a
		// synchronous failure here used to `return err` straight out of
		// runBootstrapWorkspace, cancelling ctx and tearing the tunnel down
		// with it — over one slow container startup. Since the UI's restart
		// button (POST /api/workspaces/{slug}/restart) travels over that
		// SAME tunnel, that left the workspace stuck offline with no way to
		// recover except SSHing into the host and force-restarting the
		// container by hand (confirmed live 2026-08-21: the container
		// itself came up healthy on its own minutes later — only the tunnel
		// never came back because the process that owned it had already
		// exited). Backgrounding this means a readiness timeout just
		// retries with backoff — the tunnel, and therefore the restart
		// button, stay usable the whole time.
		go bootstrapWorkspaceSelfHeal(ctx, m.Only("workspace"), wsOpts, statePath, st)
	} else {
		rlog.Println("lean link: local runtime NOT installed — run 'bootstrap-workspace --with-workspace' (no --token needed, already linked) to provision it here, or trigger it from the control plane (the \"bootstrap\" verb over this same /link connection — see README).")
	}

	if runInBackground {
		svcCfg := servicemgr.Config{
			Slug: reg.slug, ExePath: resolveExePath(),
			ControlPlane: *controlPlane, Elevated: *elevated,
			// What makes the respawned service load THIS identity's
			// credentials rather than the first one's — and the reason the
			// generated unit sets no HOME. See servicemgr.Config.Instance.
			Instance: instanceName,
		}
		if err := installAndStartService(svcCfg); err != nil {
			return err
		}
		rlog.Println("Detaching — the background service now holds the /link connection.")
		switch runtime.GOOS {
		case "darwin":
			rlog.Println("(loginctl-equivalent not needed on macOS: LaunchAgents start automatically at login)")
		case "windows":
			rlog.Println("(loginctl-equivalent not needed on Windows: the Scheduled Task's logon trigger starts it at sign-in)")
			rlog.Println("Note: it starts at SIGN-IN, not at boot — a rebooted machine sitting at the lock screen is not linked yet.")
		default:
			rlog.Println("Run: loginctl enable-linger $USER   # so it survives logout/reboot")
		}
		stop() // cancel our own /link connection — the service owns it now
		<-runDone
		return nil
	}

	if provisionWorkspace {
		rlog.Printf("workspace %q linked — holding the /link connection open (Ctrl-C to stop this foreground run)\n", reg.slug)
	} else {
		rlog.Printf("linked to workspace %q (lean, no local runtime) — holding the /link connection open (Ctrl-C to stop this foreground run)\n", reg.slug)
	}
	<-ctx.Done()
	return <-runDone
}

// bootstrapWorkspaceSelfHeal runs the workspace module's
// detect->install->verify cycle in a loop until it succeeds or ctx is
// cancelled, backing off between attempts (workspaceSelfHealMinBackoff up
// to workspaceSelfHealMaxBackoff) instead of returning an error to a
// caller that would tear down the /link tunnel over it. See the call site
// in runBootstrapWorkspace for why this must not be synchronous.
func bootstrapWorkspaceSelfHeal(ctx context.Context, m *bootstrap.Manifest, opts bootstrap.RunOptions, statePath string, st *state.State) {
	backoff := workspaceSelfHealMinBackoff
	for {
		statuses, err := bootstrap.Run(ctx, m, opts)
		reportStatuses(statuses)
		if err == nil {
			if !st.Provisioned {
				st.Provisioned = true
				if err := state.Save(statePath, st); err != nil {
					rlog.Printf("workspace: bootstrapped but could not persist provisioned state: %v\n", err)
				}
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		rlog.Printf("workspace: bootstrap failed, retrying in %s: %v\n", backoff, err)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff *= 2
		if backoff > workspaceSelfHealMaxBackoff {
			backoff = workspaceSelfHealMaxBackoff
		}
	}
}

// startLANFastPath boots the LAN fast-path TLS terminator (case a) in the
// background if the per-workspace cert+key have been delivered. Absent cert
// (control-plane hasn't pushed it yet) is not an error — the workspace stays
// reachable via the /link tunnel; the terminator just doesn't offer the
// local bypass until the cert lands. Honors AW_LAN_FASTPATH_PORT (default
// 8443) and AW_LAN_FASTPATH_DISABLE=1 to opt out entirely.
func startLANFastPath(ctx context.Context, slug string) {
	if os.Getenv("AW_LAN_FASTPATH_DISABLE") == "1" {
		return
	}
	certFile, keyFile, ok := lanfastpath.LocateCert(slug)
	if !ok {
		rlog.Printf("lan-fastpath: no cert at %s yet — local bypass off, tunnel path unaffected\n", certFile)
		return
	}
	port := lanfastpath.DefaultPort
	if v := os.Getenv("AW_LAN_FASTPATH_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			port = p
		}
	}
	if addrs := lanfastpath.LANAddrs(); len(addrs) > 0 {
		rlog.Printf("lan-fastpath: LAN addrs %s — serving https :%d -> %s\n", strings.Join(addrs, ","), port, lanfastpath.DefaultTarget)
	} else {
		rlog.Printf("lan-fastpath: no private LAN addr found — serving https :%d anyway (localhost only)\n", port)
	}
	go func() {
		cfg := lanfastpath.Config{Port: port, CertFile: certFile, KeyFile: keyFile}
		if err := lanfastpath.Serve(ctx, cfg); err != nil && ctx.Err() == nil {
			rlog.Printf("lan-fastpath: terminator stopped: %v\n", err)
		}
	}()
}

// reportHostPowerStatus prints requested vs effective, and the delta.
//
// The delta is the reason this is in `status` at all: the failure this feature
// can produce is someone believing they enabled KVM on a machine that cannot
// provide it, and then debugging a slow VM instead of a missing device.
func reportHostPowerStatus(requested []string) {
	if len(requested) == 0 {
		rlog.Println("host-power: none (app containers get no host devices — the default)")
		return
	}
	res := hostpower.Resolve(requested)
	rlog.Printf("host-power: requested %s -> effective %s\n",
		hostpower.Format(requested), hostpower.Describe(res.Effective))
	for name, reason := range res.Refused {
		rlog.Printf("host-power:   %s NOT available — %s\n", name, reason)
	}
}

// reportInstances tells an operator how many tenant identities this MACHINE
// is serving, and which one they are currently looking at.
//
// Without it the feature is invisible: nothing else in `status`, and nothing
// in the console, distinguishes a machine serving one account from a machine
// serving two — so the next person to touch that box has no way to find out
// except by listing ~/.aw-remote-host/instances by hand. The line for the
// default instance is deliberately printed only when there IS something to
// report, so the overwhelmingly common single-identity host's output is
// unchanged.
func reportInstances(current string) {
	all, err := instance.List()
	if err != nil {
		return
	}
	others := make([]string, 0, len(all))
	for _, n := range all {
		if n != current {
			others = append(others, n)
		}
	}
	if current == "" {
		if len(others) == 0 {
			return // the single-identity host: output unchanged
		}
		rlog.Printf("instance: default — this machine also serves %d other tenant %s: %s\n",
			len(others), plural(len(others), "identity", "identities"), strings.Join(others, ", "))
		rlog.Println("instance: everything below is the DEFAULT instance only — re-run with --instance <name> to see one of the others.")
		return
	}
	rlog.Printf("instance: %s (this machine also has: default%s)\n",
		current, prefixed(", ", strings.Join(others, ", ")))
}

func prefixed(sep, s string) string {
	if s == "" {
		return ""
	}
	return sep + s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	_, plan, controlPlane := commonFlags(fs)
	instanceRaw := fs.String("instance", "", instanceFlagHelpLink)
	if err := fs.Parse(args); err != nil {
		return err
	}
	instanceName, _, err := resolveInstance(fs, *instanceRaw)
	if err != nil {
		return err
	}
	if *plan {
		rlog.Printf("[plan] would query link + module status from %s\n", *controlPlane)
		return nil
	}
	reportInstances(instanceName)

	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return err
	}
	creds, err := link.LoadCredentials(credPath)
	if err != nil {
		return err
	}
	if creds == nil {
		rlog.Println("linked: no (no credentials found — run bootstrap-workspace --token <awbs_...>)")
	} else {
		rlog.Printf("linked: yes (remote_host_id=%s)\n", creds.RemoteHostID)
	}

	statePath, err := state.DefaultPath()
	if err != nil {
		return err
	}
	st, err := state.Load(statePath)
	if err != nil {
		return err
	}
	if st.WorkspaceSlug != "" {
		rlog.Printf("workspace: %s\n", st.WorkspaceSlug)
	}
	reportHostPowerStatus(st.HostPower)
	reportVPNStatus(context.Background(), st)

	if mgr, mgrErr := servicemgr.Default(); mgrErr != nil {
		rlog.Printf("service: no supported service manager (%v)\n", mgrErr)
	} else {
		svcPath, pathErr := mgr.Path(servicemgr.Config{Slug: st.WorkspaceSlug, Instance: instanceName})
		if pathErr != nil {
			rlog.Printf("service (%s): could not resolve path: %v\n", mgr.Name(), pathErr)
		} else if _, statErr := os.Stat(svcPath); statErr == nil {
			rlog.Printf("service (%s): installed at %s\n", mgr.Name(), svcPath)
		} else {
			rlog.Printf("service (%s): not installed (run bootstrap-workspace --background to install)\n", mgr.Name())
		}
	}

	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return err
	}
	extractDir := extractDirFor(credPath)
	if err := bootstrap.ExtractScripts(extractDir); err != nil {
		return fmt.Errorf("extract bootstrap scripts: %w", err)
	}

	if !st.Provisioned {
		rlog.Println("provisioned: no (lean link — run bootstrap-workspace --with-workspace to install podman/postgres/redis/aw-workspace here)")
		return nil
	}

	ctx := context.Background()
	opts := bootstrap.RunOptions{ExtractDir: extractDir, Env: []string{"AW_POSTGRES_PASSWORD=" + st.PostgresPassword}}
	allOK := true
	// Default(), not Modules: an opt-in module this host never asked for is
	// not "not healthy", it is absent on purpose. reportVPNStatus above
	// already says what is true about the vpn module on this machine.
	for _, mod := range m.Default().Modules {
		ok, out := bootstrap.Detect(ctx, mod, opts)
		if ok {
			rlog.Printf("%s: healthy\n", mod.Name)
		} else {
			allOK = false
			rlog.Printf("%s: not healthy\n%s\n", mod.Name, out)
		}
	}
	if !allOK {
		return fmt.Errorf("one or more modules are not healthy")
	}
	return nil
}

func runUnlink(args []string) error {
	fs := flag.NewFlagSet("unlink", flag.ContinueOnError)
	_, plan, controlPlane := commonFlags(fs)
	stopContainers := fs.Bool("stop-containers", false, "also stop the podman containers this host started")
	instanceRaw := fs.String("instance", "", instanceFlagHelpLink)
	if err := fs.Parse(args); err != nil {
		return err
	}
	instanceName, _, err := resolveInstance(fs, *instanceRaw)
	if err != nil {
		return err
	}
	if *plan {
		credPath, credErr := link.DefaultCredentialsPath()
		if credErr != nil {
			return credErr
		}
		if instanceName != "" {
			rlog.Printf("[plan] would unlink instance %q ONLY — this machine's other instances, and its shared firewall/VPN/self-update state, are untouched\n", instanceName)
		}
		rlog.Printf("[plan] would remove %s and unlink from %s\n", credPath, *controlPlane)
		rlog.Println("[plan] would also POST /api/link/detach so the control plane revokes this host's credential and stops listing it")
		rlog.Println("[plan] would also stop and uninstall the background service, if installed")
		if *stopContainers {
			rlog.Println("[plan] would also stop: aw-remote-host-postgres, aw-remote-host-redis, aw-remote-host-workspace")
		}
		return nil
	}

	if statePath, err := state.DefaultPath(); err == nil {
		if st, stErr := state.Load(statePath); stErr == nil && st != nil {
			if mgr, mgrErr := servicemgr.Default(); mgrErr == nil {
				// Instance-scoped, and that is the whole of the Linux fix:
				// systemd's Path/Start/Stop/Uninstall used to ignore this
				// Config and act on one fixed unit name, so unlinking either
				// identity stopped, disabled and deleted the other's service.
				svcCfg := servicemgr.Config{Slug: st.WorkspaceSlug, Instance: instanceName}
				if svcPath, pathErr := mgr.Path(svcCfg); pathErr == nil {
					if _, statErr := os.Stat(svcPath); statErr == nil {
						if path, err := mgr.Uninstall(svcCfg); err != nil {
							rlog.Printf("unlink: could not uninstall %s service: %v\n", mgr.Name(), err)
						} else {
							rlog.Printf("unlink: uninstalled %s service (%s)\n", mgr.Name(), path)
						}
					}
				}
			}
		}
	}

	if *stopContainers {
		for _, name := range []string{"aw-remote-host-workspace", "aw-remote-host-postgres", "aw-remote-host-redis"} {
			cmd := exec.Command("podman", "stop", name)
			if err := cmd.Run(); err != nil {
				rlog.Printf("unlink: could not stop %s: %v\n", name, err)
			} else {
				rlog.Printf("unlink: stopped %s\n", name)
			}
		}
	}

	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return err
	}

	// Tell the control plane BEFORE deleting the credential that authenticates
	// the call — without this, unlink was purely local and the workspace kept
	// pointing at a host that had already gone (Kanban 3df5bf3b). Best-effort:
	// a machine being unlinked is often one that has lost its network, and a
	// control plane that cannot be reached must not stop the local unlink from
	// finishing. The operator is told what is left over instead.
	if creds, credErr := link.LoadCredentials(credPath); credErr == nil &&
		creds != nil && creds.HostCredential != "" {
		ctx, cancel := context.WithTimeout(context.Background(), link.DetachTimeout)
		if detachErr := link.Detach(ctx, *controlPlane, creds.HostCredential); detachErr != nil {
			rlog.Printf("unlink: could not tell %s this host is unlinking: %v\n", *controlPlane, detachErr)
			rlog.Println("unlink: this host may still be listed in the console — remove it there with Delete")
		} else {
			rlog.Println("unlink: control plane revoked this host's credential")
		}
		cancel()
	}

	if err := link.DeleteCredentials(credPath); err != nil {
		return err
	}
	rlog.Println("unlink: removed local credentials")

	// A named instance owns its whole directory, so removing it is the
	// honest end state — leaving an empty instances/<name>/ behind would
	// keep `status` reporting an identity this machine no longer serves,
	// which is the one thing that report exists to get right. The DEFAULT
	// instance's directory is never removed: it is ~/.aw-remote-host itself,
	// which holds this machine's firewall state, its VPN dead-man switch and
	// its self-update marker — none of which belong to the identity being
	// unlinked.
	if instanceName != "" {
		if dir, dirErr := instance.Dir(instanceName); dirErr == nil {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				rlog.Printf("unlink: could not remove instance dir %s: %v\n", dir, rmErr)
			} else {
				rlog.Printf("unlink: removed instance %q (%s) — this machine's other instances are untouched\n", instanceName, dir)
			}
		}
	}
	return nil
}

// linkProxy is what one live /link connection is handed: tunnelproxy's
// http_req/ws_* half (a reverse proxy onto the local workspace server) plus
// tcpproxy's tcp_* half (an arbitrary host:port dialled from this machine).
//
// Composed HERE rather than by embedding one package in the other, because
// they answer different questions — "proxy my known local service" vs "reach
// something on my network" — and neither should have to import the other to
// stay usable alone. Forwarded explicitly rather than by struct embedding:
// both types are named Handler, so embedding both is a duplicate-field
// compile error.
type linkProxy struct {
	web *tunnelproxy.Handler
	tcp *tcpproxy.Handler
}

func newLinkProxy() *linkProxy {
	return &linkProxy{web: tunnelproxy.NewHandler(), tcp: &tcpproxy.Handler{}}
}

func (p *linkProxy) ServeHTTP(ctx context.Context, id, method, path string,
	headers map[string]string, body []byte,
	head func(id string, status int, headers map[string]string),
	chunk func(id string, data []byte), end func(id string)) {
	p.web.ServeHTTP(ctx, id, method, path, headers, body, head, chunk, end)
}

func (p *linkProxy) OpenWS(ctx context.Context, id, path string, headers map[string]string,
	sendMsg func(id string, data []byte, isText bool)) error {
	return p.web.OpenWS(ctx, id, path, headers, sendMsg)
}

func (p *linkProxy) WSMessage(id string, data []byte, isText bool) error {
	return p.web.WSMessage(id, data, isText)
}

func (p *linkProxy) CloseWS(id string) error { return p.web.CloseWS(id) }

// CloseAllWS is what link calls when the connection drops. The tcp sessions
// are just as dead at that moment — nothing can deliver another tcp_data for
// them — so drain both here rather than leaking every dialled socket for the
// life of the process.
func (p *linkProxy) CloseAllWS() {
	p.web.CloseAllWS()
	p.tcp.CloseAllTCP()
}

func (p *linkProxy) OpenTCP(ctx context.Context, id, host string, port int,
	sendData func(id string, data []byte), onEOF func(id string, reason string)) error {
	return p.tcp.OpenTCP(ctx, id, host, port, sendData, onEOF)
}

func (p *linkProxy) SendTCP(id string, data []byte) error { return p.tcp.SendTCP(id, data) }
func (p *linkProxy) CloseTCP(id string) error             { return p.tcp.CloseTCP(id) }
func (p *linkProxy) CloseAllTCP()                         { p.tcp.CloseAllTCP() }
