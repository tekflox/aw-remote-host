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
	"github.com/tekflox/aw-remote-host/internal/firewall"
	"github.com/tekflox/aw-remote-host/internal/hostpower"
	"github.com/tekflox/aw-remote-host/internal/lanfastpath"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/ops"
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

func reportStatuses(statuses []bootstrap.ModuleStatus) {
	for _, st := range statuses {
		switch {
		case st.AlreadyOK:
			fmt.Printf("%s: already ok, skipped install\n", st.Module)
		case st.OK:
			fmt.Printf("%s: installed and verified\n", st.Module)
		default:
			fmt.Printf("%s: FAILED\n", st.Module)
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
			fmt.Fprintf(os.Stderr, "host-power: %s NOT granted — %s\n", name, reason)
		}
	}
	if len(res.Effective) == 0 {
		return "", fmt.Errorf(
			"host-power: none of %s can be delivered by this host — see the reasons above",
			strings.Join(requested, ","))
	}
	fmt.Printf("host-power: %s\n", hostpower.Describe(res.Effective))
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
	var withWorkspace, full *bool
	if allowProvision {
		withWorkspace = fs.Bool("with-workspace", false, "also install/start the full local runtime (podman, postgres+pgvector, redis, the aw-workspace container) — default is a LEAN link: register this machine and hold /link (enables exec_* + control-plane-driven \"bootstrap\") without provisioning anything locally. Re-run with this flag later (no --token needed once linked) to provision, or trigger it remotely via the control plane's own \"bootstrap\" verb (see README) — no need to re-run by hand.")
		full = fs.Bool("full", false, "alias for --with-workspace")
	}
	hostPower := fs.String("host-power", "", "comma-separated elevated host access to grant app containers on this machine (default: none). Grants:\n"+hostpower.Help()+
		"Only what this host can actually deliver is granted — each grant is probed, and anything undeliverable is reported, not silently assumed. An app must ALSO declare it in runtime.host_power and hold the matching host:* permission. Re-run with a different value to change it; pass --host-power=none to revoke.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Parse before anything else touches the disk: a typo'd grant name must
	// abort here, not halfway through provisioning.
	hostPowerRequested, hostPowerChanged, err := parseHostPowerFlag(fs, *hostPower)
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
			fmt.Printf("[plan] would provision the workspace inside a WSL2 distro (%s):\n", wsl.DefaultDistro)
			for _, step := range []string{
				"update the WSL kernel",
				"download the Ubuntu rootfs and import it as " + wsl.DefaultDistro,
				"enable systemd inside it",
				"install aw-remote-host inside it",
				"run bootstrap-workspace --with-workspace in there (podman, postgres, redis, workspace)",
				"install a systemd service inside it, and a Startup-folder keep-alive out here",
			} {
				fmt.Printf("[plan] wsl: %s\n", step)
			}
			return nil
		}
		return wsl.ProvisionWorkspace(wsl.Options{
			Token:        *token,
			ControlPlane: *controlPlane,
			Log:          func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
		})
	}

	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return err
	}

	if *plan {
		if provisionWorkspace {
			fmt.Printf("[plan] would link to %s as this machine, then run:\n", *controlPlane)
			for _, a := range bootstrap.Plan(m.Default()) {
				fmt.Printf("[plan] %s: %s — %s\n", a.Module, a.Step, a.Detail)
			}
		} else {
			fmt.Printf("[plan] would link to %s as this machine (lean: no local provisioning — use 'bootstrap-workspace --with-workspace' to also run):\n", *controlPlane)
			for _, a := range bootstrap.Plan(m.Default()) {
				fmt.Printf("[plan] (skipped — lean %s) %s: %s — %s\n", cmdName, a.Module, a.Step, a.Detail)
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

	if !*yes {
		if provisionWorkspace {
			fmt.Println("This will install/verify: podman, postgres+pgvector, redis, and start the aw-workspace runtime on this machine.")
		} else {
			fmt.Println("This will register this machine with the control plane and hold the /link connection open (enables exec_* + a control-plane-driven \"bootstrap\" later) — no local runtime (podman, postgres, redis, aw-workspace) is installed. Use 'bootstrap-workspace --with-workspace' to also do that now.")
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
		fmt.Println("--host-power=privileged removes container isolation for every app that requests it on this machine: an app container gets every device and every Linux capability, which is root-equivalent access to this host.")
		fmt.Println("Prefer naming the specific grants an app needs (e.g. --host-power=kvm,tun), or --host-power=all for every device grant without dropping isolation.")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Lean by default: skip local infra provisioning entirely unless
	// --with-workspace opted in. The /link registration below (and the
	// ops.Handler it wires up) works standalone — exec_* and the
	// control-plane-driven "bootstrap" verb (src/api/placement/
	// remote_host_driver.py) don't need any module installed locally first.
	if provisionWorkspace {
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
	}

	hostname, _ := os.Hostname()
	c := link.New(*controlPlane, *token)
	c.Info = link.RegisterInfo{
		Hostname:           hostname,
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		CLIVersion:         version,
		HostPower:          hostPowerEnv,
		HostPowerRequested: hostpower.Format(st.HostPower),
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
		fmt.Fprintf(os.Stderr, "firewall: self-heal failed (continuing): %v\n", err)
	}

	// Same bargain for an external-tunnel route (internal/vpn/externalroute.go),
	// and it is not optional here: this rule is a routing POLICY rule, and
	// systemd-networkd flushes every one it does not own whenever it restarts
	// — which on the production bare metal is whatever the daily unattended
	// apt upgrade decides. Measured 2026-09-02: networkd restarted at 06:48:54
	// and the aw-vpn-hub rules installed at boot were gone, on a container
	// that had not restarted. tailscaled survives that only because it does
	// exactly this. A no-op on every host that has no external route recorded.
	reassertRunner := vpn.PrivilegedRunner{Inner: ops.DefaultRunner, Sudo: runtime.GOOS != "darwin" && runtime.GOOS != "windows" && os.Geteuid() != 0}
	go vpn.ReassertLoop(ctx, reassertRunner, func(restored []string, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "vpn: could not re-assert the external route (continuing): %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "vpn: re-asserted the external route after something flushed it: %s\n", strings.Join(restored, ", "))
	})

	go func() {
		runDone <- c.Run(ctx, credPath, link.RunCallbacks{
			OnRegistered: func(reply *link.RegisteredReply) {
				if reply.WorkspaceSlug != "" {
					st.WorkspaceSlug = reply.WorkspaceSlug
					_ = state.Save(statePath, st)
				}
				if err := updater.ClearPending(); err != nil {
					fmt.Fprintf(os.Stderr, "self-update: could not clear rollback marker after registration: %v\n", err)
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
				}
				fmt.Printf("link: registered (remote_host_id=%s, workspace=%s)\n", reply.RemoteHostID, reply.WorkspaceSlug)
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
					fmt.Fprintf(os.Stderr, "link: disconnected: %v\n", err)
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

	if provisionWorkspace {
		wsOpts := bootstrap.RunOptions{
			ExtractDir: extractDir,
			Env: append(bootstrap.EnvPassthrough("AW_WORKSPACE_IMAGE", "XDG_RUNTIME_DIR"),
				"AW_WORKSPACE_SLUG="+reg.slug,
				"AW_POSTGRES_PASSWORD="+st.PostgresPassword,
				"AW_BACKEND_URL="+*controlPlane,
				"AW_WORKSPACE_HOST_TOKEN="+reg.hostCredential,
				"AW_HOST_POWER="+hostPowerEnv,
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
		fmt.Println("lean link: local runtime NOT installed — run 'bootstrap-workspace --with-workspace' (no --token needed, already linked) to provision it here, or trigger it from the control plane (the \"bootstrap\" verb over this same /link connection — see README).")
	}

	if runInBackground {
		svcCfg := servicemgr.Config{
			Slug: reg.slug, ExePath: resolveExePath(),
			ControlPlane: *controlPlane, Elevated: *elevated,
		}
		if err := installAndStartService(svcCfg); err != nil {
			return err
		}
		fmt.Println("Detaching — the background service now holds the /link connection.")
		switch runtime.GOOS {
		case "darwin":
			fmt.Println("(loginctl-equivalent not needed on macOS: LaunchAgents start automatically at login)")
		case "windows":
			fmt.Println("(loginctl-equivalent not needed on Windows: the Scheduled Task's logon trigger starts it at sign-in)")
			fmt.Println("Note: it starts at SIGN-IN, not at boot — a rebooted machine sitting at the lock screen is not linked yet.")
		default:
			fmt.Println("Run: loginctl enable-linger $USER   # so it survives logout/reboot")
		}
		stop() // cancel our own /link connection — the service owns it now
		<-runDone
		return nil
	}

	if provisionWorkspace {
		fmt.Printf("workspace %q linked — holding the /link connection open (Ctrl-C to stop this foreground run)\n", reg.slug)
	} else {
		fmt.Printf("linked to workspace %q (lean, no local runtime) — holding the /link connection open (Ctrl-C to stop this foreground run)\n", reg.slug)
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
					fmt.Fprintf(os.Stderr, "workspace: bootstrapped but could not persist provisioned state: %v\n", err)
				}
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "workspace: bootstrap failed, retrying in %s: %v\n", backoff, err)
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
		fmt.Printf("lan-fastpath: no cert at %s yet — local bypass off, tunnel path unaffected\n", certFile)
		return
	}
	port := lanfastpath.DefaultPort
	if v := os.Getenv("AW_LAN_FASTPATH_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			port = p
		}
	}
	if addrs := lanfastpath.LANAddrs(); len(addrs) > 0 {
		fmt.Printf("lan-fastpath: LAN addrs %s — serving https :%d -> %s\n", strings.Join(addrs, ","), port, lanfastpath.DefaultTarget)
	} else {
		fmt.Printf("lan-fastpath: no private LAN addr found — serving https :%d anyway (localhost only)\n", port)
	}
	go func() {
		cfg := lanfastpath.Config{Port: port, CertFile: certFile, KeyFile: keyFile}
		if err := lanfastpath.Serve(ctx, cfg); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "lan-fastpath: terminator stopped: %v\n", err)
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
		fmt.Println("host-power: none (app containers get no host devices — the default)")
		return
	}
	res := hostpower.Resolve(requested)
	fmt.Printf("host-power: requested %s -> effective %s\n",
		hostpower.Format(requested), hostpower.Describe(res.Effective))
	for name, reason := range res.Refused {
		fmt.Printf("host-power:   %s NOT available — %s\n", name, reason)
	}
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	_, plan, controlPlane := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *plan {
		fmt.Printf("[plan] would query link + module status from %s\n", *controlPlane)
		return nil
	}

	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return err
	}
	creds, err := link.LoadCredentials(credPath)
	if err != nil {
		return err
	}
	if creds == nil {
		fmt.Println("linked: no (no credentials found — run bootstrap-workspace --token <awbs_...>)")
	} else {
		fmt.Printf("linked: yes (remote_host_id=%s)\n", creds.RemoteHostID)
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
		fmt.Printf("workspace: %s\n", st.WorkspaceSlug)
	}
	reportHostPowerStatus(st.HostPower)
	reportVPNStatus(context.Background(), st)

	if mgr, mgrErr := servicemgr.Default(); mgrErr != nil {
		fmt.Printf("service: no supported service manager (%v)\n", mgrErr)
	} else {
		svcPath, pathErr := mgr.Path(servicemgr.Config{Slug: st.WorkspaceSlug})
		if pathErr != nil {
			fmt.Printf("service (%s): could not resolve path: %v\n", mgr.Name(), pathErr)
		} else if _, statErr := os.Stat(svcPath); statErr == nil {
			fmt.Printf("service (%s): installed at %s\n", mgr.Name(), svcPath)
		} else {
			fmt.Printf("service (%s): not installed (run bootstrap-workspace --background to install)\n", mgr.Name())
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
		fmt.Println("provisioned: no (lean link — run bootstrap-workspace --with-workspace to install podman/postgres/redis/aw-workspace here)")
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
			fmt.Printf("%s: healthy\n", mod.Name)
		} else {
			allOK = false
			fmt.Printf("%s: not healthy\n%s\n", mod.Name, out)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *plan {
		fmt.Printf("[plan] would remove ~/.aw-remote-host/credentials.json and unlink from %s\n", *controlPlane)
		fmt.Println("[plan] would also stop and uninstall the background service, if installed")
		if *stopContainers {
			fmt.Println("[plan] would also stop: aw-remote-host-postgres, aw-remote-host-redis, aw-remote-host-workspace")
		}
		return nil
	}

	if statePath, err := state.DefaultPath(); err == nil {
		if st, stErr := state.Load(statePath); stErr == nil && st != nil {
			if mgr, mgrErr := servicemgr.Default(); mgrErr == nil {
				svcCfg := servicemgr.Config{Slug: st.WorkspaceSlug}
				if svcPath, pathErr := mgr.Path(svcCfg); pathErr == nil {
					if _, statErr := os.Stat(svcPath); statErr == nil {
						if path, err := mgr.Uninstall(svcCfg); err != nil {
							fmt.Fprintf(os.Stderr, "unlink: could not uninstall %s service: %v\n", mgr.Name(), err)
						} else {
							fmt.Printf("unlink: uninstalled %s service (%s)\n", mgr.Name(), path)
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
				fmt.Fprintf(os.Stderr, "unlink: could not stop %s: %v\n", name, err)
			} else {
				fmt.Printf("unlink: stopped %s\n", name)
			}
		}
	}

	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return err
	}
	if err := link.DeleteCredentials(credPath); err != nil {
		return err
	}
	fmt.Println("unlink: removed local credentials")
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
