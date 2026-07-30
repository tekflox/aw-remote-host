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
	"github.com/tekflox/aw-remote-host/internal/lanfastpath"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/ops"
	"github.com/tekflox/aw-remote-host/internal/servicemgr"
	"github.com/tekflox/aw-remote-host/internal/shell"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/tunnelproxy"
	"github.com/tekflox/aw-remote-host/internal/updater"
)

// registerTimeout bounds how long bootstrap-workspace waits for the first
// /link registration reply before giving up.
const registerTimeout = 30 * time.Second

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

func confirm(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(answer)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

func runBootstrapWorkspace(args []string) error {
	fs := flag.NewFlagSet("bootstrap-workspace", flag.ContinueOnError)
	token, plan, controlPlane := commonFlags(fs)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	foreground := fs.Bool("foreground", false, "run attached, holding the /link connection; installs no service (default when neither flag is given)")
	fg := fs.Bool("fg", false, "alias for --foreground")
	background := fs.Bool("background", false, "install and start a background service (launchd on macOS, systemd on Linux), then detach")
	detach := fs.Bool("detach", false, "alias for --background")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fgMode := *foreground || *fg
	bgMode := *background || *detach
	if fgMode && bgMode {
		return fmt.Errorf("--foreground and --background are mutually exclusive")
	}
	runInBackground := bgMode // default (neither flag given) is foreground

	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return err
	}

	if *plan {
		fmt.Printf("[plan] would link to %s as this machine, then run:\n", *controlPlane)
		for _, a := range bootstrap.Plan(m) {
			fmt.Printf("[plan] %s: %s — %s\n", a.Module, a.Step, a.Detail)
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
		fmt.Println("This will install/verify: podman, postgres+pgvector, redis, and start the aw-workspace runtime on this machine.")
		if !confirm("Continue? [y/N] ") {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	infra := m.Except("workspace")
	infraOpts := bootstrap.RunOptions{
		ExtractDir: extractDir,
		Env:        []string{"AW_POSTGRES_PASSWORD=" + st.PostgresPassword},
	}
	statuses, err := bootstrap.Run(ctx, infra, infraOpts)
	reportStatuses(statuses)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	c := link.New(*controlPlane, *token)
	c.Info = link.RegisterInfo{
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		CLIVersion: version,
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
				return tunnelproxy.NewHandler()
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
		return fmt.Errorf("registered but the control plane didn't return a workspace_slug — cannot start the workspace runtime")
	}

	wsOpts := bootstrap.RunOptions{
		ExtractDir: extractDir,
		Env: append(bootstrap.EnvPassthrough("AW_WORKSPACE_IMAGE", "XDG_RUNTIME_DIR"),
			"AW_WORKSPACE_SLUG="+reg.slug,
			"AW_POSTGRES_PASSWORD="+st.PostgresPassword,
			"AW_BACKEND_URL="+*controlPlane,
			"AW_WORKSPACE_HOST_TOKEN="+reg.hostCredential,
		),
	}
	wsStatuses, err := bootstrap.Run(ctx, m.Only("workspace"), wsOpts)
	reportStatuses(wsStatuses)
	if err != nil {
		return err
	}

	if runInBackground {
		svcCfg := servicemgr.Config{Slug: reg.slug, ExePath: resolveExePath(), ControlPlane: *controlPlane}
		if err := installAndStartService(svcCfg); err != nil {
			return err
		}
		fmt.Println("Detaching — the background service now holds the /link connection.")
		if runtime.GOOS == "darwin" {
			fmt.Println("(loginctl-equivalent not needed on macOS: LaunchAgents start automatically at login)")
		} else {
			fmt.Println("Run: loginctl enable-linger $USER   # so it survives logout/reboot")
		}
		stop() // cancel our own /link connection — the service owns it now
		<-runDone
		return nil
	}

	fmt.Printf("workspace %q running — holding the /link connection open (Ctrl-C to stop this foreground run)\n", reg.slug)
	<-ctx.Done()
	return <-runDone
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

	ctx := context.Background()
	opts := bootstrap.RunOptions{ExtractDir: extractDir, Env: []string{"AW_POSTGRES_PASSWORD=" + st.PostgresPassword}}
	allOK := true
	for _, mod := range m.Modules {
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
