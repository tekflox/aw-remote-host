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
	"strings"
	"syscall"
	"time"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/state"
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
	if err := fs.Parse(args); err != nil {
		return err
	}

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
		slug         string
		remoteHostID string
	}
	registered := make(chan registration, 1)
	runDone := make(chan error, 1)

	go func() {
		runDone <- c.Run(ctx, credPath, link.RunCallbacks{
			OnRegistered: func(reply *link.RegisteredReply) {
				if reply.WorkspaceSlug != "" {
					st.WorkspaceSlug = reply.WorkspaceSlug
					_ = state.Save(statePath, st)
				}
				fmt.Printf("link: registered (remote_host_id=%s, workspace=%s)\n", reply.RemoteHostID, reply.WorkspaceSlug)
				select {
				case registered <- registration{slug: reply.WorkspaceSlug, remoteHostID: reply.RemoteHostID}:
				default:
				}
			},
			OnDisconnect: func(err error) {
				if err != nil {
					fmt.Fprintf(os.Stderr, "link: disconnected: %v\n", err)
				}
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
		Env: []string{
			"AW_WORKSPACE_SLUG=" + reg.slug,
			"AW_POSTGRES_PASSWORD=" + st.PostgresPassword,
			"AW_BACKEND_URL=" + *controlPlane,
		},
	}
	wsStatuses, err := bootstrap.Run(ctx, m.Only("workspace"), wsOpts)
	reportStatuses(wsStatuses)
	if err != nil {
		return err
	}

	if err := writeSystemdUnit(*controlPlane); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write systemd user unit: %v\n", err)
	} else {
		unitPath, _ := systemdUnitPath()
		fmt.Printf("systemd user unit written to %s\n", unitPath)
		fmt.Println("Run: systemctl --user daemon-reload && systemctl --user enable --now aw-remote-host")
		fmt.Println("Then: loginctl enable-linger $USER   # so it survives logout/reboot")
	}

	fmt.Printf("workspace %q running — holding the /link connection open (Ctrl-C to stop this foreground run)\n", reg.slug)
	<-ctx.Done()
	return <-runDone
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
		if *stopContainers {
			fmt.Println("[plan] would also stop: aw-remote-host-postgres, aw-remote-host-redis, aw-remote-host-workspace")
		}
		return nil
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
