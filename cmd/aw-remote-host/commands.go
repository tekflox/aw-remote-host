package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/link"
)

// manifestPath locates bootstrap/manifest.json relative to this binary's
// repo checkout. Card 4 will make this configurable / embed the manifest;
// for the skeleton it's enough to resolve it next to the source tree.
func manifestPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "bootstrap", "manifest.json")
}

func commonFlags(fs *flag.FlagSet) (token *string, plan *bool, controlPlane *string) {
	token = fs.String("token", "", "bearer token identifying this machine to the control plane")
	plan = fs.Bool("plan", false, "print planned actions without executing them")
	controlPlane = fs.String("control-plane", defaultControlPlane, "control plane base URL")
	return
}

func runBootstrapWorkspace(args []string) error {
	fs := flag.NewFlagSet("bootstrap-workspace", flag.ContinueOnError)
	token, plan, controlPlane := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *token == "" && !*plan {
		return fmt.Errorf("--token is required (or pass --plan to preview without a token)")
	}

	m, err := bootstrap.LoadManifest(manifestPath())
	if err != nil {
		return err
	}

	if *plan {
		fmt.Printf("[plan] would link to %s as this machine, then run:\n", *controlPlane)
		return bootstrap.Run(m, true)
	}

	c := link.New(*controlPlane, *token)
	if err := c.Dial(); err != nil {
		return err
	}
	return bootstrap.Run(m, false)
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
	return fmt.Errorf("status not implemented yet (see card 4)")
}

func runUnlink(args []string) error {
	fs := flag.NewFlagSet("unlink", flag.ContinueOnError)
	_, plan, controlPlane := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *plan {
		fmt.Printf("[plan] would remove ~/.aw-remote-host/credentials.json and unlink from %s\n", *controlPlane)
		return nil
	}
	return fmt.Errorf("unlink not implemented yet (see card 4)")
}
