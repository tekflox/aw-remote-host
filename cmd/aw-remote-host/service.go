package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tekflox/aw-remote-host/internal/servicemgr"
)

// resolveExePath returns an absolute path to the running binary, for use
// in the generated service definition's ProgramArguments/ExecStart — a
// relative os.Args[0] wouldn't resolve once launchd/systemd invoke it
// from a different working directory.
func resolveExePath() string {
	if p, err := exec.LookPath(os.Args[0]); err == nil {
		return p
	}
	if p, err := filepath.Abs(os.Args[0]); err == nil {
		return p
	}
	return os.Args[0]
}

// installAndStartService installs (or replaces) and starts the background
// service for this OS (launchd on macOS, systemd on Linux) so the /link
// connection survives after this foreground process exits.
func installAndStartService(cfg servicemgr.Config) error {
	mgr, err := servicemgr.Default()
	if err != nil {
		return fmt.Errorf("--background needs a supported service manager: %w", err)
	}
	path, err := mgr.Install(cfg)
	if err != nil {
		return fmt.Errorf("install %s service: %w", mgr.Name(), err)
	}
	if err := mgr.Start(cfg); err != nil {
		return fmt.Errorf("start %s service: %w", mgr.Name(), err)
	}
	fmt.Printf("%s service installed (%s) and started.\n", mgr.Name(), path)
	return nil
}
