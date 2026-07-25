// Package servicemgr abstracts "install/start/stop/uninstall a background
// service that keeps `aw-remote-host bootstrap-workspace` running" across
// the two platforms the BYOD onboarding chain targets: systemd (Linux) and
// launchd (macOS, e.g. the macbook-fred e2e box — no systemd there).
package servicemgr

import (
	"fmt"
	"runtime"
)

// Config carries what a Manager needs to render its service definition.
// Slug scopes the macOS launchd label/plist filename (a machine could in
// principle run more than one workspace-host link); it's informational on
// the systemd side, which only ever manages a single fixed unit name.
type Config struct {
	Slug         string // workspace slug, known once /link has registered
	ExePath      string // absolute path to the aw-remote-host binary
	ControlPlane string
}

// Manager installs/starts/stops/uninstalls the background service that
// runs `aw-remote-host bootstrap-workspace --foreground` on this host's
// behalf. Every method takes Config explicitly (rather than a Manager
// storing it) because Start/Stop/Uninstall commonly run in a fresh CLI
// invocation (e.g. `unlink`) that only has the slug from state.json, not
// from a live Install() call in the same process.
type Manager interface {
	// Name identifies the underlying service manager, e.g. "systemd" or
	// "launchd" — used in CLI output.
	Name() string
	// Path returns where the service definition would be/is written,
	// without writing anything — used by `status` to report it.
	Path(cfg Config) (string, error)
	// Install (over)writes the service definition and reloads the
	// manager's unit cache. Returns the path written.
	Install(cfg Config) (string, error)
	// Start enables and starts the installed service.
	Start(cfg Config) error
	// Stop stops the service; best-effort, no error if it isn't running.
	Stop(cfg Config) error
	// Uninstall stops the service (if running) and removes its
	// definition file. Returns the path removed.
	Uninstall(cfg Config) (string, error)
}

// New returns the Manager for goos, or an error if goos isn't supported.
// Takes goos explicitly (rather than reading runtime.GOOS itself) so
// callers can test both branches from a single-GOOS test binary.
func New(goos string) (Manager, error) {
	switch goos {
	case "linux":
		return &systemdManager{}, nil
	case "darwin":
		return &launchdManager{}, nil
	default:
		return nil, fmt.Errorf("no service manager for GOOS=%q (supported: linux, darwin)", goos)
	}
}

// Default returns New(runtime.GOOS) — what the CLI actually uses.
func Default() (Manager, error) {
	return New(runtime.GOOS)
}
