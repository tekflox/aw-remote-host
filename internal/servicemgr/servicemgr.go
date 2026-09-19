// Package servicemgr abstracts "install/start/stop/uninstall a background
// service that keeps `aw-remote-host bootstrap-workspace` running" across
// the three platforms this CLI targets: systemd (Linux), launchd (macOS,
// e.g. the macbook-fred e2e box — no systemd there) and Task Scheduler
// (Windows, via schtasks).
//
// Windows only ever reaches this package for a LEAN link — the local
// runtime a full `--with-workspace` provision stands up is podman plus a
// Linux container image, neither of which exists there. What a Windows host
// gets is the /link connection itself: remote exec, the fs_* verbs, process
// listing. See the "Windows (lean link only)" section of the README.
package servicemgr

import (
	"fmt"
	"runtime"
)

// Config carries what a Manager needs to render its service definition.
// Slug scopes the macOS launchd label/plist filename; Instance scopes the
// systemd unit name, the launchd label and the Scheduled Task name, and is
// what a machine serving more than one tenant identity is keyed on.
type Config struct {
	Slug         string // workspace slug, known once /link has registered
	ExePath      string // absolute path to the aw-remote-host binary
	ControlPlane string
	// Instance names the tenant identity this service definition belongs
	// to — "" for the default (unnamed) instance, which every host linked
	// before instances existed is.
	//
	// It does two things, and the second is the point of the first:
	//
	//  1. It scopes the unit/task name and the definition's path, so a
	//     second identity's `link --background` cannot overwrite the
	//     first's unit — which is what the systemd branch did, silently,
	//     for as long as it ignored this Config.
	//  2. It is passed to the binary as `--instance <name>` in
	//     ProgramArguments/ExecStart. That, and NOT a HOME override, is how
	//     the respawned service finds its own credentials: the generated
	//     launchd plist has no EnvironmentVariables key at all, so a
	//     hand-set HOME survived only the operator's foreground shell and
	//     the next launchd respawn silently loaded the FIRST account's
	//     credentials.json. HOME would also move podman's storage root, the
	//     Go build cache and ssh, which is what made that workaround unsafe
	//     rather than merely fragile.
	//
	// The default instance's rendered definition, unit name and launchd
	// label MUST stay byte-identical to what pre-instance releases wrote:
	// every BYOD host in the field is an unnamed instance, and a renamed
	// unit orphans them all on upgrade (old unit still enabled, new name
	// never started).
	Instance string
	// Elevated asks the OS to run the link with administrative rights.
	//
	// Windows only today. The default is deliberately off: everything the
	// lean link exists to do — exec, file transfer, ConPTY — works fine
	// unprivileged, and an install that silently demands admin is a worse
	// default than one that cannot restart a service.
	//
	// What it unlocks is the class of task that is NOT optional-extra but
	// simply impossible without it, and which reads to a user as the tool
	// being broken: restarting a Windows service, writing under
	// C:\Program Files, editing another service's config. Diagnosing a
	// remote desktop on 2026-08-24 hit all three in one session — the
	// symptom each time was an "Access denied" buried in a command's
	// output, not a refusal the caller could see coming.
	Elevated bool
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

// serviceArgs returns the argv (everything after the binary path) that the
// generated service definition runs, shared by the systemd and launchd
// renderers so the two can never drift.
//
// The DEFAULT instance runs `bootstrap-workspace --control-plane <cp> --yes
// --foreground` — byte-for-byte the spelling already on disk in every BYOD
// host's unit file. Do not "tidy" it.
//
// A NAMED instance runs `link` instead, and that substitution is load-
// bearing rather than cosmetic: a second identity on a machine is lean-only
// (two full workspaces collide on container names, the published port and
// the podman network — see the link command's refusal), and `link` is the
// command that structurally cannot provision. It also carries --instance,
// which is what makes the respawned service load ITS OWN credentials.
func serviceArgs(cfg Config) []string {
	if cfg.Instance == "" {
		return []string{"bootstrap-workspace", "--control-plane", cfg.ControlPlane, "--yes", "--foreground"}
	}
	return []string{"link", "--instance", cfg.Instance, "--control-plane", cfg.ControlPlane, "--yes", "--foreground"}
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
	case "windows":
		return &schtasksManager{}, nil
	default:
		return nil, fmt.Errorf("no service manager for GOOS=%q (supported: linux, darwin, windows)", goos)
	}
}

// Default returns New(runtime.GOOS) — what the CLI actually uses.
func Default() (Manager, error) {
	return New(runtime.GOOS)
}
