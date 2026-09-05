// Command aw-remote-host is the BYOD bootstrap client: it links a user's
// own machine to the AW control plane and installs the runtime components
// (podman, postgres+pgvector, redis, workspace) needed to run an AW
// workspace locally. Every action it can take is in this repo — nothing it
// runs is opaque or pulled from a private source.
package main

import (
	"fmt"
	"os"
)

// version is set via -ldflags "-X main.version=vX.Y.Z" at release build time.
var version = "dev"

// windowless is set to "true" via -ldflags at build time for the Windows
// `aw-remote-hostw.exe` variant, which is additionally linked with
// -H=windowsgui so Task Scheduler can run it without a console window
// parked on the user's desktop for as long as the machine is up.
//
// The catch that makes this flag necessary rather than just a link mode: a
// GUI-subsystem binary has NO console, so stdout and stderr go nowhere at
// all. Every line this process logs — registration, reconnects, the reason
// a link dropped — would be silently discarded, which is precisely the
// silent-degradation failure this project keeps being bitten by. So the
// windowless build redirects both to a log file instead.
var windowless = ""

const defaultControlPlane = "https://api.aw.tekflox.com"

func main() {
	redirectOutputIfWindowless()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "link":
		err = runLink(args)
	case "bootstrap-workspace":
		err = runBootstrapWorkspace(args)
	case "status":
		err = runStatus(args)
	case "vpn":
		err = runVPN(args)
	case "unlink":
		err = runUnlink(args)
	case "version":
		fmt.Println(version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "aw-remote-host: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "aw-remote-host: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `aw-remote-host — BYOD bootstrap client for Agentic Workspace

Usage:
  aw-remote-host <command> [flags]

Commands:
  link                  Register this machine and hold /link — nothing else,
                        ever. No local runtime, no --with-workspace/--full
                        (rejected if passed). Enables exec_* command
                        execution. Use bootstrap-workspace instead if you
                        might want the local runtime.
  bootstrap-workspace   Same lean link as "link" by default, but accepts
                        --with-workspace to also provision the local
                        runtime (now or later — see below).
  status                Show link + bootstrap status
  vpn                   Join this machine to the tenant's mesh (headscale).
                        Opt-in — never run by a plain bootstrap. Installs
                        tailscale, enrols the node, and can ADVERTISE it as
                        an exit node. Enrolling never changes this machine's
                        default route; the two subcommands below do.
%s
%s
  unlink                Disconnect this machine from the control plane
  version               Print the client version

Flags (link, bootstrap-workspace, status, unlink):
  --token           Bearer token identifying this machine to the control plane
  --plan            Print planned actions without executing them
  --control-plane   Control plane base URL (default %s)
  --yes             (link, bootstrap-workspace) skip the confirmation prompt
  --with-workspace/--full
                    (bootstrap-workspace ONLY — "link" doesn't have this flag)
                    also install/start the full local runtime — podman,
                    postgres+pgvector, redis, and the aw-workspace container.
                    DEFAULT (both commands) is a LEAN link: register this
                    machine and hold /link (enables exec_* command execution
                    + a control-plane-driven "bootstrap" later) without
                    installing anything locally. Re-run bootstrap-workspace
                    later with this flag (no --token needed once linked) to
                    provision, or trigger it from the control plane instead
                    — no need to come back to this machine by hand.
  --foreground/--fg (link, bootstrap-workspace) run attached, holding the
                    /link connection; installs no background service. This
                    is the DEFAULT when neither --foreground nor
                    --background is given — so a first run is always
                    visible before you decide to background it.
  --background/--detach
                    (link, bootstrap-workspace) install and start a
                    background service — launchd on macOS, systemd on
                    Linux — then detach; the service itself runs with
                    --foreground.
  --stop-containers (unlink) also stop the podman containers this host started

Flags (vpn):
  --login-server    the tenant's headscale, e.g. https://headscale.aw.tekflox.com
                    (required — never defaulted: one headscale per tenant)
  --authkey         a headscale pre-auth key, for a first enrolment
  --hostname        node name in the mesh (default: this machine's hostname)
  --advertise-exit-node
                    offer this node as an exit gate. Advertising does not
                    change this machine's own routing, and a headscale admin
                    still has to approve the route before any peer can use it.
  --accept-dns      accept MagicDNS (off by default — it rewrites this host's
                    resolver)
  --plan            print the eligibility verdict and what would run, and
                    change nothing

unlink also stops and uninstalls the background service (launchd/systemd),
if one was installed.
`, vpnExitUsage, vpnExternalUsage, defaultControlPlane)
}
