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

const defaultControlPlane = "https://api.aw.tekflox.com"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "bootstrap-workspace":
		err = runBootstrapWorkspace(args)
	case "status":
		err = runStatus(args)
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
  bootstrap-workspace   Install/verify the workspace runtime (podman, postgres+pgvector, redis)
  status                Show link + bootstrap status
  unlink                Disconnect this machine from the control plane
  version               Print the client version

Flags (bootstrap-workspace, status, unlink):
  --token           Bearer token identifying this machine to the control plane
  --plan            Print planned actions without executing them
  --control-plane   Control plane base URL (default %s)
`, defaultControlPlane)
}
