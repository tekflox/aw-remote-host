// Package assets embeds this directory's manifest and module scripts into
// the compiled aw-remote-host binary. install.sh only ships the binary
// (see repo root README's transparency contract) — the module scripts have
// to travel with it rather than being read off a repo checkout that may
// not exist on the target machine.
package assets

import "embed"

//go:embed manifest.json podman postgres redis workspace
var FS embed.FS
