// Package assets embeds this directory's manifest and module scripts into
// the compiled aw-remote-host binary. install.sh only ships the binary
// (see repo root README's transparency contract) — the module scripts have
// to travel with it rather than being read off a repo checkout that may
// not exist on the target machine.
package assets

import "embed"

// The module list is explicit, not a wildcard, so adding a module directory
// without adding it here compiles cleanly and then fails at runtime with
// "script not found" on the target machine. TestEveryManifestModuleIsEmbedded
// in internal/bootstrap guards that, because the failure otherwise only shows
// up on a host, not in CI.
//
//go:embed manifest.json lib podman postgres redis workspace vpn
var FS embed.FS
