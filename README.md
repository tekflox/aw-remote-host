# aw-remote-host

The **BYOD bootstrap client** for [Agentic Workspace](https://aw.tekflox.com)
— a small Go CLI you run on your own machine to link it to the AW control
plane and stand up the local runtime (podman, Postgres+pgvector, Redis, the
`aw-workspace` container) your workspace runs on.

## Why this repo is public

The control plane only ever **triggers** or **selects** which bootstrap
modules to run — it never pushes opaque code to your machine. Every byte
`aw-remote-host` executes on your machine, and everything each bootstrap
module installs, is in this repository, reviewable by anyone, before you
ever run it. That is the whole transparency contract:

- **What dials out:** the CLI opens exactly one outbound connection —
  `wss://<control-plane>/link` (see `internal/link/link.go`), authenticated
  with the `--token` you pass. **No inbound port is ever opened** on your
  machine — nothing here ever listens for connections from the internet.
- **What gets installed, and from where:** every component is pinned in
  [`bootstrap/manifest.json`](bootstrap/manifest.json) — container images
  by exact SHA-256 digest (not a mutable tag), OS packages by name via your
  distro's own package manager. Nothing is fetched from an undisclosed
  source.
- **What binds where:** every container a bootstrap module starts
  (Postgres, Redis) binds to `127.0.0.1` only. Nothing here is reachable
  from your network or the internet.
- **How to audit:** read `bootstrap/manifest.json` for the exact pinned
  versions/digests, then read `bootstrap/<module>/install.sh` and
  `verify.sh` for each module — they're short, idempotent shell scripts,
  not compiled binaries. The Go CLI itself is small enough to read in one
  sitting; start at `cmd/aw-remote-host/main.go`.
- **How to verify what you download:** `install.sh` (this repo's root)
  downloads a specific tagged release binary and checks its SHA-256 against
  the checksums file published alongside that same release — see
  [Installing](#installing) below.

## Status

This is the **skeleton** (first card of the BYOD onboarding chain, "1/6").
The CLI subcommands exist and support a `--plan` dry-run mode that prints
what would happen without touching your system, but the real
`bootstrap-workspace` implementation — actually installing and linking
things — lands in a later card. See [Roadmap](#roadmap).

## Installing

```sh
curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh
```

This pins an exact release version, downloads the matching
`linux_amd64`/`linux_arm64` binary from
[GitHub Releases](https://github.com/tekflox/aw-remote-host/releases),
verifies its SHA-256 checksum, and installs it to `~/.local/bin`.

## Usage

```sh
aw-remote-host bootstrap-workspace --token <token> [--plan] [--control-plane https://api.aw.tekflox.com]
aw-remote-host status [--token <token>]
aw-remote-host unlink [--token <token>]
aw-remote-host version
```

`--plan` prints the actions each command would take without executing
anything — use it to see exactly what would happen before running for
real.

### Credentials

Once linked, credentials are written to `~/.aw-remote-host/credentials.json`
with file mode `0600` (card 4).

## Repository layout

```
cmd/aw-remote-host/     Go CLI entrypoint (bootstrap-workspace, status, unlink, version)
internal/link/          WS client stub that dials wss://<control-plane>/link
internal/bootstrap/     Manifest loader + module install/verify orchestration
bootstrap/manifest.json Pinned module list (name, version, image digest or package, verify command)
bootstrap/<module>/     One dir per module: README.md, install.sh, verify.sh
install.sh              Root installer: pinned binary download + checksum verify
```

## Roadmap (BYOD onboarding chain)

This is card 1 of 6. Later cards build on this skeleton:

- Card 3 — the control plane's `/link` server this CLI dials.
- Card 4 — real `bootstrap-workspace` implementation: actual
  detect/install/verify execution, credential file writing.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

Go 1.23+. No external dependencies — the CLI skeleton is stdlib-only by
design, to keep the audit surface of this transparency-critical repo as
small as possible.
