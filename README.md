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

Card 4 of 6 (BYOD onboarding chain): `bootstrap-workspace` is real —
idempotent detect→install→verify over every manifest module, a dial-back
to the control plane's `/link` over WebSocket that redeems the one-time
`awbs_` token for a durable `awlk_` credential, and a persistent reconnect
loop (exponential backoff). Cross-platform: Linux (systemd user unit) and
macOS (launchd LaunchAgent — the e2e test box, macbook-fred, is a Mac with
no systemd) via `internal/servicemgr`. `--plan` still previews everything
without touching your system. See [Roadmap](#roadmap).

## Installing

```sh
curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh
```

This pins an exact release version, downloads the matching
`linux_amd64`/`linux_arm64` binary from
[GitHub Releases](https://github.com/tekflox/aw-remote-host/releases),
verifies its SHA-256 checksum, and installs it to `~/.local/bin`.

macOS binaries aren't published by the release workflow yet — build from
source there for now (`go build ./cmd/aw-remote-host`, Go 1.23+).

## Usage

```sh
aw-remote-host bootstrap-workspace --token <token> [--plan] [--yes] [--foreground|--background] [--control-plane https://api.aw.tekflox.com]
aw-remote-host status [--plan]
aw-remote-host unlink [--plan] [--stop-containers]
aw-remote-host version
```

`--plan` prints the actions each command would take without executing
anything — use it to see exactly what would happen before running for
real. `--yes` skips the confirmation prompt `bootstrap-workspace` shows
before touching your system. Once linked, `--token` is no longer needed —
`bootstrap-workspace` reuses the stored `awlk_` credential.

### `--foreground` vs `--background`

`bootstrap-workspace` defaults to **`--foreground`** (`--fg`) when neither
flag is given — first-run transparency: it stays attached, prints
everything to stdout, and holds the `/link` connection itself. Nothing is
installed as a service.

Pass **`--background`** (`--detach`) to install and start the platform
service instead — **launchd** on macOS, **systemd** on Linux (see
`internal/servicemgr`) — then detach; the service re-invokes
`bootstrap-workspace --foreground` on your behalf so the connection
survives this terminal closing. `unlink` stops and uninstalls whichever
service is present.

### Credentials

Once linked, credentials are written to `~/.aw-remote-host/credentials.json`
with file mode `0600`. The generated Postgres password and last-known
workspace slug live alongside it in `~/.aw-remote-host/state.json` (also
`0600`) — the password is stable across re-runs so a restart never locks
itself out of the existing data volume.

### Running persistently

`bootstrap-workspace --background` writes and starts:

- **Linux:** `~/.config/systemd/user/aw-remote-host.service`. Pair with
  `loginctl enable-linger $USER` so it survives logout/reboot.
- **macOS:** `~/Library/LaunchAgents/com.tekflox.aw-remote-host.<slug>.plist`
  — a LaunchAgent, so it starts automatically at login with no extra
  linger step needed. Logs go to `~/Library/Logs/aw-remote-host.<slug>.log`.

### macOS container runtime

macOS has no native podman daemon — `podman` runs everything against a
Linux VM. `bootstrap/podman/install.sh`/`verify.sh` detect whichever of
**podman machine**, **colima**, or **Docker Desktop** is already running
and use it; if none is, they start a podman machine. If none is found and
none can be started, they fail with a clear message naming all three
options — see `bootstrap/podman/README.md`.

## Repository layout

```
cmd/aw-remote-host/     Go CLI entrypoint (bootstrap-workspace, status, unlink, version)
internal/link/          WS client that dials wss://<control-plane>/link, credential persistence, reconnect loop
internal/bootstrap/     Manifest loader + embedded-script extraction + detect/install/verify orchestration
internal/servicemgr/    Per-OS background service manager (systemd on Linux, launchd on macOS)
internal/state/         Local state (generated Postgres password, last-known workspace slug)
bootstrap/embed.go      go:embed of manifest.json + every module's scripts into the binary
bootstrap/manifest.json Pinned module list (name, version, image digest or package, verify command)
bootstrap/<module>/     One dir per module: README.md, install.sh, verify.sh
install.sh              Root installer: pinned binary download + checksum verify
```

## Roadmap (BYOD onboarding chain)

Card 4 of 6, built on cards 1–3 (repo scaffold + the control plane's
bootstrap-token/`/link` endpoints). Remaining work in later cards: the
console-side pairing UI polish and the end-to-end BYOD test (card 6).

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

Go 1.23+. One dependency, `github.com/gorilla/websocket` (pinned in
`go.sum`) — needed for the real `/link` WebSocket client; everything else
is stdlib, keeping the audit surface of this transparency-critical repo
small.
