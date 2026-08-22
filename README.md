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

Card 4 of 6 (BYOD onboarding chain): `bootstrap-workspace` is real — a
dial-back to the control plane's `/link` over WebSocket that redeems the
one-time `awbs_` token for a durable `awlk_` credential, and a persistent
reconnect loop (exponential backoff). Lean by default (link only, see
[Lean link vs `--with-workspace`](#lean-link-vs---with-workspace) below);
`--with-workspace` runs the idempotent detect→install→verify cycle over
every manifest module too. Cross-platform: Linux (systemd user unit),
macOS (launchd LaunchAgent — the e2e test box, macbook-fred, is a Mac with
no systemd) and Windows (Task Scheduler, **lean link only** — see
[Windows](#windows-lean-link-only)) via `internal/servicemgr`. `--plan`
still previews everything without touching your system. See
[Roadmap](#roadmap).

## Installing

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.ps1 | iex
```

Both pin an exact release version, verify its SHA-256 checksum against the
release's published `checksums.txt`, and install without needing admin
rights. `install.sh` downloads the matching
`linux_amd64`/`linux_arm64`/`darwin_amd64`/`darwin_arm64` tarball from
[GitHub Releases](https://github.com/tekflox/aw-remote-host/releases) into
`~/.local/bin`; `install.ps1` downloads the `windows_amd64`/`windows_arm64`
zip into `%LOCALAPPDATA%\Programs\aw-remote-host` and adds it to your user
PATH.

### Upgrading an already-installed binary (e.g. macbook-fred)

`install.sh`'s embedded bootstrap scripts (`bootstrap.ExtractScripts`) are
baked into the Go binary at build time — editing the on-disk copy under
`~/.aw-remote-host/bootstrap-scripts/` does nothing (see the gotcha in the
`aw-workspace-base-dir-host-mount` KB doc). A fix to `bootstrap/workspace/install.sh`
(e.g. the Tier-2 podman-socket mount + `--security-opt label=disable`,
commit `753214a`) only takes effect on the target machine once the
**binary itself** is rebuilt/released and re-installed there:

1. A push to `main` that changes the remote-host runtime, bootstrap scripts,
   installer, or release workflow runs `release.yml`, bumps the latest
   `vX.Y.Z` patch tag, and publishes
   `dist/aw-remote-host_<version>_<os>_<arch>.tar.gz` + `checksums.txt` on the
   GitHub Release. `workflow_dispatch` can still be used with an explicit
   `tag` input when a release needs to be pinned manually.
2. On the target machine, re-run the installer to pull the new pinned
   version and replace the binary in place:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh
   ```
   (or set `AW_REMOTE_HOST_VERSION=<tag>` to pin explicitly instead of the
   script's built-in default).
3. Restart whichever service is running it so the new binary's embedded
   scripts take effect on the **next** `bootstrap-workspace` re-provision —
   the running process itself doesn't hot-swap:
   - **macOS (launchd):** `launchctl kickstart -k gui/$(id -u)/com.tekflox.aw-remote-host.<slug>`
     (or unload/reload the plist under `~/Library/LaunchAgents/`).
   - **Linux (systemd user):** `systemctl --user restart aw-remote-host.service`
4. Trigger (or wait for) a workspace re-provision to confirm the new
   `install.sh` logic actually ran — e.g. check that the podman socket is
   mounted with `--security-opt label=disable` on the recreated container.

## Usage

```sh
aw-remote-host bootstrap-workspace --token <token> [--with-workspace] [--plan] [--yes] [--foreground|--background] [--control-plane https://api.aw.tekflox.com]
aw-remote-host status [--plan]
aw-remote-host unlink [--plan] [--stop-containers]
aw-remote-host version
```

`--plan` prints the actions each command would take without executing
anything — use it to see exactly what would happen before running for
real. `--yes` skips the confirmation prompt `bootstrap-workspace` shows
before touching your system. Once linked, `--token` is no longer needed —
`bootstrap-workspace` reuses the stored `awlk_` credential.

### Lean link vs `--with-workspace`

`bootstrap-workspace` is **lean by default**: it registers this machine
with the control plane and holds the `/link` connection open, without
installing anything locally. A lean link already gives the control plane
`exec_start`/`exec_status`/`exec_wait`/`exec_kill`/`list_processes` on this
machine (see `internal/ops/ops_exec.go`) — enough for command execution,
CI-style deploy steps, etc. — with zero local footprint.

Pass **`--with-workspace`** (`--full`) to also install/start the full local
runtime: podman, postgres+pgvector, redis, and the `aw-workspace` container.
Do this immediately at link time, or defer it — both are equivalent:

- **Later, from this machine**: re-run `bootstrap-workspace --with-workspace`
  (no `--token` needed, it reuses the stored credential).
- **From the control plane** (e.g. a "provision this host" button in
  aw-console): no need to come back to this machine at all — a lean-linked
  host already answers the same `"bootstrap"` verb over `/link` that
  `src/api/placement/remote_host_driver.py` dispatches for a managed
  workspace, which runs the exact same install code
  (`internal/ops.Handler.Bootstrap`).

`aw-remote-host status` reports `provisioned: no` for a lean link (module
health checks are skipped — nothing was installed, so nothing to check) and
switches to the full per-module health report once either path above has
completed successfully.

### `--foreground` vs `--background`

`bootstrap-workspace` defaults to **`--foreground`** (`--fg`) when neither
flag is given — first-run transparency: it stays attached, prints
everything to stdout, and holds the `/link` connection itself. Nothing is
installed as a service.

Pass **`--background`** (`--detach`) to install and start the platform
service instead — **launchd** on macOS, **systemd** on Linux, **Task
Scheduler** on Windows (see `internal/servicemgr`) — then detach; the
service re-invokes
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
- **Windows:** a Scheduled Task named `aw-remote-host`, defined by
  `~/.aw-remote-host/aw-remote-host.xml` and registered with `schtasks
  /Create /XML`. Its trigger is **logon**, so it comes back when you sign
  in — not at boot. Inspect it with `schtasks /Query /TN aw-remote-host /V
  /FO LIST`.

### Windows (lean link only)

A Windows host is **always a lean link** — and that is a property of the
product, not a gap waiting to be filled: the workspace is a *Linux
container image*, so there is nothing `--with-workspace` could install
there. What a Windows machine gets is the `/link` connection itself:

| Works | Does not |
|---|---|
| `exec_start` / `exec_status` / `exec_wait` / `exec_kill` | `stop` / `restart` / `reinstall` / `bootstrap` / `update` |
| `list_processes` | `self-update` |
| every `fs_*` verb (stat/list/mkdir/delete/read/write) | the interactive PTY shell |
| `health` (reports `offline: true` — there is no workspace to report on) | |

The verbs in the right column are refused **by name** with an explanation,
rather than failing with a bare "podman: executable file not found" that
reads like a broken PATH (see `workspaceLifecycleVerbs` in
`internal/ops/ops.go`). The PTY shell needs ConPTY, which this build does
not implement — `exec_start` covers one-shot commands in the meantime.

Install:

```powershell
irm https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.ps1 | iex
```

Then, in a **new** terminal (the installer adds itself to your user PATH):

```powershell
aw-remote-host link --token awbs_... --background
```

Three Windows-specific things worth knowing:

- **Commands run under PowerShell**, not `sh` — `powershell.exe -NoProfile
  -NonInteractive -Command` (see `internal/ops/proc_windows.go`). A native
  program's exit code is propagated explicitly via `$LASTEXITCODE`; without
  that, PowerShell reports 0 for a command that plainly failed.
- **`--background` installs a Scheduled Task**, not a service, triggered at
  **logon**. A rebooted machine sitting at the lock screen is therefore not
  linked yet — someone has to sign in. That is the honest trade for an
  install that needs no admin rights.
- **Killing a job kills its whole tree** (`taskkill /T /F`), the Windows
  stand-in for the process-group SIGKILL used on POSIX.

If you want the *full* workspace runtime on a Windows machine, use **WSL2**
instead: inside a WSL2 Ubuntu everything is ordinary Linux, so `install.sh`
and `--with-workspace` work unmodified. Enable systemd (`[boot]
systemd=true` in `/etc/wsl.conf`) and `loginctl enable-linger $USER` first,
or the service will not survive your terminal closing.

### macOS container runtime

macOS has no native podman daemon — `podman` runs everything against a
Linux VM. `bootstrap/podman/install.sh`/`verify.sh` detect whichever of
**podman machine**, **colima**, or **Docker Desktop** is already running
and use it; if none is, they install podman (via Homebrew, or a vendored
download if Homebrew isn't available either — see below) and start a
podman machine. See `bootstrap/podman/README.md`.

### Dependency resolution (no package manager required)

Each bootstrap module is responsible for resolving its own prerequisites —
the control plane never assumes you have Homebrew, apt, or any other
package manager. `bootstrap/lib/deps.sh` is the shared helper library for
this (`ensure_cmd`, `fetch_and_extract_pkg`); see `bootstrap/lib/README.md`
for the extension contract. The first concrete case: a clean, brew-less
macOS machine gets a **vendored podman** (official `.pkg` release,
extracted with `pkgutil --expand-full`, no sudo/admin) instead of failing
outright — see `bootstrap/podman/README.md`'s "No Homebrew" section.
`internal/bootstrap/runner.go` propagates the vendored `podman` onto
`$PATH` for every module that runs after it, in the same process and
across separate `bootstrap.Run()` calls.

## Repository layout

```
cmd/aw-remote-host/     Go CLI entrypoint (bootstrap-workspace, status, unlink, version)
internal/link/          WS client that dials wss://<control-plane>/link, credential persistence, reconnect loop
internal/bootstrap/     Manifest loader + embedded-script extraction + detect/install/verify orchestration
internal/servicemgr/    Per-OS background service manager (systemd on Linux, launchd on macOS, schtasks on Windows)
internal/ops/proc_*.go  Per-OS process control: which shell runs a command, process-group setup, tree kill
internal/state/         Local state (generated Postgres password, last-known workspace slug)
bootstrap/embed.go      go:embed of manifest.json + lib/ + every module's scripts into the binary
bootstrap/manifest.json Pinned module list (name, version, image digest or package, verify command)
bootstrap/lib/          Shared dependency-resolution helpers (deps.sh) sourced by module install.sh scripts
bootstrap/<module>/     One dir per module: README.md, install.sh, verify.sh
install.sh              Root installer (Linux/macOS): pinned binary download + checksum verify
install.ps1             Root installer (Windows): same contract, PowerShell + zip
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
