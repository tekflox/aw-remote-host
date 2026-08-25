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
  source. Exactly one module — the opt-in `vpn` one — installs from an
  upstream vendor's own installer instead, because tailscale ships in no
  distro's repositories; that installer is named in the manifest's `source`
  field, `--plan` prints it, and all it does is add tailscale's signed apt/dnf
  repository before handing back to your package manager.
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
aw-remote-host vpn --login-server <headscale-url> [--authkey <key>] [--hostname <name>] [--advertise-exit-node] [--accept-dns] [--plan]
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
  in — not at boot. It also restarts itself every minute on failure. The
  task runs **`aw-remote-hostw.exe`**, a second GUI-subsystem build shipped
  in the same zip, so no console window sits on your desktop; because a GUI
  binary has no stdout, that build appends everything it would have printed
  to `~/.aw-remote-host/aw-remote-host.log`. Inspect the task with
  `schtasks /Query /TN aw-remote-host /V /FO LIST`.

  The task runs **unprivileged by default** (`RunLevel=LeastPrivilege`).
  Everything the lean link exists to do — `exec_*`, file transfer, the
  ConPTY shell — works fine that way, and an install that silently demands
  admin is a worse default than one that cannot restart a service.

  What that costs you is a specific class of task that is not an
  optional extra but simply impossible, and which reads like the tool being
  broken rather than a permission problem: **restarting a Windows service,
  writing anywhere under `C:\Program Files`, editing another service's
  config file.** The symptom is an `Access denied` buried in a command's
  output — `Restart-Service` comes back `CouldNotStopService`, an ini write
  reports success at the shell and changes nothing.

  Pass **`--elevated`** to register the task with
  `RunLevel=HighestAvailable` instead, from a PowerShell started with
  *Run as administrator*:

  ```powershell
  aw-remote-host bootstrap-workspace --elevated --background
  ```

  `HighestAvailable` means "the highest rights this account **has**" — it
  never promotes a standard user, it only stops UAC handing an
  administrator a filtered token. Registering such a task itself requires
  elevation, so `--elevated` refuses up front outside an elevated prompt
  rather than failing halfway through `schtasks /Create`.

### Firewall management (needs a privileged install)

This host can manage its own firewall (`internal/firewall`) — the control
plane pushes a persisted rule set over `/link` as a `firewall_apply` frame,
and this process turns it into real `nft`/`iptables` state, full-state and
idempotent every time. **The daemon itself runs without root or admin
rights by design** (see `internal/lanfastpath`'s `DefaultPort` comment —
the whole reason the LAN fast-path uses 8443 instead of 443 is that a
typical linked account has no passwordless sudo), so on a default install
`iptables -N`/`nft add table` fail with `EPERM` and firewall management
reports itself unavailable — honestly, not silently:

```json
{"backend": "iptables", "privileged": false,
 "privileged_reason": "aw-remote-host is not running as root and no NOPASSWD sudoers entry exists for iptables/nft — see this repo's README for the privileged-install prerequisite."}
```

That `privileged_reason` is exactly what the console shows next to this
host to explain why it can't apply firewall rules — nothing here tries to
escalate privilege on its own, and nothing pretends a rule took effect when
it didn't (a UI listing rules that were never actually applied is worse
than the feature being absent).

**To make firewall management work on a given host**, this process needs to
be able to run `nft`/`iptables` as root — either of:

- Run the linked service as root (a system-level unit instead of the
  default per-user one), or
- Add a **NOPASSWD** `sudoers.d` entry scoped to exactly `nft`/`iptables`
  for the account this process runs as, and have it invoke them via `sudo`.

There is no first-class flag for this yet (v1 tracks the *probe*, not the
*grant* — compare `--host-power`, which is the analogous opt-in for
`/dev/kvm`); until then, granting it is a manual step on the host itself.
`Probe()` re-checks on every `firewall_apply`/`firewall_status` call (never
cached), so a host that gains a NOPASSWD entry later starts reporting
`privileged: true` on its very next call with no restart needed.

v1 is **Linux-only** on purpose — macOS and Windows always report
`backend: "unsupported"` (still gracefully, never an error) rather than
guessing at a `pf`/`netsh` implementation.

### Mesh membership — `aw-remote-host vpn` (phase 1)

This host can join **the tenant's own mesh**, so the machines behind one
account can reach each other, and so one of them can later serve as the
others' exit gate. The client is stock tailscale; the control plane is a
**headscale instance per tenant** — never a shared one, because two
headscales do not federate, which makes tenant isolation a property of the
topology rather than of getting an ACL right.

```bash
aw-remote-host vpn --plan            # eligibility verdict only, changes nothing
aw-remote-host vpn \
  --login-server https://headscale.<tenant>.example \
  --authkey hskey-auth-... [--advertise-exit-node]
```

The `vpn` module is **opt-in**: it is in `bootstrap/manifest.json` with
`"optional": true`, so a plain `bootstrap-workspace --with-workspace` never
runs it. Joining a network is a decision the machine's owner makes, not a
side effect of provisioning a workspace.

**What phase 1 deliberately does not do:** select an exit node, or change
this machine's default route in any other way. The `/link` tunnel is the
only remote-management path a linked host has, so a default route pointed at
a mesh that is down takes the means of fixing it down with the machine — the
same shape as the outage recorded in `commands.go`'s
`bootstrapWorkspaceSelfHeal` comment. `--advertise-exit-node` is inside the
line because *advertising* provably does not change the advertiser's own
routing (confirmed on real hardware, 2026-08-25); it also does nothing at all
until a headscale admin approves the route, which `status` says out loud.
`--accept-routes` and `--accept-dns` are both forced **off**, overriding
tailscale's own defaults, for the same reason.

Eligibility is probed and **refused with a reason**, in the same spirit as
`--host-power` and the firewall probe above — a host that cannot really do
this has to say why, not fail quietly:

```
vpn: host is darwin/arm64, uid 503 (no root, no passwordless sudo)
vpn: NOT eligible — `sudo -n true` fails for this user, so `sudo tailscaled
     install-system-daemon` cannot run. macOS needs that system daemon: without
     it tailscaled has no privileged helper, and `tailscale set`/`tailscale up`
     fail with "Access denied: checkprefs access denied".
```

That refusal is not hypothetical. Without root, tailscaled can still start
with `--tun=userspace-networking`, which yields a SOCKS5/HTTP proxy and
**not** a network interface — so a host "installed" that way reports success
and carries none of its own traffic. See `bootstrap/vpn/README.md` for the
full eligibility table and `internal/vpn` for the probe.

`status` reports the node, its mesh IP, and for each peer whether the path is
**direct or relayed**:

```
vpn: node aw-vpn-phase1-test (100.64.0.4) online on tailnet headscale.aw.tekflox.com
vpn:   peer aw-baremetal    100.64.0.1   idle, no direct path established — would relay via DERP(hel)  [offers exit node]
vpn:   peer aw-mac          100.64.0.3   idle, no direct path established — would relay via DERP(mad)
```

The direct/relay distinction earns its place: two nodes on the *same home
network*, behind the same public IP, were measured relaying through Madrid
because one of them is WSL2 and sits behind a second layer of NAT. A relay is
a normal outcome, not a rare fallback, and without this line "it works, but
every packet goes to Madrid and back" is invisible.

### Windows (lean link only)

A Windows host is **always a lean link** — and that is a property of the
product, not a gap waiting to be filled: the workspace is a *Linux
container image*, so there is nothing `--with-workspace` could install
there. What a Windows machine gets is the `/link` connection itself:

| Works | Does not |
|---|---|
| `exec_start` / `exec_status` / `exec_wait` / `exec_kill` | `stop` / `restart` / `reinstall` / `bootstrap` / `update` |
| `list_processes` | `self-update` (its rollback monitor is a `sh -c` script) |
| every `fs_*` verb (stat/list/mkdir/delete/read/write) | a PTY on the `workspace` target — there is no container here |
| the interactive PTY shell, via ConPTY | |
| `health` (reports `offline: true` — there is no workspace to report on) | |

Because `self-update` is refused, **updating a Windows host is manual**:

```powershell
irm https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.ps1 | iex
schtasks /End /TN aw-remote-host
aw-remote-host bootstrap-workspace --background
```

The installer handles the running binary being locked — Windows forbids
overwriting a running image but permits renaming one, so it moves the old
exe aside under a **timestamped** name rather than failing with a sharing
violation. The timestamp matters: a fixed `.old` collides with a still-
running predecessor from a previous update, and the rename then fails
partway through and leaves the directory with no usable binary at all.
Displaced copies are swept on later runs; anything still locked is left
alone. The task still has to be restarted to pick the new
binary up, hence the last two lines.

The verbs in the right column are refused **by name** with an explanation,
rather than failing with a bare "podman: executable file not found" that
reads like a broken PATH (see `workspaceLifecycleVerbs` in
`internal/ops/ops.go`).

The interactive shell is a real **ConPTY** pseudoconsole
(`internal/shell/conpty_windows.go`), not an emulation: arrow keys, colour
and full-screen programs work. It is hand-built on `CreatePseudoConsole` +
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` because `creack/pty` — which the POSIX
side uses — ships Windows files that are stubs returning `ErrUnsupported`,
and because `os/exec` cannot pass a process-thread attribute list. Needs
Windows 10 1809 or newer. `pwsh` when installed, else `powershell.exe`.

Install:

```powershell
irm https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.ps1 | iex
```

Then, in a **new** terminal (the installer adds itself to your user PATH):

```powershell
aw-remote-host link --token awbs_... --background
```

Three Windows-specific things worth knowing:

- **Commands run under PowerShell**, not `sh` — `-NoProfile -NonInteractive
  -Command` (see `internal/ops/proc_windows.go`). A native program's exit
  code is propagated explicitly via `$LASTEXITCODE`; without that,
  PowerShell reports 0 for a command that plainly failed. **`pwsh` (7+) is
  used when installed**, falling back to `powershell.exe`: on a real Win10
  host, 5.1 cost 13.6s of startup on *every* command. Installing PowerShell
  7 is the single biggest thing you can do for remote-exec latency here.
- **`wsl.exe` writes UTF-16LE**, so its output arrives through `exec_start`
  with a null byte between every character. That is wsl being wsl, not a
  transport bug — pipe it through `| Out-String` and it still comes back
  UTF-16. Prefix such commands with `chcp 65001 | Out-Null;` or read them
  as UTF-16 on your side.
- **`--background` installs a Scheduled Task**, not a service, triggered at
  **logon**. A rebooted machine sitting at the lock screen is therefore not
  linked yet — someone has to sign in. That is the honest trade for an
  install that needs no admin rights.
- **Killing a job kills its whole tree** (`taskkill /T /F`), the Windows
  stand-in for the process-group SIGKILL used on POSIX.

#### Running the workspace on a Windows machine

`--with-workspace` on Windows does not try to provision this machine — it
stands up a **WSL2 distro** and provisions the workspace in there, because
the workspace is a Linux container image:

```powershell
aw-remote-host bootstrap-workspace --token awbs_... --with-workspace
```

That single command updates the WSL kernel, imports an Ubuntu rootfs as a
distro named `aw-ubuntu`, enables systemd in it, installs the Linux
aw-remote-host inside, provisions podman/postgres/redis/the workspace, then
installs a systemd service in the distro and a Startup-folder keep-alive out
on Windows so all of it returns at logon. `--plan` prints the steps without
doing any of it. It is idempotent: an existing distro is reused, and the
rootfs is cached.

The result is TWO linked hosts for one workspace on one physical machine —
the Windows box (lean: exec, fs, shell) and the distro (which runs the
workspace). The control plane models that fine; `RemoteHost.workspace_slug`
is a plain foreign key.

Note the keep-alive: WSL shuts an idle distro down, so the Startup script
holds a blocking command open rather than just booting the distro and
exiting. Without it systemd and every container go down seconds after
logon, while `wsl -l -v` reports Stopped and any diagnostic command you run
quietly starts it again.

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
cmd/aw-remote-host/     Go CLI entrypoint (bootstrap-workspace, status, vpn, unlink, version)
internal/link/          WS client that dials wss://<control-plane>/link, credential persistence, reconnect loop
internal/bootstrap/     Manifest loader + embedded-script extraction + detect/install/verify orchestration
internal/servicemgr/    Per-OS background service manager (systemd on Linux, launchd on macOS, schtasks on Windows)
internal/ops/proc_*.go  Per-OS process control: which shell runs a command, process-group setup, tree kill
internal/firewall/      firewall_apply/firewall_status verbs: nft/iptables backends, privilege probe, self-heal cache
internal/vpn/           Mesh (tailscale/headscale): eligibility probe, status/prefs readers
internal/state/         Local state (generated Postgres password, last-known workspace slug, mesh enrolment)
bootstrap/embed.go      go:embed of manifest.json + lib/ + every module's scripts into the binary
bootstrap/manifest.json Pinned module list (name, version, image digest or package, source, optional, verify command)
bootstrap/lib/          Shared helpers sourced by module scripts (deps.sh, network.sh, publish.sh, vpn.sh)
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
