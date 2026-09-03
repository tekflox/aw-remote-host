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

Step 2 is safe to re-run: `install.sh` compares the resolved tag against
`${INSTALL_DIR}/aw-remote-host version` and exits 0 with "already at
&lt;tag&gt;" instead of downloading again. It compares the binary **on disk**,
which is not necessarily the one **running** — see step 3, and the
`(deleted)` note below. `AW_REMOTE_HOST_FORCE=1` reinstalls anyway, for a
binary that is the right version and the wrong bytes.

### Why a CONTAINERISED host never reaches a release version on its own

Measured 2026-09-02 on the host that serves the `aw` workspace: its
`/usr/local/bin/aw-remote-host` was dated **Aug 6**, and reported `dev`,
although the checkout beside it was at v0.1.66 and the container had been
recreated that same day. Three separate mechanisms, and each one has to be
known before the version on such a host makes any sense:

1. **The image build never stamps a version.** `main.go`'s `var version =
   "dev"` is overwritten only by `-ldflags "-X main.version=${VERSION}"`,
   which lives in `.github/workflows/release.yml`. The Dockerfile that
   builds this binary for the workspace host (in the *legacy* repo,
   `tools/aw-remote-host/Dockerfile`) runs a plain `go build`, so **every**
   binary born from that image reports `dev` — including one built from a
   v0.1.66 checkout, five minutes ago.
2. **`dev` is refused on purpose.** `parseAgentVersion` (aw-workspace-ui
   `src/lib/networkingApi.js`) and `_parse_agent_version` (aw-backend
   `src/api/routes/host_link.py`) both return null for it, and both
   callers treat null as too old. A version nobody can compare proves
   nothing about what is inside the binary, and exit-gate selection on a
   pre-v0.1.58 agent would move the *machine's* default route. Do not
   loosen this to make a rebuild pass — rebuilding is not the fix.
3. **Nothing self-updates it.** The container's entrypoint re-execs
   `bootstrap-workspace` in a `while true` loop; it never re-installs.

So on a containerised host, `install.sh` with a pinned release tag is the
only path to a comparable version — and it is **ephemeral**: `/usr/local/bin`
lives in the image layer, so the next container recreation reverts the
binary to the `dev` build and the host is refused again. The durable fix is
`-ldflags` plus a pinned release in that Dockerfile, in the legacy repo.

Restarting the agent on such a host means killing the process and letting
the entrypoint's loop respawn it ~10-15s later. Two things bite:
`pkill` may not exist in the running image (scan `/proc/*/comm` and
`kill -TERM` instead), and the kill has to be **detached**
(`sh -c 'sleep 3; …' &`) because the process being killed is the parent of
the exec call doing the killing.

## Usage

```sh
aw-remote-host bootstrap-workspace --token <token> [--with-workspace] [--force] [--plan] [--yes] [--foreground|--background] [--control-plane https://api.aw.tekflox.com]
aw-remote-host status [--plan]
aw-remote-host vpn --login-server <headscale-url> [--authkey <key>] [--hostname <name>] [--advertise-exit-node] [--accept-dns] [--plan]
aw-remote-host vpn use-exit <node> [--expect-egress <ip>] [--exclude <cidrs>] [--deadman 2m] [--confirm-timeout 45s] [--persist-across-reboot] [--plan]
aw-remote-host vpn clear-exit [--plan]
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

### Downgrade guard on a full bootstrap

Either path above — `--with-workspace` here, or the control plane's
`"bootstrap"` verb — runs every module's `install.sh` from scratch, which
can silently reset postgres/redis onto empty storage if it happens to run
under an OLDER binary than the one that already bootstrapped this host (see
`internal/state.CheckDowngrade`; this is what caused a real incident on
2026-09-02, where an outer container recreation both wiped nested podman's
own container registry — see `bootstrap/lib/podman_storage.sh` — and rolled
the running binary back to a pre-fix build baked into a never-rebuilt image).

Once a host has completed a full bootstrap, a later one from an older
binary is refused with a loud error instead of silently reinitializing
everything. Pass `--force` if that downgrade is genuinely intentional; the
control-plane `"bootstrap"` verb takes the same opt-out via `args.force`.

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

### Mesh membership — `aw-remote-host vpn`

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

**Enrolling never changes this machine's default route.** Neither does
`--advertise-exit-node`: *advertising* provably does not change the
advertiser's own routing (confirmed on real hardware, 2026-08-25), and it
does nothing at all until a headscale admin approves the route, which
`status` says out loud. `--accept-routes` and `--accept-dns` are both forced
**off**, overriding tailscale's own defaults.

Moving the default route is a separate, explicit command — see
"[Using another node as the exit gate](#using-another-node-as-the-exit-gate)"
below.

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

### Using another node as the exit gate

```bash
aw-remote-host vpn use-exit aw-baremetal --plan          # gate + exclusions, changes nothing
aw-remote-host vpn use-exit aw-baremetal                 # THIS MOVES THE DEFAULT ROUTE
aw-remote-host vpn clear-exit                            # and back
```

This routes the machine's traffic — and, because every container NATs out
through it, every container's traffic with it — through `<node>`. It is the
one command in this repo that can take a host off the internet **and remove
the means of putting it back**, so the safety machinery is the feature:

- **On Linux, the control plane and every attached network stay outside the
  tunnel.** Installed as `ip rule … lookup main` at priority 5260, which beats
  tailscale's catch-all at 5270. Pointing at the *main* table is what makes a
  leftover exclusion inert rather than a black hole — the difference from
  the `ip rule from 172.18.0.5 lookup 51821` that left a container on this
  very infrastructure with no internet for two days, silently. If the control
  plane cannot even be resolved, the command **refuses** rather than moving
  the route without knowing where it is.
- **A dead-man's switch is armed before anything changes**, in its own
  session so it outlives whatever armed it, and is stood down only *after*
  egress has been confirmed. Kill the tool mid-flight and the route still
  comes back.
- **Egress is confirmed, not assumed.** The real public IP is fetched through
  the new route (fresh connections — a pooled one would answer from the old
  path) and must match `--expect-egress`, or have changed. Anything else is
  reverted and reported as a failure. "The interface is up" proves nothing.
- **A boot guard clears the selection at reboot**, because the selection
  survives a reboot and nothing re-confirms it on the way back up — a
  systemd oneshot on Linux, a user LaunchAgent on macOS.
- **A Mac can be a client of a gate, and installs no routes at all.** There
  tailscaled owns the utun, the LAN stays out natively via
  `--exit-node-allow-lan-access`, and the only available pin — a static host
  route naming a gateway — would turn into a black hole the moment the laptop
  changed networks. So the control plane is *confirmed through the gate*
  rather than pinned around it, and the reply says so in `manageability`
  instead of letting a screen assume the Linux guarantee. It needs
  `sudo tailscale set --operator=<user>` once, from an administrator account;
  without it the command refuses, naming that command, before anything moves.

`status` then reports which gate is in force, what the **real** egress IP is,
what is pinned outside the tunnel, and every leftover state in between.
Full detail, limits and the end-to-end measurements are in
[`bootstrap/vpn/README.md`](bootstrap/vpn/README.md).

### Windows (lean link only)

A Windows host is **always a lean link** — and that is a property of the
product, not a gap waiting to be filled: the workspace is a *Linux
container image*, so there is nothing `--with-workspace` could install
there. What a Windows machine gets is the `/link` connection itself:

| Works | Does not |
|---|---|
| `exec_start` / `exec_status` / `exec_wait` / `exec_kill` | `stop` / `restart` / `reinstall` / `bootstrap` / `update` |
| `list_processes` | a PTY on the `workspace` target — there is no container here |
| every `fs_*` verb (stat/list/mkdir/delete/read/write) | |
| the interactive PTY shell, via ConPTY | |
| `health` (reports `offline: true` — there is no workspace to report on) | |
| `self-update` — updates the **binary**, not the workspace | |

`self-update` **works on a lean host**, Windows included. It used to be
refused, because it sat in `workspaceLifecycleVerbs` alongside the
podman-backed verbs and so inherited their "needs the local workspace
runtime" gate. That was a miscategorisation: it replaces the
`aw-remote-host` binary and has nothing to do with the workspace container.
A lean host — every Windows host, and a podman-less Linux one — was told to
install a Linux container runtime in order to update an executable.

On Windows the verb drives `install.ps1` through `powershell.exe` (there is
no `sh` or `curl` on a stock host), then bounces the Scheduled Task. The
rollback monitor has a PowerShell twin of the POSIX script, with the binary
restore slotted between a stop and a start because Windows locks a running
image.

The installer handles the running binary being locked — Windows forbids
overwriting a running image but permits renaming one, so it moves the old
exe aside under a **timestamped** name rather than failing with a sharing
violation. The timestamp matters: a fixed `.old` collides with a still-
running predecessor from a previous update, and the rename then fails
partway through and leaves the directory with no usable binary at all.
Displaced copies are swept on later runs; anything still locked is left
alone.

Updating by hand is still available, and is the fallback if the link itself
is down:

```powershell
irm https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.ps1 | iex
taskkill /F /IM aw-remote-host.exe
taskkill /F /IM aw-remote-hostw.exe
schtasks /Run /TN aw-remote-host
```

`taskkill` and not `schtasks /End`: Task Scheduler ends a task by killing
its whole process tree, which from inside a session spawned by that task
would kill the shell issuing the command.

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
internal/vpn/           Mesh (tailscale/headscale): eligibility probe, status/prefs
                        readers, exit-gate selection, route exclusions, dead-man's switch
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
