# podman

**What:** the container runtime every other bootstrap module (postgres,
redis, workspace) runs on top of.

**Why:** rootless by default, no long-running privileged daemon (unlike
Docker), which fits a BYOD machine you don't want a stranger's code running
as root on.

## Linux

Installed from your distro's package manager (`apt`, `dnf`, `pacman`) — no
third-party binary, no curl-pipe-sh for this one. `install.sh` skips the
install if `podman` is already on `$PATH`; `verify.sh` exits `0` if
`podman info` succeeds.

## macOS

macOS has no native podman daemon — `podman` itself runs everything against
a Linux VM (a "podman machine"). Both scripts detect which container
backend, if any, is already running — **podman machine**, **colima**, or
**Docker Desktop** — and report which one, but every module in this repo
still drives containers via the `podman` CLI, so `podman` itself has to end
up working regardless of which backend you use:

- If none is running, `install.sh` installs `podman` via Homebrew (if
  available) and starts a podman machine (`podman machine init && podman
  machine start`).
- **If Homebrew isn't available, or `brew install podman` fails** (e.g. a
  dedicated service account that doesn't own the Homebrew prefix — a clean
  BYOD Mac with no brew, no colima, no Docker Desktop is the other case),
  `install.sh` falls back to vendoring podman itself instead of giving up —
  see "No Homebrew" below.
- If colima or Docker Desktop is already running, both scripts detect it
  and treat it as OK — but if `podman info` still fails against it, the
  fix is the same: `podman machine init && podman machine start`.

### No Homebrew — vendored install

Validated end-to-end on a real brew-less Mac (2026-07-26). `install.sh`
downloads the official podman macOS installer, pinned at **v6.0.2**, from
`github.com/containers/podman/releases`, and extracts it with `pkgutil
--expand-full` (no sudo, no admin rights) into `~/podman-dist/podman/`
using `bootstrap/lib/deps.sh`'s `fetch_and_extract_pkg` helper — see that
file's README for the general dependency-resolution pattern this is the
first case of.

It also writes `~/podman-dist/env.sh` (exports `PATH`,
`CONTAINERS_HELPER_BINARY_DIR`, `CONTAINERS_MACHINE_PROVIDER=applehv`) for
a human to `source` in their own shell later, and pins
`~/.config/containers/containers.conf`'s `[machine]` provider to
**`applehv`** — the default **libkrun**/krunkit provider is known to abort
(SIGABRT) on some Mac models; Apple Virtualization + vfkit (`applehv`) is
the one that actually works there. `install.sh` only writes that file if no
provider is configured yet, so it never clobbers an existing config.

**PATH propagation to later modules:** postgres/redis/workspace's
`install.sh`/`verify.sh` all call `podman` directly and run as separate
`bash` invocations from `internal/bootstrap/runner.go`, so a vendored
install (never on the system `$PATH`) would otherwise be invisible to
them. The runner's `runScript()` checks for `~/podman-dist/podman/bin` on
every script it runs (any module, not just podman) and prepends it onto
that script's `$PATH` when present — see `podmanVendoredBinDir()` in
`internal/bootstrap/runner.go`. This is a no-op whenever podman is already
on `$PATH` normally (brew install, or already vendored in a prior run), so
the happy path is unaffected.

### Podman machine sizing

A fresh `podman machine init` (the "no running container backend found"
branch above) is sized from this host's physical RAM/CPU
(`bootstrap/lib/podman_machine.sh`'s `podman_machine_recommended_size`)
instead of podman's own 2GiB/2cpu default, which OOM-kills a real
workspace (postgres + redis + the workspace + several Tier-2 app
containers) under real load.

An **already-running** machine that is undersized is not auto-resized —
`podman machine set` needs stop+start, which would kill every running
container including the workspace itself, so that's an outage, not a
setting. `verify.sh` diagnoses it instead: it writes
`~/.aw-remote-host/degradations/podman-machine-undersized` (removed again
once the machine is resized) with the exact `podman machine stop && podman
machine set --memory N --cpus M && podman machine start` to run, surfaced
by `aw-remote-host status` and the ops `Health` payload. See
`bootstrap/lib/README.md`'s "degradations/ marker-dir convention" section.
