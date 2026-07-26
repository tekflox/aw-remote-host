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
- **If Homebrew isn't available either** (a clean BYOD Mac — no brew, no
  colima, no Docker Desktop), `install.sh` vendors podman itself instead of
  giving up — see "No Homebrew" below.
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
