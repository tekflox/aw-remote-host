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
- If colima or Docker Desktop is already running, both scripts detect it
  and treat it as OK — but if `podman info` still fails against it, the
  fix is the same: `podman machine init && podman machine start`.
- If nothing is found and Homebrew isn't available either, both scripts
  exit non-zero with a clear message naming all three options.
