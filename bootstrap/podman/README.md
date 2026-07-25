# podman

**What:** the container runtime every other bootstrap module (postgres,
redis, workspace) runs on top of. Installed from your distro's package
manager — no third-party binary, no curl-pipe-sh for this one.

**Why:** rootless by default, no long-running privileged daemon (unlike
Docker), which fits a BYOD machine you don't want a stranger's code running
as root on.

## Install

`install.sh` detects your package manager (`apt`, `dnf`, `pacman`) and
installs `podman` if it's not already on `$PATH`. Idempotent — re-running it
on a machine that already has podman is a no-op.

## Verify

`verify.sh` exits `0` if `podman info` succeeds, non-zero otherwise.
