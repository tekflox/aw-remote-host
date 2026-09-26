#!/usr/bin/env bash
# Shared helper for pointing nested ROOTFUL podman's own storage — its
# container/image registry, NOT the $DATA_DIR bind mounts postgres/redis
# use for their actual data — at a path under $HOME instead of the package
# default (/var/lib/containers/storage). Sourced by bootstrap/podman/install.sh.
#
# THE INCIDENT THIS EXISTS TO PREVENT (confirmed live 2026-09-02,
# incident:byod-postgres-lost-bind-mount-2026-09-02): rootful podman reads
# /etc/containers/storage.conf, a location that lives in whatever
# filesystem this process's root is on. On a normal bare-metal/VM host
# that's the real, persistent disk — a non-issue. But aw-remote-host's own
# docker-compose simulator (tools/aw-remote-host/) runs bootstrap-workspace
# as root INSIDE a docker container (nested/rootful podman — see
# tools/aw-remote-host/entrypoint.sh), where "this process's root" is the
# OUTER container's own writable layer, not the aw-remote-host-state volume
# (which only covers $HOME). Every time that outer container gets
# recreated — a redeploy, or (what actually happened) a crash-loop restart
# after 41 failed cycles — podman "forgets" every container/image it ever
# created even though the actual data under $HOME/postgres-data etc.
# survives untouched on the volume. With nothing left for podman to detect,
# the next bootstrap has no choice but to run the full manifest from
# scratch, which is what turned a container recreate into a Postgres/Redis
# data-loss incident.
#
# A rootless install (the common BYOD case: bootstrap-workspace running as
# the host user) already keeps its storage under that user's own $HOME by
# podman's own default ($HOME/.local/share/containers) — nothing to do
# there. bootstrap/podman/install.sh gates the call to this file's function
# on id -u == 0 for exactly that reason; kept OUT of the function itself so
# it stays pure and testable without mocking `id`.
#
# Not meant to be executed directly — only sourced.


# configure_podman_graphroot <conf_file> <home_dir>
#
# Idempotently writes <conf_file> (podman's storage.conf) so its [storage]
# graphroot points at <home_dir>/.local/share/containers/storage instead of
# whatever podman's package default is. Safe to call on every bootstrap —
# a no-op once the conf already says what this function would write.
#
# runroot is written TOO, and deliberately NOT under $HOME. Podman refuses to
# start at all when a storage.conf exists but omits it —
# "Failed to obtain podman configuration: runroot must be set" — so writing a
# graphroot-only conf installs podman and bricks it in the same step, which is
# exactly what happened on the aw workspace host on 2026-09-05: every module
# after podman (postgres, redis, workspace) never ran. Unlike graphroot, this
# one holds per-boot runtime state (lock files, active mounts); on $HOME it
# would survive a container recreate as stale locks pointing at mounts that no
# longer exist, so /run — podman's own rootful default — is the correct place.
#
# The early-return also checks runroot, not just graphroot: a host already
# bootstrapped by the graphroot-only version has a conf whose graphroot is
# ALREADY correct, so a graphroot-only guard would return early and leave that
# host permanently broken instead of repairing it.
PODMAN_RUNROOT="${PODMAN_RUNROOT:-/run/containers/storage}"

# PODMAN_MOUNT_PROGRAM is what gets handed to podman as [storage.options]
# mount_program whenever _podman_mount_program_for below decides one is
# needed. fuse-overlayfs is podman's own documented answer to nested
# overlay-on-overlay — see that function's comment for the two incidents
# this line exists to close.
PODMAN_MOUNT_PROGRAM="${PODMAN_MOUNT_PROGRAM:-/usr/bin/fuse-overlayfs}"

# _podman_mount_program_for <home_dir>
#
# Decides whether configure_podman_graphroot needs to hand podman a
# mount_program for a graphroot rooted under <home_dir>. Podman's native
# "overlay" driver refuses to mount on top of a filesystem that is ITSELF
# already overlayfs — confirmed live via
# bug:aw-automation-byod-smoke-workspace-provisioning-timeout (GHA run
# 35860295745): "'overlay' is not supported over overlayfs, a mount_program
# is required". That's exactly aw-remote-host's own docker-compose simulator,
# and any bare-metal host that ends up recreating aw-remote-host inside
# ANOTHER container.
#
# This function's first version (861f4aa) detected the case and had
# configure_podman_graphroot fall back to the vfs driver entirely instead of
# overlay — that clears the hard error, but vfs has no copy-on-write and
# fully duplicates every layer per image AND per container. Confirmed live
# 2026-09-26 (incident:aw-automation-byod-vfs-bloat), one bootstrap after
# 861f4aa's own fix landed: 44G on disk for 4.4G of actual image content, on
# a bare-metal host down to 8.9G free because of it. fuse-overlayfs is
# podman's own documented answer to the exact error message above — real
# copy-on-write overlay semantics without needing the kernel to support
# overlay-on-overlay, so the driver can stay "overlay" everywhere and only
# the mount_program changes. Verified: built aw-remote-host's own production
# Dockerfile, ran it privileged, confirmed `podman info` reports
# graphDriverName: overlay with fuse-overlayfs wired in, and podman pull+run
# both succeed — same result reproduced independently inside aw-automation's
# own byod/Dockerfile container (docker:27-dind, the exact environment
# GHA run 35860295745 failed in).
#
# mount_program is only handed to podman when it's actually needed — setting
# it unconditionally would force every ordinary bare-metal/VM host (a real
# disk, no nesting) onto FUSE overlay too, trading away the faster native
# kernel driver for nothing.
#
# findmnt not resolving (missing, or <home_dir> not yet mounted anywhere
# distinguishable) means "assume a normal disk" — no mount_program, same as
# the pre-existing default before nesting was ever a concern here.
_podman_mount_program_for() {
  local home_dir="$1" fstype
  fstype="$(findmnt -no FSTYPE -T "$home_dir" 2>/dev/null || true)"
  case "$fstype" in
    overlay | overlayfs | fuse.fuse-overlayfs)
      echo "$PODMAN_MOUNT_PROGRAM"
      ;;
    *)
      echo ""
      ;;
  esac
}

configure_podman_graphroot() {
  local conf_file="$1" home_dir="$2"
  local storage_root="$home_dir/.local/share/containers/storage"
  local mount_program desired
  mkdir -p "$storage_root" "$(dirname "$conf_file")"
  mount_program="$(_podman_mount_program_for "$home_dir")"

  desired="[storage]
driver = \"overlay\"
runroot = \"$PODMAN_RUNROOT\"
graphroot = \"$storage_root\""
  if [ -n "$mount_program" ]; then
    desired="$desired

[storage.options]
mount_program = \"$mount_program\""
  fi

  # Full-content comparison rather than a chain of greps: it repairs ANY
  # drift from what this function would write right now — a stale driver, a
  # missing/wrong mount_program, leftover options from an older version —
  # instead of only the specific fields an earlier version happened to
  # check for. That's the exact gap that let 861f4aa's own conf (correct
  # graphroot+runroot, no mount_program) go unrepaired: a guard checking
  # only those two fields would have returned early and left that host
  # silently on vfs forever.
  if [ -f "$conf_file" ] && [ "$(cat "$conf_file")" = "$desired" ]; then
    return 0
  fi

  printf '%s\n' "$desired" > "$conf_file"
  echo "podman: graphroot set to $storage_root (survives this container being recreated; the package default /var/lib/containers/storage does not), runroot at $PODMAN_RUNROOT${mount_program:+, mount_program=$mount_program (native overlay-on-overlay would otherwise hard-fail — see incident:aw-automation-byod-vfs-bloat-2026-09-26)}"
}
