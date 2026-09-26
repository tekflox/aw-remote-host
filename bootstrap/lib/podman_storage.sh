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

# _podman_graphroot_driver_for <home_dir>
#
# Picks the storage driver configure_podman_graphroot should write for a
# graphroot rooted under <home_dir>. Podman's native "overlay" driver cannot
# run on top of a filesystem that is ITSELF already overlayfs without a
# mount_program (fuse-overlayfs) — confirmed live via
# bug:aw-automation-byod-smoke-workspace-provisioning-timeout, GHA run
# 35860295745: "'overlay' is not supported over overlayfs, a mount_program
# is required". aw-automation's byod/Dockerfile hits exactly this — its
# `docker:27-dind` test container's own root filesystem is overlayfs before
# podman ever starts, which is why that Dockerfile pre-configures
# driver = "vfs" for itself. On a normal bare-metal/VM host, <home_dir> sits
# on a real disk (ext4 etc.) and native overlay is correct and faster — so
# this detects the exception instead of assuming it, or assuming the
# opposite (this function used to hardcode "overlay" unconditionally, which
# is the bug: it clobbered the byod/Dockerfile's own "vfs" the moment this
# repo's install.sh ran as root inside that container).
#
# findmnt not resolving (missing, or <home_dir> not yet mounted anywhere
# distinguishable) falls back to "overlay" — the pre-existing, safe-for-a-
# real-disk default.
_podman_graphroot_driver_for() {
  local home_dir="$1" fstype
  fstype="$(findmnt -no FSTYPE -T "$home_dir" 2>/dev/null || true)"
  case "$fstype" in
    overlay | overlayfs | fuse.fuse-overlayfs)
      echo "vfs"
      ;;
    *)
      echo "overlay"
      ;;
  esac
}

configure_podman_graphroot() {
  local conf_file="$1" home_dir="$2"
  local storage_root="$home_dir/.local/share/containers/storage"
  local driver
  mkdir -p "$storage_root" "$(dirname "$conf_file")"
  driver="$(_podman_graphroot_driver_for "$home_dir")"
  if [ -f "$conf_file" ] \
    && grep -q "driver = \"$driver\"" "$conf_file" 2>/dev/null \
    && grep -q "graphroot = \"$storage_root\"" "$conf_file" 2>/dev/null \
    && grep -q "runroot = \"$PODMAN_RUNROOT\"" "$conf_file" 2>/dev/null; then
    return 0
  fi
  cat > "$conf_file" <<EOF
[storage]
driver = "$driver"
runroot = "$PODMAN_RUNROOT"
graphroot = "$storage_root"
EOF
  echo "podman: graphroot set to $storage_root (survives this container being recreated; the package default /var/lib/containers/storage does not), runroot at $PODMAN_RUNROOT, driver $driver"
}
