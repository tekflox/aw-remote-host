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
# a no-op once the graphroot already matches.
configure_podman_graphroot() {
  local conf_file="$1" home_dir="$2"
  local storage_root="$home_dir/.local/share/containers/storage"
  mkdir -p "$storage_root" "$(dirname "$conf_file")"
  if [ -f "$conf_file" ] && grep -q "graphroot = \"$storage_root\"" "$conf_file" 2>/dev/null; then
    return 0
  fi
  cat > "$conf_file" <<EOF
[storage]
driver = "overlay"
graphroot = "$storage_root"
EOF
  echo "podman: graphroot set to $storage_root (survives this container being recreated; the package default /var/lib/containers/storage does not)"
}
