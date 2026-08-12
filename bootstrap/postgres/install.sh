#!/usr/bin/env bash
# Install (or reuse) a 127.0.0.1-only postgres+pgvector container. Idempotent.
set -euo pipefail

IMAGE="docker.io/pgvector/pgvector@sha256:1d533553fefe4f12e5d80c7b80622ba0c382abb5758856f52983d8789179f0fb"
CONTAINER_NAME="aw-remote-host-postgres"
NETWORK_NAME="aw-remote-host"
POSTGRES_PASSWORD="${AW_POSTGRES_PASSWORD:-postgres}"

# The data dir lives under $HOME on the host, NOT in a podman named volume.
# Why: on a containerised BYOD host, podman's storage (/var/lib/containers)
# sits in the aw-remote-host container's own writable overlay layer, so the
# `docker rm -f` + `run` that every aw-remote-host UPDATE performs destroys
# it — taking the workspace's entire database with it. $HOME is the durable
# mount. Same ${HOME}/<name> + AW_*_HOST_DIR override convention as
# bootstrap/workspace/install.sh's HOST_DIR.
DEFAULT_DATA_DIR="${HOME}/postgres-data"
DATA_DIR="${AW_POSTGRES_HOST_DIR:-${DEFAULT_DATA_DIR}}"
LEGACY_VOLUME="aw-remote-host-postgres-data"
CONTAINER_DATA_DIR="/var/lib/postgresql/data"
# The `postgres` user baked into the pgvector image.
POSTGRES_UID="999"
POSTGRES_GID="999"

# Shared network so the workspace container reaches postgres by name (a BYOD
# host has no aw-sandbox netns to piggyback on 127.0.0.1).
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

# A container left over from before the volume->host-dir move must be REPLACED,
# not just started — otherwise a host bootstrapped earlier keeps its database
# on the ephemeral volume forever and never picks this fix up. Removing the
# container leaves that volume (and its data) untouched, so the copy below has
# something to migrate from and a rollback stays available.
if podman container exists "$CONTAINER_NAME"; then
  current_src="$(podman inspect "$CONTAINER_NAME" \
    --format "{{range .Mounts}}{{if eq .Destination \"$CONTAINER_DATA_DIR\"}}{{.Source}}{{end}}{{end}}" 2>/dev/null || true)"
  if [ "$current_src" = "$DATA_DIR" ]; then
    echo "postgres: container already exists on $DATA_DIR, ensuring it's running"
    podman network connect "$NETWORK_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || true
    podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  else
    echo "postgres: container is on legacy storage ($current_src) — recreating on $DATA_DIR"
    podman stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    podman rm -f "$CONTAINER_NAME" >/dev/null
  fi
fi

if ! podman container exists "$CONTAINER_NAME"; then
  mkdir -p "$DATA_DIR"

  # One-time migration off the legacy named volume. Only when the target is
  # still empty — a populated $DATA_DIR is the source of truth and must never
  # be overwritten by a stale volume that happens to still exist.
  if [ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ] && podman volume exists "$LEGACY_VOLUME" 2>/dev/null; then
    legacy_data="$(podman volume inspect "$LEGACY_VOLUME" --format '{{.Mountpoint}}' 2>/dev/null || true)"
    if [ -n "$legacy_data" ] && [ -n "$(ls -A "$legacy_data" 2>/dev/null)" ]; then
      echo "postgres: migrating data $legacy_data -> $DATA_DIR (legacy volume kept as rollback)"
      cp -a "$legacy_data/." "$DATA_DIR/"
    fi
  fi

  # Must be writable by the image's `postgres` user — root can chown directly,
  # a rootless host needs `podman unshare` to land inside its own user-namespace
  # mapping (same dual path as bootstrap/workspace/install.sh).
  if [ "$(id -u)" = "0" ]; then
    chown -R "${POSTGRES_UID}:${POSTGRES_GID}" "$DATA_DIR" 2>/dev/null || true
  else
    podman unshare chown -R "${POSTGRES_UID}:${POSTGRES_GID}" "$DATA_DIR" 2>/dev/null || true
  fi

  podman run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    -p 127.0.0.1:5432:5432 \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$DATA_DIR":"$CONTAINER_DATA_DIR" \
    "$IMAGE"
fi

echo "postgres: waiting for readiness..."
for _ in $(seq 1 30); do
  if podman exec "$CONTAINER_NAME" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Postgres only applies POSTGRES_PASSWORD on the data dir's FIRST init. If
# state.json (which holds AW_POSTGRES_PASSWORD) was lost while the data
# survived, a re-bootstrap generates a new password that won't match what's
# baked into the data dir, and auth fails silently downstream. Re-apply the
# current password unconditionally so the pair self-corrects regardless of
# whether this run created a fresh data dir or reused an existing one.
podman exec "$CONTAINER_NAME" psql -U postgres -c \
  "ALTER USER postgres WITH PASSWORD '${POSTGRES_PASSWORD}';" >/dev/null
echo "postgres: password re-applied (idempotent)"

# Create the workspace database (the aw-workspace runtime connects to
# .../aw_workspace) and enable pgvector inside it. Idempotent.
if ! podman exec "$CONTAINER_NAME" psql -U postgres -tAc \
      "SELECT 1 FROM pg_database WHERE datname='aw_workspace'" | grep -q 1; then
  podman exec "$CONTAINER_NAME" psql -U postgres -c "CREATE DATABASE aw_workspace;" >/dev/null
fi
podman exec "$CONTAINER_NAME" psql -U postgres -d aw_workspace -c "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null
echo "postgres: ready, aw_workspace db + pgvector enabled ($DATA_DIR)"
