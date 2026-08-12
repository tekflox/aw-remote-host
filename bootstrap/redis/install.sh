#!/usr/bin/env bash
# Install (or reuse) a 127.0.0.1-only redis container. Idempotent.
set -euo pipefail

IMAGE="docker.io/library/redis@sha256:a8f08480e1f88f2647fed492d1178c06abb0d0c1fbf02c682a61e2f483fb3954"
CONTAINER_NAME="aw-remote-host-redis"
NETWORK_NAME="aw-remote-host"

# Host dir instead of a podman named volume — `--appendonly yes` below means
# this data is meant to survive, and a named volume does not: see the long
# comment in bootstrap/postgres/install.sh for why podman storage is ephemeral
# on a containerised BYOD host.
DEFAULT_DATA_DIR="${HOME}/redis-data"
DATA_DIR="${AW_REDIS_HOST_DIR:-${DEFAULT_DATA_DIR}}"
LEGACY_VOLUME="aw-remote-host-redis-data"
CONTAINER_DATA_DIR="/data"
# The `redis` user baked into the redis image.
REDIS_UID="999"
REDIS_GID="999"

# Shared network so the workspace container reaches redis by name.
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

if podman container exists "$CONTAINER_NAME"; then
  current_src="$(podman inspect "$CONTAINER_NAME" \
    --format "{{range .Mounts}}{{if eq .Destination \"$CONTAINER_DATA_DIR\"}}{{.Source}}{{end}}{{end}}" 2>/dev/null || true)"
  if [ "$current_src" = "$DATA_DIR" ]; then
    echo "redis: container already exists on $DATA_DIR, ensuring it's running"
    podman network connect "$NETWORK_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || true
    podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  else
    echo "redis: container is on legacy storage ($current_src) — recreating on $DATA_DIR"
    podman stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    podman rm -f "$CONTAINER_NAME" >/dev/null
  fi
fi

if ! podman container exists "$CONTAINER_NAME"; then
  mkdir -p "$DATA_DIR"

  # One-time migration off the legacy named volume — see the matching block in
  # bootstrap/postgres/install.sh.
  if [ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ] && podman volume exists "$LEGACY_VOLUME" 2>/dev/null; then
    legacy_data="$(podman volume inspect "$LEGACY_VOLUME" --format '{{.Mountpoint}}' 2>/dev/null || true)"
    if [ -n "$legacy_data" ] && [ -n "$(ls -A "$legacy_data" 2>/dev/null)" ]; then
      echo "redis: migrating data $legacy_data -> $DATA_DIR (legacy volume kept as rollback)"
      cp -a "$legacy_data/." "$DATA_DIR/"
    fi
  fi

  if [ "$(id -u)" = "0" ]; then
    chown -R "${REDIS_UID}:${REDIS_GID}" "$DATA_DIR" 2>/dev/null || true
  else
    podman unshare chown -R "${REDIS_UID}:${REDIS_GID}" "$DATA_DIR" 2>/dev/null || true
  fi

  podman run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    -p 127.0.0.1:6379:6379 \
    -v "$DATA_DIR":"$CONTAINER_DATA_DIR" \
    "$IMAGE" redis-server --appendonly yes
fi

echo "redis: waiting for readiness..."
for _ in $(seq 1 30); do
  if podman exec "$CONTAINER_NAME" redis-cli PING >/dev/null 2>&1; then
    echo "redis: ready ($DATA_DIR)"
    exit 0
  fi
  sleep 1
done

echo "redis: did not become ready in time" >&2
exit 1
