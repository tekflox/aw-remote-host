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
#
# Resolved through bootstrap/lib/container.sh's resolve_data_dir(), NOT
# inline — verify.sh computes this exact same path the exact same way, and
# that file's header explains why they must never be allowed to drift.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/publish.sh
source "$SCRIPT_DIR/../lib/publish.sh"
# shellcheck source=../lib/network.sh
source "$SCRIPT_DIR/../lib/network.sh"
# shellcheck source=../lib/container.sh
source "$SCRIPT_DIR/../lib/container.sh"

DATA_DIR="$(resolve_data_dir AW_REDIS_HOST_DIR redis-data)"
LEGACY_VOLUME="aw-remote-host-redis-data"
CONTAINER_DATA_DIR="/data"
# The `redis` user baked into the redis image.
REDIS_UID="999"
REDIS_GID="999"

# Host-port publish is optional — see bootstrap/lib/publish.sh for why a taken
# port must not fail the install.
mapfile -t PUBLISH_ARGS < <(publish_args redis 6379 "${AW_REDIS_PUBLISH:-}")

# Shared network so the workspace container reaches redis by name.
ensure_network "$NETWORK_NAME"

if podman container exists "$CONTAINER_NAME"; then
  current_src="$(mount_source "$CONTAINER_NAME" "$CONTAINER_DATA_DIR")"
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
    ${PUBLISH_ARGS[@]+"${PUBLISH_ARGS[@]}"} \
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
