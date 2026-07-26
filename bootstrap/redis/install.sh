#!/usr/bin/env bash
# Install (or reuse) a 127.0.0.1-only redis container. Idempotent.
set -euo pipefail

IMAGE="docker.io/library/redis@sha256:a8f08480e1f88f2647fed492d1178c06abb0d0c1fbf02c682a61e2f483fb3954"
CONTAINER_NAME="aw-remote-host-redis"
VOLUME_NAME="aw-remote-host-redis-data"
NETWORK_NAME="aw-remote-host"

# Shared network so the workspace container reaches redis by name.
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

if podman container exists "$CONTAINER_NAME"; then
  echo "redis: container already exists, ensuring it's running"
  podman network connect "$NETWORK_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || true
  podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  podman volume create "$VOLUME_NAME" >/dev/null
  podman run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    -p 127.0.0.1:6379:6379 \
    -v "$VOLUME_NAME":/data \
    "$IMAGE" redis-server --appendonly yes
fi

echo "redis: waiting for readiness..."
for _ in $(seq 1 30); do
  if podman exec "$CONTAINER_NAME" redis-cli PING >/dev/null 2>&1; then
    echo "redis: ready"
    exit 0
  fi
  sleep 1
done

echo "redis: did not become ready in time" >&2
exit 1
