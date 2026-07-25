#!/usr/bin/env bash
# Exit 0 if the redis container is running and responding to PING.
set -euo pipefail

CONTAINER_NAME="aw-remote-host-redis"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "redis: container not found" >&2
  exit 1
fi

reply=$(podman exec "$CONTAINER_NAME" redis-cli PING)
if [ "$reply" != "PONG" ]; then
  echo "redis: unexpected reply: $reply" >&2
  exit 1
fi
echo "redis: healthy"
