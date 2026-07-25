#!/usr/bin/env bash
# Exit 0 if the postgres container is running and accepting queries.
set -euo pipefail

CONTAINER_NAME="aw-remote-host-postgres"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "postgres: container not found" >&2
  exit 1
fi

podman exec "$CONTAINER_NAME" pg_isready -U postgres >/dev/null
podman exec "$CONTAINER_NAME" psql -U postgres -tAc "SELECT 1;" >/dev/null
echo "postgres: healthy"
