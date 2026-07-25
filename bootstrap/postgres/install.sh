#!/usr/bin/env bash
# Install (or reuse) a 127.0.0.1-only postgres+pgvector container. Idempotent.
set -euo pipefail

IMAGE="docker.io/pgvector/pgvector@sha256:1d533553fefe4f12e5d80c7b80622ba0c382abb5758856f52983d8789179f0fb"
CONTAINER_NAME="aw-remote-host-postgres"
VOLUME_NAME="aw-remote-host-postgres-data"
POSTGRES_PASSWORD="${AW_POSTGRES_PASSWORD:-postgres}"

if podman container exists "$CONTAINER_NAME"; then
  echo "postgres: container already exists, ensuring it's running"
  podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  podman volume create "$VOLUME_NAME" >/dev/null
  podman run -d \
    --name "$CONTAINER_NAME" \
    -p 127.0.0.1:5432:5432 \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$VOLUME_NAME":/var/lib/postgresql/data \
    "$IMAGE"
fi

echo "postgres: waiting for readiness..."
for _ in $(seq 1 30); do
  if podman exec "$CONTAINER_NAME" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

podman exec "$CONTAINER_NAME" psql -U postgres -c "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null
echo "postgres: ready, pgvector enabled"
