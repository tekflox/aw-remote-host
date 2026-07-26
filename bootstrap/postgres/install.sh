#!/usr/bin/env bash
# Install (or reuse) a 127.0.0.1-only postgres+pgvector container. Idempotent.
set -euo pipefail

IMAGE="docker.io/pgvector/pgvector@sha256:1d533553fefe4f12e5d80c7b80622ba0c382abb5758856f52983d8789179f0fb"
CONTAINER_NAME="aw-remote-host-postgres"
VOLUME_NAME="aw-remote-host-postgres-data"
NETWORK_NAME="aw-remote-host"
POSTGRES_PASSWORD="${AW_POSTGRES_PASSWORD:-postgres}"

# Shared network so the workspace container reaches postgres by name (a BYOD
# host has no aw-sandbox netns to piggyback on 127.0.0.1).
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

if podman container exists "$CONTAINER_NAME"; then
  echo "postgres: container already exists, ensuring it's running"
  podman network connect "$NETWORK_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || true
  podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  podman volume create "$VOLUME_NAME" >/dev/null
  podman run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
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

# Postgres only applies POSTGRES_PASSWORD on the volume's FIRST init. If
# state.json (which holds AW_POSTGRES_PASSWORD) was lost while the data
# volume survived, a re-bootstrap generates a new password that won't match
# what's baked into the volume, and auth fails silently downstream. Re-apply
# the current password unconditionally so the pair self-corrects regardless
# of whether this run created a fresh volume or reused an existing one.
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
echo "postgres: ready, aw_workspace db + pgvector enabled"
