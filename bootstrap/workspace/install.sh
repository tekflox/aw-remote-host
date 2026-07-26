#!/usr/bin/env bash
# Install (or reuse) the aw-workspace runtime container. Idempotent.
# Requires AW_WORKSPACE_SLUG / AW_POSTGRES_PASSWORD / AW_BACKEND_URL in the
# environment — aw-remote-host sets these after the /link registration
# reply tells it which workspace slug this token is scoped to (the user
# never types a slug).
#
# Networking: in a BYOD host there is no shared aw-sandbox netns, so the
# workspace, postgres and redis are separate containers. They are joined on
# a user-defined podman network (``aw-remote-host``) and reach each other by
# container name via aardvark-dns — NOT via 127.0.0.1 (which, inside the
# workspace container, is its own loopback).
set -euo pipefail

: "${AW_WORKSPACE_SLUG:?AW_WORKSPACE_SLUG must be set (comes from the /link registered reply)}"
: "${AW_POSTGRES_PASSWORD:?AW_POSTGRES_PASSWORD must be set}"
: "${AW_BACKEND_URL:?AW_BACKEND_URL must be set}"

IMAGE="ghcr.io/fredericowu/aw-workspace:latest"
CONTAINER_NAME="aw-remote-host-workspace"
NETWORK_NAME="aw-remote-host"
PG_HOST="aw-remote-host-postgres"
REDIS_HOST="aw-remote-host-redis"
SCHEMA="workspace_${AW_WORKSPACE_SLUG}"
DB_URL="postgresql+psycopg://postgres:${AW_POSTGRES_PASSWORD}@${PG_HOST}:5432/aw_workspace"
REDIS_URL="redis://${REDIS_HOST}:6379/0"

# Ensure the shared network exists (postgres/redis create it too — idempotent).
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

if podman container exists "$CONTAINER_NAME"; then
  echo "workspace: container already exists, ensuring it's running"
  podman network connect "$NETWORK_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || true
  podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  podman run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --restart=always \
    -p 127.0.0.1:9030:9030 \
    -e AW_WORKSPACE="$AW_WORKSPACE_SLUG" \
    -e AW_WORKSPACE_SCHEMA="$SCHEMA" \
    -e AWSERV_DB_URL="$DB_URL" \
    -e AW_WORKSPACE_DB_URL="$DB_URL" \
    -e AW_REDIS_URL="$REDIS_URL" \
    -e AW_BACKEND_URL="$AW_BACKEND_URL" \
    "$IMAGE"
fi

echo "workspace: waiting for readiness..."
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:9030/api/health" >/dev/null 2>&1; then
    echo "workspace: ready"
    exit 0
  fi
  sleep 1
done

echo "workspace: did not become healthy in time" >&2
echo "workspace: last container logs (probable cause below):" >&2
podman logs --tail 20 "$CONTAINER_NAME" >&2 2>&1 || true
exit 1
