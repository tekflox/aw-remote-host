#!/usr/bin/env bash
# Install (or reuse) the aw-workspace runtime container. Idempotent.
# Requires AW_WORKSPACE_SLUG / AW_POSTGRES_PASSWORD / AW_BACKEND_URL in the
# environment — aw-remote-host sets these after the /link registration
# reply tells it which workspace slug this token is scoped to (the user
# never types a slug).
set -euo pipefail

: "${AW_WORKSPACE_SLUG:?AW_WORKSPACE_SLUG must be set (comes from the /link registered reply)}"
: "${AW_POSTGRES_PASSWORD:?AW_POSTGRES_PASSWORD must be set}"
: "${AW_BACKEND_URL:?AW_BACKEND_URL must be set}"

IMAGE="ghcr.io/fredericowu/aw-workspace:latest"
CONTAINER_NAME="aw-remote-host-workspace"
SCHEMA="workspace_${AW_WORKSPACE_SLUG}"
DB_URL="postgresql+psycopg://postgres:${AW_POSTGRES_PASSWORD}@127.0.0.1:5432/aw_workspace"

if podman container exists "$CONTAINER_NAME"; then
  echo "workspace: container already exists, ensuring it's running"
  podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  podman run -d \
    --name "$CONTAINER_NAME" \
    --restart=always \
    -p 127.0.0.1:9030:9030 \
    -e AW_WORKSPACE="$AW_WORKSPACE_SLUG" \
    -e AW_WORKSPACE_SCHEMA="$SCHEMA" \
    -e AWSERV_DB_URL="$DB_URL" \
    -e AW_WORKSPACE_DB_URL="$DB_URL" \
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
exit 1
