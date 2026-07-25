#!/usr/bin/env bash
# Exit 0 if the aw-workspace container is running and its health endpoint
# responds.
set -euo pipefail

CONTAINER_NAME="aw-remote-host-workspace"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "workspace: container not found" >&2
  exit 1
fi

curl -fsS "http://127.0.0.1:9030/api/health" >/dev/null
echo "workspace: healthy"
