#!/usr/bin/env bash
# Exit 0 if the aw-workspace container is running. Stub — no real health
# check wired yet (see card 4).
set -euo pipefail

CONTAINER_NAME="aw-remote-host-workspace"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "workspace: container not found" >&2
  exit 1
fi

echo "workspace: container present (health check not implemented yet, see card 4)"
