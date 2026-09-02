#!/usr/bin/env bash
# Exit 0 if the redis container is running, responding to PING, AND mounted
# on the data dir install.sh expects.
#
# The mount check exists because of the 2026-09-02 incident: this script
# used to only run PING, never checking WHICH volume was actually mounted,
# so a container left on an emptied-out legacy volume read as "healthy"
# indefinitely and install.sh's own legacy-storage recreate branch never
# got a chance to run (RunModule skips install.sh entirely once verify.sh
# exits 0). See bootstrap/lib/container.sh for the full story and
# bootstrap/workspace/verify.sh for the same bug class solved once already
# for a different symptom.
set -euo pipefail

CONTAINER_NAME="aw-remote-host-redis"
CONTAINER_DATA_DIR="/data"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "redis: container not found" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/container.sh
source "$SCRIPT_DIR/../lib/container.sh"

expected_dir="$(resolve_data_dir AW_REDIS_HOST_DIR redis-data)"
actual_dir="$(mount_source "$CONTAINER_NAME" "$CONTAINER_DATA_DIR")"
if [ "$actual_dir" != "$expected_dir" ]; then
  echo "redis: mounted on '${actual_dir:-<unknown>}', expected '$expected_dir' — recreating on the expected data dir" >&2
  exit 1
fi

reply=$(podman exec "$CONTAINER_NAME" redis-cli PING)
if [ "$reply" != "PONG" ]; then
  echo "redis: unexpected reply: $reply" >&2
  exit 1
fi
echo "redis: healthy"
