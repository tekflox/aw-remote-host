#!/usr/bin/env bash
# Exit 0 if the postgres container is running, accepting queries, AND
# mounted on the data dir install.sh expects.
#
# The mount check exists because of the 2026-09-02 incident: this script
# used to only run pg_isready + SELECT 1, never checking WHICH volume was
# actually mounted, so a container left on an emptied-out legacy volume
# read as "healthy" indefinitely and install.sh's own legacy-storage
# recreate branch never got a chance to run (RunModule skips install.sh
# entirely once verify.sh exits 0). See bootstrap/lib/container.sh for the
# full story and bootstrap/workspace/verify.sh for the same bug class
# solved once already for a different symptom.
set -euo pipefail

CONTAINER_NAME="aw-remote-host-postgres"
CONTAINER_DATA_DIR="/var/lib/postgresql/data"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "postgres: container not found" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/container.sh
source "$SCRIPT_DIR/../lib/container.sh"

expected_dir="$(resolve_data_dir AW_POSTGRES_HOST_DIR postgres-data)"
actual_dir="$(mount_source "$CONTAINER_NAME" "$CONTAINER_DATA_DIR")"
if [ "$actual_dir" != "$expected_dir" ]; then
  echo "postgres: mounted on '${actual_dir:-<unknown>}', expected '$expected_dir' — recreating on the expected data dir" >&2
  exit 1
fi

podman exec "$CONTAINER_NAME" pg_isready -U postgres >/dev/null
podman exec "$CONTAINER_NAME" psql -U postgres -tAc "SELECT 1;" >/dev/null
echo "postgres: healthy"
