#!/usr/bin/env bash
# Exit 0 if the aw-workspace container is running and its health endpoint
# responds — and, when this host now has a podman API socket available,
# the container is actually using it (Tier-2 app containers). A container
# started before the socket existed on this host is stale relative to what
# this host can now do: failing here forces install.sh to recreate it with
# AW_CONTAINER_SOCKET wired in (install.sh already has that recreate-if-
# missing logic; it just needs verify.sh to stop short-circuiting past it).
set -euo pipefail

CONTAINER_NAME="aw-remote-host-workspace"

if ! podman container exists "$CONTAINER_NAME"; then
  echo "workspace: container not found" >&2
  exit 1
fi

curl -fsS "http://127.0.0.1:9030/api/health" >/dev/null

if [ "$(uname -s)" != "Darwin" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=../lib/podman_socket.sh
  source "$SCRIPT_DIR/../lib/podman_socket.sh"
  sock="$(podman_socket_default_path)"
  if [ -S "$sock" ] && ! podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -q '^AW_CONTAINER_SOCKET='; then
    echo "workspace: podman socket is available at $sock but the container isn't using it — recreating for Tier-2 app containers" >&2
    exit 1
  fi
fi

echo "workspace: healthy"
