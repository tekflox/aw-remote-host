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

# Same short-circuit, different drift: the runner treats a module whose
# verify.sh exits 0 as AlreadyOK and never runs install.sh at all, so every
# recreate condition install.sh knows about is unreachable on a host whose
# container is merely *up*. install.sh gained a --init check on 2026-08-20 and
# it never once fired for that reason — the live workspace kept PID 1 as its
# own python process, which reaps nothing it did not spawn, and accumulated
# 151 zombies out of 173 processes over 2.7 days. Anything install.sh
# guarantees about HOW the container was created has to be asserted here too,
# or it only ever applies to hosts that had no container yet.
if [ "$(podman inspect "$CONTAINER_NAME" --format '{{.HostConfig.Init}}')" != "true" ]; then
  echo "workspace: container has no init at PID 1 — recreating so orphaned processes get reaped" >&2
  exit 1
fi

echo "workspace: healthy"
