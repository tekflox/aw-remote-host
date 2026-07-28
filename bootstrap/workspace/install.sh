#!/usr/bin/env bash
# Install (or reuse) the aw-workspace runtime container. Idempotent.
# Requires AW_WORKSPACE_SLUG / AW_POSTGRES_PASSWORD / AW_BACKEND_URL /
# AW_WORKSPACE_HOST_TOKEN in the environment — aw-remote-host sets these after
# the /link registration reply tells it which workspace slug this token is
# scoped to (the user never types a slug).
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
: "${AW_WORKSPACE_HOST_TOKEN:?AW_WORKSPACE_HOST_TOKEN must be set (durable awlk_ host credential)}"

IMAGE="ghcr.io/fredericowu/aw-workspace:latest"
CONTAINER_NAME="aw-remote-host-workspace"
NETWORK_NAME="aw-remote-host"
PG_HOST="aw-remote-host-postgres"
REDIS_HOST="aw-remote-host-redis"
SCHEMA="workspace_${AW_WORKSPACE_SLUG}"
DB_URL="postgresql+psycopg://postgres:${AW_POSTGRES_PASSWORD}@${PG_HOST}:5432/aw_workspace"
REDIS_URL="redis://${REDIS_HOST}:6379/0"

# Host directory bind-mounted into the container at /opt/agentic-workspace so
# the whole workspace fs is visible/editable from the host AND survives
# container recreation (apps install into it — decoupled-apps framework).
# Defaults to ~/agentic-workspace (no root needed; under $HOME so podman
# machine already shares it into the VM on macOS). Ties to
# feature:aw-remote-host-configurable-install-path.
CONTAINER_WORKDIR="/opt/agentic-workspace"
HOST_DIR="${AW_WORKSPACE_HOST_DIR:-${HOME}/agentic-workspace}"
mkdir -p "$HOST_DIR"

# Ensure the shared network exists (postgres/redis create it too — idempotent).
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

# First-run seed: the repo is baked into the image at $CONTAINER_WORKDIR, but a
# bind-mount over that path would MASK it with an empty host dir. So if the host
# dir is empty, populate it from the image first. Re-bootstrap with an existing
# (non-empty) host dir is left untouched — never clobber the user's files/apps.
if [ -z "$(ls -A "$HOST_DIR" 2>/dev/null)" ]; then
  echo "workspace: seeding $HOST_DIR from image $IMAGE (first run)"
  podman pull "$IMAGE" >/dev/null 2>&1 || true
  SEED_CONTAINER="${CONTAINER_NAME}-seed"
  podman rm -f "$SEED_CONTAINER" >/dev/null 2>&1 || true
  podman create --name "$SEED_CONTAINER" "$IMAGE" >/dev/null
  # trailing /. copies the directory *contents* into HOST_DIR.
  podman cp "${SEED_CONTAINER}:${CONTAINER_WORKDIR}/." "$HOST_DIR"
  podman rm -f "$SEED_CONTAINER" >/dev/null 2>&1 || true
  echo "workspace: seeded $(ls -A "$HOST_DIR" | wc -l | tr -d ' ') entries into $HOST_DIR"
else
  echo "workspace: $HOST_DIR already populated — leaving host files untouched"
fi

# Tier-2 (container-per-app) support: mount the host's ROOTLESS podman socket
# into the workspace so the decoupled-apps ContainerSupervisor can spawn app
# containers over the Docker API (podman is Docker-API-compatible). TRUST NOTE:
# this is the *rootless* socket — scoped to the unprivileged `aw` user, NOT root
# — so an app container can only do what user `aw` already can (no host root).
# Frederico approved mounting it (Telegram 2026-07-28). App containers join the
# same podman network so the workspace reaches them by name (AW_CONTAINER_NETWORK),
# exactly like it reaches postgres/redis.
HOST_PODMAN_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
CONTAINER_SOCK="/run/podman.sock"
SOCKET_ARGS=()
if [ -S "$HOST_PODMAN_SOCK" ]; then
  echo "workspace: mounting rootless podman socket $HOST_PODMAN_SOCK (Tier-2 apps enabled)"
  # --security-opt label=disable: on an SELinux host (e.g. the Fedora CoreOS
  # podman-machine VM on macOS) the bind-mounted rootless socket carries an
  # `unconfined_t` context the nested container's confined domain can't reach —
  # the ContainerSupervisor's docker-SDK call gets EACCES ("Permission denied")
  # even though DAC ownership matches. Disabling SELinux labelling for the
  # workspace container lets it reach the socket. Verified live on macbook-fred
  # 2026-07-28 (without it, `curl --unix-socket /run/podman.sock` = EACCES; with
  # it, the podman API + the aw-app-browser Tier-2 container + CDP all work).
  SOCKET_ARGS=(
    -v "${HOST_PODMAN_SOCK}:${CONTAINER_SOCK}"
    --security-opt label=disable
    -e "AW_CONTAINER_SOCKET=${CONTAINER_SOCK}"
    -e "AW_CONTAINER_NETWORK=${NETWORK_NAME}"
  )
else
  echo "workspace: no rootless podman socket at $HOST_PODMAN_SOCK — Tier-2 apps disabled" >&2
fi

if podman container exists "$CONTAINER_NAME"; then
  if ! podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -q '^AW_WORKSPACE_HOST_TOKEN='; then
    echo "workspace: existing container is missing AW_WORKSPACE_HOST_TOKEN — recreating"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi

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
    -v "${HOST_DIR}:${CONTAINER_WORKDIR}" \
    ${SOCKET_ARGS[@]+"${SOCKET_ARGS[@]}"} \
    -e AW_WORKSPACE="$AW_WORKSPACE_SLUG" \
    -e AW_WORKSPACE_SCHEMA="$SCHEMA" \
    -e AWSERV_DB_URL="$DB_URL" \
    -e AW_WORKSPACE_DB_URL="$DB_URL" \
    -e AW_REDIS_URL="$REDIS_URL" \
    -e AW_BACKEND_URL="$AW_BACKEND_URL" \
    -e AW_WORKSPACE_HOST_TOKEN="$AW_WORKSPACE_HOST_TOKEN" \
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
