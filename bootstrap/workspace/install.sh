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

IMAGE="${AW_WORKSPACE_IMAGE:-ghcr.io/fredericowu/aw-workspace:latest}"
CONTAINER_NAME="aw-remote-host-workspace"
NETWORK_NAME="aw-remote-host"
PG_HOST="aw-remote-host-postgres"
REDIS_HOST="aw-remote-host-redis"
SCHEMA="workspace_${AW_WORKSPACE_SLUG}"
DB_URL="postgresql+psycopg://postgres:${AW_POSTGRES_PASSWORD}@${PG_HOST}:5432/aw_workspace"
REDIS_URL="redis://${REDIS_HOST}:6379/0"

# Host directory bind-mounted into the container at /opt/aw-workspace so
# the whole workspace fs is visible/editable from the host AND survives
# container recreation (apps install into it — decoupled-apps framework).
# Defaults to ~/aw-workspace (no root needed; under $HOME so podman
# machine already shares it into the VM on macOS). Ties to
# feature:aw-remote-host-configurable-install-path.
CONTAINER_WORKDIR="/opt/aw-workspace"
LEGACY_CONTAINER_WORKDIR="/opt/agentic-workspace"
DEFAULT_HOST_DIR="${HOME}/aw-workspace"
LEGACY_HOST_DIR="${HOME}/agentic-workspace"
HOST_DIR="${AW_WORKSPACE_HOST_DIR:-${DEFAULT_HOST_DIR}}"

# Two more host dirs, siblings of HOST_DIR — NOT nested inside it — bind-
# mounted at /opt/home (HOME; dotfiles like ~/.claude) and /opt/data
# (AW_WORKSPACE_HOME; app-installed bin shims/secrets/skills, formerly
# $HOME/.aw-workspace). Separate mounts specifically so this file's own
# `Update` sync of HOST_DIR (see ops.go's syncWorkspaceSource, which wipes
# everything in HOST_DIR not named .aw-workspace before copying the fresh
# image in) can never touch them — they're structurally outside what that
# sync ever iterates. See repos/aw-workspace/Dockerfile for the full
# rationale. Frederico decision 2026-08-01.
HOME_DIR="${AW_WORKSPACE_HOME_DIR:-${HOST_DIR}-home}"
DATA_DIR="${AW_WORKSPACE_DATA_DIR:-${HOST_DIR}-data}"
mkdir -p "$HOME_DIR" "$DATA_DIR"
# The normal (rootless podman, human-run) case relies on podman's own
# userns uid-mapping the same way HOST_DIR already does — untouched here.
# Only when this script itself runs as root (e.g. a privileged/rootful
# podman-in-docker setup, not the common case) does a plain `mkdir -p`
# leave these root-owned, which the container's uid-1001 `ubuntu` process
# can't write into — pre-chown for that case only.
if [ "$(id -u)" = "0" ]; then
  chown 1001:1001 "$HOME_DIR" "$DATA_DIR" 2>/dev/null || true
fi

if [ -z "${AW_WORKSPACE_HOST_DIR:-}" ] && [ ! -e "$DEFAULT_HOST_DIR" ] && [ -e "$LEGACY_HOST_DIR" ]; then
  if podman container exists "$CONTAINER_NAME"; then
    echo "workspace: removing existing container before host-dir migration"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  echo "workspace: migrating host dir $LEGACY_HOST_DIR -> $DEFAULT_HOST_DIR"
  mv "$LEGACY_HOST_DIR" "$DEFAULT_HOST_DIR"
fi
mkdir -p "$HOST_DIR"

PULL_ARGS=()
if [[ "$IMAGE" == localhost/* || "$IMAGE" == localhost:* || "$IMAGE" == 127.0.0.1/* || "$IMAGE" == 127.0.0.1:* ]]; then
  PULL_ARGS=(--tls-verify=false)
fi

# Ensure the shared network exists (postgres/redis create it too — idempotent).
podman network exists "$NETWORK_NAME" >/dev/null 2>&1 || podman network create "$NETWORK_NAME" >/dev/null

# First-run seed: the repo is baked into the image at $CONTAINER_WORKDIR, but a
# bind-mount over that path would MASK it with an empty host dir. So if the host
# dir is empty, populate it from the image first. Re-bootstrap with an existing
# (non-empty) host dir is left untouched — never clobber the user's files/apps.
if [ -z "$(ls -A "$HOST_DIR" 2>/dev/null)" ]; then
  echo "workspace: seeding $HOST_DIR from image $IMAGE (first run)"
  podman pull "${PULL_ARGS[@]}" "$IMAGE" >/dev/null 2>&1 || true
  SEED_CONTAINER="${CONTAINER_NAME}-seed"
  podman rm -f "$SEED_CONTAINER" >/dev/null 2>&1 || true
  podman create --pull=never --name "$SEED_CONTAINER" "$IMAGE" >/dev/null
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
SOCKET_AVAILABLE=0
if [ -S "$HOST_PODMAN_SOCK" ]; then
  SOCKET_AVAILABLE=1
else
  # macOS launchd services normally do not have XDG_RUNTIME_DIR. For Podman
  # machine installs, the bind source must be the socket path inside the
  # Podman VM, not the macOS client socket under /var/folders.
  MACHINE_SOCK="$(podman machine ssh podman-machine-default 'sock="/run/user/$(id -u)/podman/podman.sock"; test -S "$sock" && printf %s "$sock"' 2>/dev/null || true)"
  if [ -n "$MACHINE_SOCK" ]; then
    HOST_PODMAN_SOCK="$MACHINE_SOCK"
    SOCKET_AVAILABLE=1
  fi
fi
CONTAINER_SOCK="/run/podman.sock"
SOCKET_ARGS=()
if [ "$SOCKET_AVAILABLE" = "1" ]; then
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
  if podman inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{println .Destination}}{{end}}' \
      | grep -qx "$LEGACY_CONTAINER_WORKDIR"; then
    echo "workspace: existing container uses legacy mount $LEGACY_CONTAINER_WORKDIR — recreating"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi

if podman container exists "$CONTAINER_NAME"; then
  if ! podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -q '^AW_WORKSPACE_HOST_TOKEN='; then
    echo "workspace: existing container is missing AW_WORKSPACE_HOST_TOKEN — recreating"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  elif [ "$SOCKET_AVAILABLE" = "1" ] && ! podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -q '^AW_CONTAINER_SOCKET='; then
    echo "workspace: existing container is missing AW_CONTAINER_SOCKET — recreating for Tier-2 apps"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  elif [ "$SOCKET_AVAILABLE" = "1" ] && ! podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -q '^AW_WORKSPACE_HOST_DIR='; then
    echo "workspace: existing container is missing AW_WORKSPACE_HOST_DIR — recreating for Tier-2 app volume mounts"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  elif ! podman inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{println .Destination}}{{end}}' \
      | grep -qx "/opt/home"; then
    echo "workspace: existing container predates the /opt/home + /opt/data mounts — recreating"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi

if podman container exists "$CONTAINER_NAME"; then
  echo "workspace: container already exists, ensuring it's running"
  podman network connect "$NETWORK_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || true
  podman start "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  if podman image exists "$IMAGE"; then
    echo "workspace: using existing local image $IMAGE"
  else
    podman pull "${PULL_ARGS[@]}" "$IMAGE" >/dev/null
  fi
  podman run -d \
    --pull=never \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --restart=always \
    -p 127.0.0.1:9030:9030 \
    -v "${HOST_DIR}:${CONTAINER_WORKDIR}" \
    -v "${HOME_DIR}:/opt/home" \
    -v "${DATA_DIR}:/opt/data" \
    ${SOCKET_ARGS[@]+"${SOCKET_ARGS[@]}"} \
    -e AW_WORKSPACE="$AW_WORKSPACE_SLUG" \
    -e AW_WORKSPACE_SCHEMA="$SCHEMA" \
    -e AWSERV_DB_URL="$DB_URL" \
    -e AW_WORKSPACE_DB_URL="$DB_URL" \
    -e AW_REDIS_URL="$REDIS_URL" \
    -e AW_BACKEND_URL="$AW_BACKEND_URL" \
    -e AW_WORKSPACE_HOST_TOKEN="$AW_WORKSPACE_HOST_TOKEN" \
    -e AW_WORKSPACE_HOST_DIR="$HOST_DIR" \
    -e AW_WORKSPACE_CONTAINER_DIR="$CONTAINER_WORKDIR" \
    "$IMAGE"
fi

echo "workspace: waiting for readiness..."
for _ in $(seq 1 "${AW_WORKSPACE_READINESS_TIMEOUT:-180}"); do
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
