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

# The container's $HOME (/home/ubuntu) — where CLI tools installed by apps
# (claude, codex, copilot, cursor-agent, gh, npm's own cache/config, ...)
# keep their own login/config state — was NOT host-mounted at all before
# 2026-08-04: only CONTAINER_WORKDIR was. Every workspace update/recreate
# wiped it, so `claude login` (etc.) had to be redone every time. Sibling
# dir to HOST_DIR, NOT nested inside it — syncWorkspaceSource's update path
# only special-cases ".aw-workspace"/"apps" as things to preserve when
# syncing HOST_DIR's tree from the image; keeping this outside HOST_DIR
# entirely means that logic never has to know about it.
CONTAINER_HOME="/home/ubuntu"
DEFAULT_HOME_HOST_DIR="${HOME}/aw-workspace-home"
HOME_HOST_DIR="${AW_WORKSPACE_HOME_HOST_DIR:-${DEFAULT_HOME_HOST_DIR}}"
WORKSPACE_UID="1001"
WORKSPACE_GID="1001"

# Opt-in passthrough for aw-app-agents-platform-runners' warm-container mode
# (RUNNER_WARM_CONTAINER=1, default off — see that app's warm_pool.py). Only
# forwarded into the container when the HOST's own aw-remote-host process has
# it set, so every other BYOD host's default stays untouched.
RUNNER_WARM_CONTAINER="${RUNNER_WARM_CONTAINER:-}"

# Elevated host access this machine opted into, already probed and reduced to
# the EFFECTIVE set by internal/hostpower (see resolveHostPower in
# cmd/aw-remote-host/commands.go). Empty on every host that never opted in.
#
# This is passed to the workspace as an env var, NOT as podman flags on the
# workspace container itself. The workspace does not use these devices — it
# creates app containers as its own siblings over the mounted podman socket,
# and it is those containers that get --device/--cap-add, built from this same
# grant list by src/apps/hostpower.py. Elevating the workspace container here
# would grant access to the one process that has no use for it while leaving
# the app that needs it unchanged.
AW_HOST_POWER="${AW_HOST_POWER:-}"

# Worker-process count for this container — persisted HOST state (see
# internal/state.State.Workers / EffectiveWorkers), NOT baked into the image
# beyond its own ENV default of 1. Set by the Go layer the same way
# AW_HOST_POWER is; defaults to 1 here too so a direct invocation of this
# script (local dev, or any caller that never wired the env var up) still
# gets a valid value instead of `-e AW_WORKSPACE_WORKERS=` with an empty
# string, which would break `int(os.environ["AW_WORKSPACE_WORKERS"])` in
# src/start/workspace.py.
AW_WORKSPACE_WORKERS="${AW_WORKSPACE_WORKERS:-1}"

if [ -z "${AW_WORKSPACE_HOST_DIR:-}" ] && [ ! -e "$DEFAULT_HOST_DIR" ] && [ -e "$LEGACY_HOST_DIR" ]; then
  if podman container exists "$CONTAINER_NAME"; then
    echo "workspace: removing existing container before host-dir migration"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  echo "workspace: migrating host dir $LEGACY_HOST_DIR -> $DEFAULT_HOST_DIR"
  mv "$LEGACY_HOST_DIR" "$DEFAULT_HOST_DIR"
fi
mkdir -p "$HOST_DIR"
mkdir -p "$HOME_HOST_DIR"
# Must be writable by the container's `ubuntu` (1001:1001) — root here can
# chown directly; a rootless host needs `podman unshare` to land inside its
# own user-namespace mapping (same dual-path ops.go's Update() uses for
# HOST_DIR after every sync).
if [ "$(id -u)" = "0" ]; then
  chown -R "${WORKSPACE_UID}:${WORKSPACE_GID}" "$HOME_HOST_DIR" 2>/dev/null || true
else
  podman unshare chown -R "${WORKSPACE_UID}:${WORKSPACE_GID}" "$HOME_HOST_DIR" 2>/dev/null || true
fi

PULL_ARGS=()
if [[ "$IMAGE" == localhost/* || "$IMAGE" == localhost:* || "$IMAGE" == 127.0.0.1/* || "$IMAGE" == 127.0.0.1:* ]]; then
  PULL_ARGS=(--tls-verify=false)
fi

# Ensure the shared network exists (postgres/redis create it too — idempotent).
# ensure_network also repairs a podman-3.x CNI config the installed plugins
# would otherwise reject — see bootstrap/lib/network.sh.
NETWORK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/network.sh
source "$NETWORK_LIB_DIR/../lib/network.sh"
ensure_network "$NETWORK_NAME"

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
  # `podman cp` writes as the invoking user (root on a rootful host), but the
  # image's process runs as uid 1001 — so the freshly seeded tree is unwritable
  # by the very container about to mount it. Boot then dies on
  #     PermissionError: '/opt/aw-workspace/.aw-workspace/bin'
  # which reads as a broken image rather than a chown that never happened.
  #
  # This was invisible on a CONTAINERISED BYOD host, where aw-remote-host's own
  # entrypoint.sh runs a background chown loop over $HOME/aw-workspace. A NATIVE
  # install has no such entrypoint, so nothing covered it and every bare-metal
  # provision hit it (found on aw.tekflox.com, 2026-08-17). ops.go's Update()
  # already chowns HOST_DIR after every sync — the gap was only the first seed.
  #
  # Same dual root/rootless path the HOME_HOST_DIR chown above uses.
  if [ "$(id -u)" = "0" ]; then
    chown -R "${WORKSPACE_UID}:${WORKSPACE_GID}" "$HOST_DIR" 2>/dev/null || true
  else
    podman unshare chown -R "${WORKSPACE_UID}:${WORKSPACE_GID}" "$HOST_DIR" 2>/dev/null || true
  fi
else
  echo "workspace: $HOST_DIR already populated — leaving host files untouched"
fi

# Tier-2 (container-per-app) support: mount the host's podman socket into the
# workspace so the decoupled-apps ContainerSupervisor can spawn app containers
# over the Docker API (podman is Docker-API-compatible). TRUST NOTE: on a
# normal BYOD Linux/macOS host this is the *rootless* socket — scoped to the
# unprivileged `aw`/host user, NOT root — so an app container can only do what
# that user already can (no host root). On a rootful nested deployment (no
# host user to be rootless as — see bootstrap/lib/podman_socket.sh) it's the
# rootful socket instead, which is the best available on that host shape.
# Frederico approved mounting it (Telegram 2026-07-28). App containers join
# the same podman network so the workspace reaches them by name
# (AW_CONTAINER_NETWORK), exactly like it reaches postgres/redis.
HOST_PODMAN_SOCK=""
SOCKET_AVAILABLE=0
if [ "$(uname -s)" = "Darwin" ]; then
  # macOS launchd services normally do not have XDG_RUNTIME_DIR, and podman
  # itself runs against a VM — the bind source must be the socket path
  # inside the Podman VM, not a macOS client-side path.
  HOST_PODMAN_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  if [ -S "$HOST_PODMAN_SOCK" ]; then
    SOCKET_AVAILABLE=1
  else
    MACHINE_SOCK="$(podman machine ssh podman-machine-default 'sock="/run/user/$(id -u)/podman/podman.sock"; test -S "$sock" && printf %s "$sock"' 2>/dev/null || true)"
    if [ -n "$MACHINE_SOCK" ]; then
      HOST_PODMAN_SOCK="$MACHINE_SOCK"
      SOCKET_AVAILABLE=1
    fi
  fi
else
  # Linux: rootless-with-systemd and rootful-without-systemd (this
  # container's own deployment shape) need different paths AND different
  # start-up strategies — ensure_podman_socket works out which this host is
  # and, if nothing's listening yet, brings the socket up itself (the
  # bootstrap/podman module already tries this too; calling it again here
  # is a cheap no-op unless workspace is being re-bootstrapped on its own).
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=../lib/podman_socket.sh
  source "$SCRIPT_DIR/../lib/podman_socket.sh"
  HOST_PODMAN_SOCK="$(podman_socket_default_path)"
  if sock="$(ensure_podman_socket)"; then
    HOST_PODMAN_SOCK="$sock"
    SOCKET_AVAILABLE=1
  fi
fi
CONTAINER_SOCK="/run/podman.sock"
SOCKET_ARGS=()
if [ "$SOCKET_AVAILABLE" = "1" ]; then
  echo "workspace: mounting podman socket $HOST_PODMAN_SOCK (Tier-2 apps enabled)"
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
  echo "workspace: no podman socket at $HOST_PODMAN_SOCK — Tier-2 apps disabled" >&2
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
      | grep -qx "$CONTAINER_HOME"; then
    echo "workspace: existing container has no persistent \$HOME mount — recreating so CLI logins survive updates"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  elif [ -n "$RUNNER_WARM_CONTAINER" ] && ! podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -qx "RUNNER_WARM_CONTAINER=${RUNNER_WARM_CONTAINER}"; then
    echo "workspace: RUNNER_WARM_CONTAINER changed — recreating to pick it up"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  # Without --init, PID 1 is the workspace's own `python -m src.start.workspace`,
  # which only waits on pids it spawned itself. Every process in the container
  # that outlives its parent gets re-parented to it and then never reaped: 151
  # zombies out of 173 processes after 2.7 days of uptime when this was found on
  # 2026-08-20 (gh, chrome-headless, bash, ssh-agent, go, git). --init puts
  # catatonit at PID 1 to reap them, and leaves the server's own subprocess.run
  # children alone — unlike a wildcard waitpid(-1) in-process, which races
  # subprocess.run and turns a failed command into a silent success (see the
  # workspace's src/api/terminal_manager.py:_reap_children).
  #
  # The same recreate also picks up --ulimit core=0. The host kernel's
  # core_pattern is a bare "core" with core_uses_pid=1, so a segfaulting app
  # dumps its whole RSS into its cwd — /opt/aw-workspace/core.<pid>, on the
  # bind mount, where it survives every restart. codegraphcontext SIGSEGV'd 4
  # times in 2 days and left 27 GB there, on a disk already at 79%. Nobody was
  # ever going to load an 11.7 GB core; the crash is worth fixing, the dump is
  # not worth keeping. core_pattern itself is host-wide and shared with every
  # other container, so it is not this installer's to change.
  elif [ "$(podman inspect "$CONTAINER_NAME" --format '{{.HostConfig.Init}}')" != "true" ]; then
    echo "workspace: existing container has no init at PID 1 — recreating so orphaned processes get reaped"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  # Env is fixed at container creation, so a changed grant set only reaches the
  # workspace through a recreate. Unlike the checks above this one compares in
  # BOTH directions (revoking has to take effect too, or --host-power=none
  # leaves a workspace that still believes it may elevate app containers).
  elif [ "$(podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | sed -n 's/^AW_HOST_POWER=//p' | head -n1)" != "$AW_HOST_POWER" ]; then
    echo "workspace: AW_HOST_POWER changed (now '${AW_HOST_POWER:-none}') — recreating to pick it up"
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  # Same rationale as the AW_HOST_POWER check above: env is fixed at
  # container creation, so a persisted worker-count change only reaches the
  # workspace through a recreate.
  elif [ "$(podman inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | sed -n 's/^AW_WORKSPACE_WORKERS=//p' | head -n1)" != "$AW_WORKSPACE_WORKERS" ]; then
    echo "workspace: AW_WORKSPACE_WORKERS changed (now '${AW_WORKSPACE_WORKERS}') — recreating to pick it up"
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
    --init \
    --ulimit core=0 \
    -p 127.0.0.1:9030:9030 \
    -v "${HOST_DIR}:${CONTAINER_WORKDIR}" \
    -v "${HOME_HOST_DIR}:${CONTAINER_HOME}" \
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
    -e AW_WORKSPACE_HOME_HOST_DIR="$HOME_HOST_DIR" \
    ${RUNNER_WARM_CONTAINER:+-e RUNNER_WARM_CONTAINER="$RUNNER_WARM_CONTAINER"} \
    -e AW_HOST_POWER="$AW_HOST_POWER" \
    -e AW_WORKSPACE_WORKERS="$AW_WORKSPACE_WORKERS" \
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
