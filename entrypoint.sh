#!/bin/bash
# Runs `aw-remote-host bootstrap-workspace` in the foreground forever.
# If it dies for any reason (crash, network drop, control-plane restart),
# wait 10s and start it again — restart:always on the container handles
# the case where the container itself dies.
#
# Two things PID 1 owns beyond just running the loop
# (resilience:hosted-entrypoint-signal-and-hang-supervision):
#
#   - SIGTERM has to reach the child. `exec`ing the final command would make
#     that trivial, but it's incompatible with restarting on exit below, so
#     instead the child runs backgrounded and a trap forwards TERM/INT to it
#     and waits — see forward_and_wait(). Without this, PID 1 (a shell blocked
#     in a foreground wait with no trap installed) never reacts to SIGTERM
#     until the child exits on its own, so every `podman stop` on this
#     container burned the full StopTimeout and ended in SIGKILL — of this
#     process AND the nested podman/postgres it supervises — whether the Go
#     process was wedged or perfectly healthy. Bash specifically (not the
#     POSIX `sh` this used to be) because its `wait` builtin is documented to
#     return immediately on a trapped signal, with the trap then running
#     right after — the exact interruptibility this depends on. Bash is
#     already a hard dependency here (see Dockerfile).
#   - The while loop below only restarts the child when it EXITS. A process
#     that's running but wedged never exits, so a hang was invisible to this
#     script and to `podman restart` alike. The heartbeat watcher started
#     near the bottom of this file is the liveness half: it kills a child
#     whose heartbeat file has gone stale so the restart loop can do its job.
set -u

CONTROL_PLANE="${AW_CONTROL_PLANE:-https://api.aw.tekflox.com}"
STATUS_DIR=/run/aw-remote-host
STATUS_FILE="$STATUS_DIR/status"
# Touched by aw-remote-host itself (AW_REMOTE_HOST_HEARTBEAT_FILE) once per
# completed /link read-loop iteration — see internal/link/link.go's
# touchHeartbeat. Reset to "now" each time a child starts (below) so a fresh
# process gets the full HEARTBEAT_STALE_SECONDS before the watcher judges it.
HEARTBEAT_FILE="$STATUS_DIR/heartbeat"
CHILD_PID_FILE="$STATUS_DIR/child.pid"
export AW_REMOTE_HOST_HEARTBEAT_FILE="$HEARTBEAT_FILE"
mkdir -p "$STATUS_DIR"

# AW_REMOTE_HOST_TOKEN is only required for FIRST-TIME linking. Once linked,
# aw-console's credential is persisted at $CREDENTIALS_PATH, which lives on
# the aw-remote-host-state volume and survives a container recreate — the
# aw-remote-host binary itself already falls back to that stored credential
# when --token is empty (cmd/aw-remote-host/commands.go, `alreadyLinked`).
# Requiring the token unconditionally here used to reject an already-linked
# host the instant .env lost the key (see
# reliability:deploy-env-overwrite-drops-manual-vars) even though nothing
# about this host's link had actually changed.
CREDENTIALS_PATH="$HOME/.aw-remote-host/credentials.json"
if [ -s "$CREDENTIALS_PATH" ]; then
  ALREADY_LINKED=1
else
  ALREADY_LINKED=0
fi

if [ -z "${AW_REMOTE_HOST_TOKEN:-}" ] && [ "$ALREADY_LINKED" = 0 ]; then
  echo "status=missing_token detail=no_stored_credentials" > "$STATUS_FILE"
  echo "aw-remote-host: AW_REMOTE_HOST_TOKEN is not set and this host has no stored credentials at $CREDENTIALS_PATH — set AW_REMOTE_HOST_TOKEN in .env (token from aw-console) and redeploy. Exiting." >&2
  exit 1
fi
echo "status=starting" > "$STATUS_FILE"

# bootstrap-workspace's first-run seed (`podman cp` from the seed container)
# lands root-owned on disk because this whole CLI runs as root in this
# container (nested/rootful podman, unlike a normal bare-metal install where
# it runs rootless as the host user) — the aw-workspace image's process runs
# as uid 1001 and can't write into a root-owned bind mount. Chown it once
# it shows up, in the background, so the workspace container's first start
# doesn't crash-loop on PermissionError.
(
  for i in $(seq 1 60); do
    dir="$HOME/aw-workspace"
    if [ -d "$dir" ] && [ "$(stat -c %u "$dir" 2>/dev/null)" = "0" ]; then
      chown -R 1001:1001 "$dir" && echo "entrypoint: chowned $dir to uid 1001" >&2
      break
    fi
    sleep 2
  done
) &

# --- tailscaled, supervised ------------------------------------------------
# This container is a Linux host in every way the mesh cares about — root, full
# capabilities, /dev/net/tun, its own netns, and 70+ containers of its own on
# two podman networks — and it will never have systemd as PID 1, because PID 1
# here is this script. internal/vpn used to read that as "nothing keeps
# tailscaled running" and refuse enrolment; since 2026-09-01 it accepts a
# supervisor that DECLARES itself and is still alive to back the claim, which
# is what the marker below is (vpn.SupervisorMarker / vpn_has_supervisor).
#
# Written fresh on every boot, and the stale one removed first: the check on
# the other side verifies the declared pid is alive, but /run is part of this
# image's overlay rather than a tmpfs, so a marker CAN outlive the boot that
# wrote it and this is the half that stops it trying.
SUPERVISOR_MARKER=/run/aw-remote-host/tailscaled-supervisor
rm -f "$SUPERVISOR_MARKER"
mkdir -p /run/aw-remote-host /var/run/tailscale
# State on $HOME, which is the aw-remote-host-state volume — so this node's
# mesh identity survives the container recreation that a deploy performs. In
# /run it would re-register as a brand-new node on every deploy, leaving a
# trail of dead nodes in headscale and a fresh mesh IP each time.
mkdir -p "$HOME/tailscaled"
(
  while true; do
    if command -v tailscaled >/dev/null 2>&1; then
      # No --tun=userspace-networking: /dev/net/tun is present here (the
      # container is privileged) and userspace mode would give a SOCKS5 proxy
      # carrying none of this host's traffic, which is the failure internal/vpn
      # refuses unprivileged Linux hosts over.
      tailscaled \
        --state="$HOME/tailscaled/tailscaled.state" \
        --socket=/var/run/tailscale/tailscaled.sock \
        --port=41641
      echo "tailscaled: exited ($?) — restarting in 5s" >&2
    else
      # Not installed yet. Possible on an older image, and on the boot where
      # the vpn bootstrap module installs it — so keep looking rather than
      # exiting, or the supervisor would be declared and supervising nothing.
      echo "tailscaled: not installed yet — looking again in 5s" >&2
    fi
    sleep 5
  done
) &
# Declared only after the supervising subshell exists, and naming ITS pid, not
# this script's: the claim is "that process restarts tailscaled", so the pid
# has to be the one that would stop being alive if it ever stopped being true.
printf 'name=aw-remote-host-entrypoint\npid=%s\n' "$!" > "$SUPERVISOR_MARKER"

# FAIL_COUNT tracks consecutive FAST exits (< FAIL_WINDOW_SECONDS alive) so
# the healthcheck (healthcheck.sh, next to this file) can tell a real
# crash-loop apart from an occasional network blip that self-heals — without
# this, every failure mode here looked the same from outside the container:
# `docker ps` showing "Up" forever while this loop silently retried underneath
# it (see reliability:deploy-env-overwrite-drops-manual-vars).
FAIL_COUNT=0
FAIL_THRESHOLD=3
FAIL_WINDOW_SECONDS=30

# --- signal handling: forward TERM/INT to the current child, then stop -----
# CHILD_PID is only ever read/written by this script's own main flow (the
# trap runs IN this shell, interrupting whatever it was doing — see the file
# header for why bash's wait semantics make that safe), so a plain variable
# is enough here. The heartbeat watcher below is a SEPARATE process and can't
# see it, which is what CHILD_PID_FILE is for.
CHILD_PID=""

forward_and_wait() {
  if [ -n "$CHILD_PID" ] && kill -0 "$CHILD_PID" 2>/dev/null; then
    echo "entrypoint: stop signal received — forwarding TERM to aw-remote-host (pid $CHILD_PID) and waiting for a clean shutdown" >&2
    kill -TERM "$CHILD_PID" 2>/dev/null
    wait "$CHILD_PID" 2>/dev/null
    echo "entrypoint: aw-remote-host stopped cleanly" >&2
  fi
  [ -n "${WATCHER_PID:-}" ] && kill "$WATCHER_PID" 2>/dev/null
  rm -f "$CHILD_PID_FILE"
  echo "status=stopped" > "$STATUS_FILE"
  exit 0
}
trap forward_and_wait TERM INT

# --- heartbeat watcher: catches a wedged-but-alive child, not just a crash -
# Runs as its own background process for the life of the container (started
# once, unlike CHILD_PID above which changes every restart) and reads
# CHILD_PID_FILE each pass so it always targets whichever child is current.
#
# HEARTBEAT_STALE_SECONDS is deliberately far above internal/link/link.go's
# 90s defaultPumpReadTimeout: a healthy connection's own read timeout already
# forces a reconnect well before this fires, and a healthy IDLE connection
# still gets a heartbeat touch at least that often from the server's own
# ping cadence. Killing a merely-idle-but-healthy link is worse than the
# hang this exists to catch, so this threshold has to clear that bar with
# margin, not just barely exceed it. Overridable for the same reason
# CONTROL_PLANE is: production tuning without editing this file, and a short
# value is also how this behavior gets verified quickly rather than waiting
# out five real minutes.
HEARTBEAT_STALE_SECONDS="${AW_REMOTE_HOST_HEARTBEAT_STALE_SECONDS:-300}"
HEARTBEAT_CHECK_INTERVAL="${AW_REMOTE_HOST_HEARTBEAT_CHECK_INTERVAL:-15}"

(
  while true; do
    sleep "$HEARTBEAT_CHECK_INTERVAL"
    pid=$(cat "$CHILD_PID_FILE" 2>/dev/null) || continue
    [ -n "$pid" ] || continue
    kill -0 "$pid" 2>/dev/null || continue
    [ -f "$HEARTBEAT_FILE" ] || continue
    now=$(date +%s)
    mtime=$(stat -c %Y "$HEARTBEAT_FILE" 2>/dev/null) || continue
    age=$(( now - mtime ))
    if [ "$age" -gt "$HEARTBEAT_STALE_SECONDS" ]; then
      echo "entrypoint: heartbeat stale (${age}s, threshold ${HEARTBEAT_STALE_SECONDS}s) — aw-remote-host (pid $pid) looks wedged rather than merely idle. Killing it so the restart loop recycles it." >&2
      kill -TERM "$pid" 2>/dev/null
      sleep 5
      kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
    fi
  done
) &
WATCHER_PID=$!

while true; do
  echo "status=running" > "$STATUS_FILE"
  : > "$HEARTBEAT_FILE"
  START_TS=$(date +%s)
  aw-remote-host bootstrap-workspace \
    --token "${AW_REMOTE_HOST_TOKEN:-}" \
    --control-plane "$CONTROL_PLANE" \
    --yes \
    --foreground &
  CHILD_PID=$!
  echo "$CHILD_PID" > "$CHILD_PID_FILE"
  wait "$CHILD_PID"
  EXIT_CODE=$?
  CHILD_PID=""
  rm -f "$CHILD_PID_FILE"
  RUNTIME=$(( $(date +%s) - START_TS ))
  echo "aw-remote-host: exited ($EXIT_CODE) after ${RUNTIME}s — restarting in 10s" >&2

  if [ "$RUNTIME" -lt "$FAIL_WINDOW_SECONDS" ]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    FAIL_COUNT=0
  fi

  if [ "$FAIL_COUNT" -ge "$FAIL_THRESHOLD" ]; then
    echo "status=crash_loop exit_code=$EXIT_CODE fail_count=$FAIL_COUNT" > "$STATUS_FILE"
  else
    echo "status=retrying exit_code=$EXIT_CODE fail_count=$FAIL_COUNT" > "$STATUS_FILE"
  fi

  # Backgrounded + waited rather than a plain `sleep 10`, same reason as the
  # child above: a plain foreground sleep would also swallow a stop signal
  # for up to its own duration.
  sleep 10 &
  wait $!
done
