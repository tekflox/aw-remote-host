#!/usr/bin/env bash
# Shared podman-API-socket helpers — sourced by bootstrap/podman/{install,verify}.sh
# and bootstrap/workspace/install.sh so all three agree on ONE path-resolution +
# start-up strategy instead of guessing independently. That independent guessing
# is exactly how Tier-2 (container-per-app) support went silently missing on a
# rootful/no-systemd BYOD host: workspace/install.sh only ever checked the
# rootless XDG socket path, which never existed there.
#
# Self-bootstrap has to understand its own host before it can wire this up:
# Linux BYOD hosts come in two shapes, and only runtime probing tells them
# apart —
#   - rootless, with a real systemd user session (the common case: the
#     user's own account) — podman.socket is a systemd --user unit.
#   - rootful with NO systemd as init (e.g. aw-remote-host itself, running
#     inside a plain container driven by a shell entrypoint loop, not
#     systemd) — nothing manages the socket for us, so we start
#     `podman system service` directly and leave it running detached.
# macOS has no native podman daemon at all (podman talks to a VM) — that
# path is handled entirely by workspace/install.sh's own podman-machine-ssh
# fallback and deliberately NOT touched here.
#
# Not meant to be executed directly — only sourced.

# podman_socket_default_path prints where THIS host's podman API socket
# belongs, given whether podman itself runs rootful or rootless here.
podman_socket_default_path() {
  if [ "$(id -u)" = "0" ]; then
    echo "/run/podman/podman.sock"
  else
    echo "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  fi
}

# _systemd_is_init is true only when systemd is actually PID 1 managing this
# machine/container. The systemctl/systemd *binaries* being merely installed
# (common in base container images that never run as init) isn't enough —
# calling systemctl against a systemd that isn't running as init just fails
# with "Failed to connect to bus: Host is down".
_systemd_is_init() {
  [ "$(cat /proc/1/comm 2>/dev/null)" = "systemd" ]
}

# _start_socket_directly launches `podman system service` as a detached
# background process bound to $1, for hosts with no systemd to hand the
# socket-activation job to. Idempotent — no-ops if something's already
# listening on $1, and safe to call from multiple modules across a single
# bootstrap run.
_start_socket_directly() {
  local sock="$1"
  if [ -S "$sock" ]; then
    return 0
  fi
  mkdir -p "$(dirname "$sock")"
  # >&2 — this function's stdout is reserved for the socket path a caller
  # captures via $(...); a log line on stdout would corrupt that value
  # (exactly what happened during testing before this was fixed).
  echo "podman: no systemd init here — starting 'podman system service' directly for $sock" >&2
  nohup podman system service --time=0 "unix://${sock}" >/tmp/podman-system-service.log 2>&1 &
  disown 2>/dev/null || true
  for _ in $(seq 1 30); do
    [ -S "$sock" ] && return 0
    sleep 0.5
  done
  return 1
}

# ensure_podman_socket makes sure a podman API socket is listening on this
# host and prints its path on success (nothing on stdout on failure). Safe
# to call unconditionally and repeatedly — every caller just wants "give me
# a working socket path, however that has to happen on THIS host."
ensure_podman_socket() {
  local sock
  sock="$(podman_socket_default_path)"

  if [ -S "$sock" ]; then
    printf '%s' "$sock"
    return 0
  fi

  if _systemd_is_init && command -v systemctl >/dev/null 2>&1; then
    if [ "$(id -u)" = "0" ]; then
      systemctl enable --now podman.socket >/dev/null 2>&1 || true
    else
      # A --user unit's socket is torn down when the user's last session
      # ends unless lingering is enabled — enable it so the socket survives
      # an SSH disconnect (the whole point of an unattended BYOD host).
      loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true
      systemctl --user enable --now podman.socket >/dev/null 2>&1 || true
    fi
    for _ in $(seq 1 20); do
      [ -S "$sock" ] && { printf '%s' "$sock"; return 0; }
      sleep 0.5
    done
  fi

  # Either there's no systemd init to hand this to, or the unit didn't bring
  # the socket up (e.g. this distro's podman package lacks podman.socket) —
  # fall back to running the API service ourselves.
  if _start_socket_directly "$sock"; then
    printf '%s' "$sock"
    return 0
  fi

  return 1
}
