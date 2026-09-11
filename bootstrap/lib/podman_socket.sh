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
  # Liveness, not existence — a leftover socket file from a service that died
  # with a container restart would otherwise make this a no-op and leave the
  # host with a dead socket it believes in. See podman_socket_alive.
  if podman_socket_alive "$sock"; then
    return 0
  fi
  [ -S "$sock" ] && rm -f "$sock"
  mkdir -p "$(dirname "$sock")"
  # >&2 — this function's stdout is reserved for the socket path a caller
  # captures via $(...); a log line on stdout would corrupt that value
  # (exactly what happened during testing before this was fixed).
  echo "podman: no systemd init here — starting 'podman system service' directly for $sock" >&2
  nohup podman system service --time=0 "unix://${sock}" >/tmp/podman-system-service.log 2>&1 &
  disown 2>/dev/null || true
  for _ in $(seq 1 30); do
    if podman_socket_alive "$sock"; then
      # `podman system service` run this way (root, no systemd socket unit
      # to set a group/mode for us) creates the socket root:root 0600 — a
      # Tier-2 app container bind-mounting it in (workspace/install.sh)
      # always runs as a non-root uid (1001), so every API call fails
      # EACCES/"Permission denied" without this. Same trust boundary
      # workspace/install.sh already accepts for the SELinux case
      # (--security-opt label=disable): this socket is only ever reached
      # from inside this same single-tenant host/container, not exposed
      # externally, so a permissive DAC mode isn't widening anything real.
      chmod 0666 "$sock" 2>/dev/null || true
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# ensure_podman_socket makes sure a podman API socket is listening on this
# host and prints its path on success (nothing on stdout on failure). Safe
# to call unconditionally and repeatedly — every caller just wants "give me
# a working socket path, however that has to happen on THIS host."
# podman_socket_alive <sock>
#
# True only when something is ANSWERING on <sock>. A socket FILE outlives the
# process that created it, so `[ -S ]` answers a different question than the
# one every caller is asking.
#
# THE INCIDENT (2026-09-11): the aw-remote-host container was restarted. /run
# is part of its writable layer, so the socket file survived while the
# `podman system service` holding it did not. ensure_podman_socket saw the
# file, reported success, and bootstrap printed "podman: API socket ready" —
# over a dead socket. The workspace container was then rebuilt with that dead
# inode bind-mounted in, so every Tier-2 app container it tried to manage
# failed with "Cannot connect to the Docker daemon", and the workspace's own
# component listing 500'd. Nothing in the chain reported a problem, because
# every check in it was asking whether a file existed.
#
# Probes with podman itself rather than curl: podman is by definition present
# here (this is its own socket), curl is not guaranteed on a BYOD host.
podman_socket_alive() {
  [ -S "$1" ] || return 1
  podman --remote --url "unix://$1" version >/dev/null 2>&1
}

ensure_podman_socket() {
  local sock
  sock="$(podman_socket_default_path)"

  if podman_socket_alive "$sock"; then
    printf '%s' "$sock"
    return 0
  fi
  # A socket file with nothing behind it would make every path below skip the
  # bring-up it needs, so it goes. Removing it is safe precisely BECAUSE
  # nothing is listening: a live socket never reaches this line.
  [ -S "$sock" ] && rm -f "$sock"

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
      podman_socket_alive "$sock" && { printf '%s' "$sock"; return 0; }
      sleep 0.5
    done
  fi

  # Either there's no systemd init to hand this to, or the unit didn't bring
  # the socket up (e.g. this distro's podman package lacks podman.socket) —
  # fall back to running the API service ourselves.
  if _start_socket_directly "$sock" && podman_socket_alive "$sock"; then
    printf '%s' "$sock"
    return 0
  fi

  return 1
}
