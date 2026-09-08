#!/usr/bin/env bash
# Exit 0 if podman is installed and healthy, non-zero otherwise.
set -euo pipefail

if [ "$(uname -s)" = "Darwin" ]; then
  runtime_found=""
  if command -v podman >/dev/null 2>&1 && podman machine list --format '{{.Running}}' 2>/dev/null | grep -q true; then
    runtime_found="podman machine"
  elif command -v colima >/dev/null 2>&1 && colima status >/dev/null 2>&1; then
    runtime_found="colima"
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    runtime_found="Docker Desktop"
  fi

  if [ -z "$runtime_found" ]; then
    echo "podman: no container runtime found on macOS (checked: podman machine, colima, Docker Desktop)" >&2
    echo "podman: start one, e.g. 'podman machine init && podman machine start', then re-run" >&2
    exit 1
  fi

  if ! command -v podman >/dev/null 2>&1 || ! podman info >/dev/null 2>&1; then
    echo "podman: detected $runtime_found, but the 'podman' CLI isn't talking to it yet" >&2
    echo "podman: every module here drives containers via 'podman run' — run 'podman machine start' (or point podman at your $runtime_found backend), then re-run" >&2
    exit 1
  fi

  echo "podman: healthy via $runtime_found ($(podman --version))"
  exit 0
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "podman: not installed" >&2
  exit 1
fi

podman info >/dev/null

# Tier-2 (container-per-app) support needs a running podman API socket, not
# just a working CLI — fail verify (forcing install.sh to run and bring the
# socket up) until it's actually listening. See bootstrap/lib/podman_socket.sh.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/podman_socket.sh
source "$SCRIPT_DIR/../lib/podman_socket.sh"
sock="$(podman_socket_default_path)"
if [ ! -S "$sock" ]; then
  echo "podman: API socket not listening at $sock (needed for Tier-2 app containers)" >&2
  exit 1
fi

# install.sh guarantees the graphroot is pinned under $HOME on a rootful
# host; per runner.go's invariant that guarantee is unreachable unless this
# file checks it too. It is not cosmetic: $HOME is the only path on the
# aw-remote-host volume, so an unpinned graphroot puts every container and
# image on the outer container's writable layer, where the next recreate
# erases them — the 2026-09-02 postgres/redis data-loss incident. Until now
# only the socket check above happened to stand in the way of re-arming it.
# See bootstrap/lib/podman_storage.sh.
if [ "$(id -u)" = "0" ]; then
  expected_graphroot="$HOME/.local/share/containers/storage"
  actual_graphroot="$(podman info --format '{{.Store.GraphRoot}}' 2>/dev/null || true)"
  if [ "$actual_graphroot" != "$expected_graphroot" ]; then
    echo "podman: graphroot is '$actual_graphroot', expected '$expected_graphroot' — containers would live on an ephemeral layer and be erased by the next recreate (see bootstrap/lib/podman_storage.sh)" >&2
    exit 1
  fi

  # Same rootful-only gate as the graphroot check above, checked against the
  # file directly rather than `podman info`: the incident this guards against
  # is `podman system service` (the daemon, started next in install.sh) never
  # rereading containers.conf after it starts, so a `podman info` value could
  # read correct while the running daemon is still on the old driver — the
  # file is the only thing this check can meaningfully assert about a fresh
  # boot. See bootstrap/lib/podman_firewall.sh.
  firewall_conf=/etc/containers/containers.conf
  if [ ! -f "$firewall_conf" ] || ! grep -q 'firewall_driver = "iptables"' "$firewall_conf" 2>/dev/null; then
    echo "podman: $firewall_conf does not pin firewall_driver to iptables — netavark's nftables backend hits a known kernel bug on this host and container networking would fail on the next recreate (see bootstrap/lib/podman_firewall.sh)" >&2
    exit 1
  fi
fi

# The version floor, LAST: everything above is about podman working at all,
# and those messages are more useful than a version complaint when podman is
# simply broken. Conditional by design — see bootstrap/lib/podman_version.sh
# for why an unconditional floor bricks every Debian 12 host.
# shellcheck source=../lib/podman_version.sh
source "$SCRIPT_DIR/../lib/podman_version.sh"
assert_podman_version_floor

echo "podman: healthy ($(podman --version)), API socket at $sock"
