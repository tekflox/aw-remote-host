#!/usr/bin/env bash
# Shared helper for creating the user-defined podman network every module
# attaches its container to, plus the CNI repair that a podman 3.x host needs
# before that network is usable at all.
#
# Sourced by bootstrap/{postgres,redis,workspace}/install.sh — all three used
# to inline the same `podman network exists || podman network create`, and all
# three were equally broken by the problem below.

# podmanMajor prints podman's major version, or nothing if it can't be read.
podman_major() {
  podman --version 2>/dev/null | awk '{print $3}' | cut -d. -f1
}

# repair_cni_config_version rewrites `"cniVersion": "1.0.0"` down to "0.4.0"
# in every CNI conflist on this host, but ONLY on a podman older than 4.
#
# THE BUG THIS EXISTS FOR, observed twice on a real Ubuntu 22.04 host:
# jammy ships podman 3.4.4, which still uses CNI (netavark arrived in podman
# 4.x), and its `podman network create` writes `"cniVersion": "1.0.0"`. But
# jammy's containernetworking-plugins only support up to 0.4.0, so the
# `firewall` plugin rejects the file:
#
#   Error validating CNI config file .../aw-remote-host.conflist:
#     [plugin firewall does not support config version "1.0.0"]
#
# podman then behaves as though the network does not exist, and EVERY
# container start fails with `CNI network "aw-remote-host" not found` →
# `install failed: exit status 127`. The failure names the network, not the
# version mismatch, so it reads like the create silently did nothing.
#
# WHY THIS IS UNCONDITIONAL rather than "repair only if the network looks
# broken": the first version of this fix guarded on `podman network inspect`
# succeeding, reasoning that a usable network needs no repair. That guard
# made the whole thing a no-op, because **inspect reads the conflist without
# validating it against the installed plugins** — it happily returns the
# rejected network. The mismatch only ever surfaces at container-start time,
# far too late to react to. So there is no cheap runtime probe to gate on;
# the podman major version IS the signal.
#
# Scoped by version rather than by filename because the default `podman`
# network's conflist has the same problem, and a container attached to any
# rejected network fails the same way. On podman 4+ this loop finds nothing
# at all — netavark writes no conflists — so the version check is belt and
# braces rather than the only guard.
#
# 0.4.0 is safe: it is what the installed plugins speak, and nothing in a
# generated conflist uses a 1.0.0-only feature.
repair_cni_config_version() {
  local major
  major="$(podman_major)"
  case "$major" in
    '' | *[!0-9]*) return 0 ;;   # unreadable version — do not guess
  esac
  [ "$major" -lt 4 ] || return 0

  local conf
  for conf in /etc/cni/net.d/*.conflist "${HOME}/.config/cni/net.d/"*.conflist; do
    [ -f "$conf" ] || continue
    grep -q '"cniVersion"[[:space:]]*:[[:space:]]*"1\.0\.0"' "$conf" || continue
    if sed -i 's/"cniVersion"[[:space:]]*:[[:space:]]*"1\.0\.0"/"cniVersion": "0.4.0"/' "$conf" 2>/dev/null; then
      echo "network: podman ${major}.x wrote a CNI config its own plugins reject — downgraded cniVersion 1.0.0 -> 0.4.0 in $conf"
    fi
  done
}

# ensure_network creates the network if absent, then repairs the CNI config
# version. The repair runs AFTER the create on purpose: `network create` is
# what writes the offending 1.0.0, so repairing first would fix nothing.
ensure_network() {
  local name="$1"

  podman network exists "$name" >/dev/null 2>&1 || podman network create "$name" >/dev/null
  repair_cni_config_version
}
