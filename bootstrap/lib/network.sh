#!/usr/bin/env bash
# Shared helper for creating the user-defined podman network every module
# attaches its container to, plus the CNI repair that a podman 3.x host needs
# before that network is usable at all.
#
# Sourced by bootstrap/{postgres,redis,workspace}/install.sh — all three used
# to inline the same `podman network exists || podman network create`, and all
# three were equally broken by the problem below.

# ensure_network creates the network if absent, then repairs the CNI config
# version when this host needs it.
#
# THE BUG THIS EXISTS FOR, observed on a real Ubuntu 22.04 host:
# jammy ships podman 3.4.4, which still uses CNI (netavark arrived in podman
# 4.x), and its `podman network create` writes `"cniVersion": "1.0.0"` into
# /etc/cni/net.d/<name>.conflist. But jammy's containernetworking-plugins
# only support up to 0.4.0, so the `firewall` plugin rejects the file:
#
#   Error validating CNI config file .../aw-remote-host.conflist:
#     [plugin firewall does not support config version "1.0.0"]
#
# podman then behaves as though the network does not exist, and EVERY
# container start fails with `CNI network "aw-remote-host" not found` →
# `install failed: exit status 127`. The failure names the network, not the
# version mismatch, so it reads like the create silently did nothing.
#
# manifest.json asks for podman 4.x precisely to avoid CNI, but a distro that
# packages 3.x is exactly the case `4.x (distro-packaged)` cannot guarantee.
# Rewriting the version is safe: 0.4.0 is what the installed plugins speak,
# and nothing in the generated conflist uses a 1.0.0-only feature.
#
# Deliberately narrow: only touches files that declare 1.0.0, only when the
# plugins are too old to accept it, and never on a netavark host (podman 4+
# writes no conflist at all, so the loop simply finds nothing).
ensure_network() {
  local name="$1"

  podman network exists "$name" >/dev/null 2>&1 || podman network create "$name" >/dev/null

  # If the network is already usable, there is nothing to repair. This is the
  # netavark path and the already-patched path both.
  if podman network inspect "$name" >/dev/null 2>&1; then
    return 0
  fi

  local repaired=0
  local conf
  for conf in /etc/cni/net.d/*.conflist "${HOME}/.config/cni/net.d/"*.conflist; do
    [ -f "$conf" ] || continue
    grep -q '"cniVersion"[[:space:]]*:[[:space:]]*"1\.0\.0"' "$conf" || continue
    if sed -i 's/"cniVersion"[[:space:]]*:[[:space:]]*"1\.0\.0"/"cniVersion": "0.4.0"/' "$conf" 2>/dev/null; then
      echo "network: downgraded cniVersion 1.0.0 -> 0.4.0 in $conf (podman $(podman --version 2>/dev/null | awk '{print $3}') ships CNI configs its own plugins reject)"
      repaired=1
    fi
  done

  if [ "$repaired" = "1" ]; then
    # The network may have been created before the repair, in which case its
    # conflist is now valid and podman can see it. Re-create only if it still
    # cannot.
    podman network inspect "$name" >/dev/null 2>&1 || \
      podman network create "$name" >/dev/null 2>&1 || true
  fi

  if ! podman network inspect "$name" >/dev/null 2>&1; then
    echo "network: '$name' still not usable after CNI repair — containers will fail to start." >&2
    echo "network: check 'podman network ls' and /etc/cni/net.d/*.conflist by hand." >&2
    return 1
  fi
}
