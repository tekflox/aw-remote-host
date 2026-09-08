#!/usr/bin/env bash
# Shared helper for pinning nested ROOTFUL podman's netavark firewall
# backend to iptables. Sourced by bootstrap/podman/install.sh.
#
# THE INCIDENT THIS EXISTS TO PREVENT (confirmed live 2026-09-08, during the
# podman 4.3.1 -> 5.4.2 / trixie rebase on aw-remote-host): netavark 1.14.0-2
# — the version trixie ships — hits a known nftables bug: the host kernel is
# missing `fib` lookup support in the `inet` table, same class as
# containers/netavark#1411. Every container network on this host failed to
# come up on the freshly-recreated container, taking podman/postgres/redis/
# workspace down with it.
#
# The fix applied live was setting `firewall_driver = "iptables"` in
# `/etc/containers/containers.conf` — netavark falls back to the older,
# unaffected iptables backend instead of nftables. That file is not tracked
# anywhere and does not survive the next container recreation, so this
# repeats the graphroot problem podman_storage.sh already solves: same file
# family, same fix shape, same rootful-only host.
#
# ORDERING MATTERS AS MUCH AS THE VALUE (confirmed live the same day):
# `podman system service` — the daemon bootstrap/lib/podman_socket.sh starts,
# which serves the Marketplace / warm-container-pool Docker-compat API — reads
# containers.conf once at startup and never again. A CLI invocation of podman
# rereads the file every time, so `podman start`/`podman run` picked up a
# post-hoc fix immediately while the already-running daemon kept using the
# old (broken) firewall driver until it was killed and restarted by hand.
# bootstrap/podman/install.sh calls this BEFORE it sources podman_socket.sh,
# so the daemon never starts against the old config in the first place.
#
# A rootless install (the common BYOD case) is not known to hit this — it
# isn't nested inside another container's writable layer, and isn't
# necessarily running the trixie base this bug was found on. Kept OUT of the
# function itself, same as podman_storage.sh's graphroot gate, so it stays
# pure and testable without mocking `id`.
#
# Not meant to be executed directly — only sourced.

# configure_podman_firewall_driver <conf_file>
#
# Idempotently ensures <conf_file> (podman's containers.conf) sets
# [network] firewall_driver = "iptables". Safe to call on every bootstrap —
# a no-op once the conf already says what this function would write.
configure_podman_firewall_driver() {
  local conf_file="$1"
  mkdir -p "$(dirname "$conf_file")"
  if [ -f "$conf_file" ] && grep -q 'firewall_driver = "iptables"' "$conf_file" 2>/dev/null; then
    return 0
  fi
  # Nothing else on this host's rootful path writes to $conf_file (the
  # macOS-only [machine] provider write in bootstrap/podman/install.sh
  # targets a different, rootless-only path), so replacing it wholesale is
  # safe and matches podman_storage.sh's own graphroot rewrite.
  cat > "$conf_file" <<'EOF'
[network]
firewall_driver = "iptables"
EOF
  echo "podman: firewall_driver pinned to iptables in $conf_file (netavark's nftables backend hits a known kernel fib-support bug on this host — see bootstrap/lib/podman_firewall.sh)"
}
