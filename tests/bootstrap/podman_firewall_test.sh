#!/usr/bin/env bash
# Tests bootstrap/lib/podman_firewall.sh's containers.conf rewrite in
# isolation — no real podman, no root needed (the id -u == 0 gate lives in
# the caller, bootstrap/podman/install.sh, on purpose — see that file's
# comment).
#
# Run: tests/bootstrap/podman_firewall_test.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# shellcheck source=../../bootstrap/lib/podman_firewall.sh
source "$REPO_DIR/bootstrap/lib/podman_firewall.sh"

fail=0
expect() {
  local what="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    echo "ok   - $what"
  else
    echo "FAIL - $what: got [$got], want [$want]" >&2
    fail=1
  fi
}

CONF="$TMP/etc/containers/containers.conf"

configure_podman_firewall_driver "$CONF" >/dev/null
expect "writes the conf file" "1" "$([ -f "$CONF" ] && echo 1 || echo 0)"
expect "pins firewall_driver to iptables" \
  "firewall_driver = \"iptables\"" "$(grep 'firewall_driver' "$CONF")"

# A pre-existing conf with a different (or absent) driver must be corrected,
# not left alone — this is the exact case that let netavark's nftables
# backend hit the host's kernel fib-support bug on 2026-09-08.
cat > "$CONF" <<'EOF'
[network]
firewall_driver = "nftables"
EOF
configure_podman_firewall_driver "$CONF" >/dev/null
expect "overwrites a conf pinned to nftables" \
  "firewall_driver = \"iptables\"" "$(grep 'firewall_driver' "$CONF")"
expect "old nftables value is gone" "0" "$(grep -c 'nftables' "$CONF")"

# Idempotent — must not error or duplicate content on a second run against
# an already-correct conf (install.sh calls this on every bootstrap).
BEFORE="$(cat "$CONF")"
configure_podman_firewall_driver "$CONF" >/dev/null
configure_podman_firewall_driver "$CONF" >/dev/null
AFTER="$(cat "$CONF")"
expect "re-running is idempotent" "$BEFORE" "$AFTER"

exit "$fail"
