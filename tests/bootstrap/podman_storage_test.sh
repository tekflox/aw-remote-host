#!/usr/bin/env bash
# Tests bootstrap/lib/podman_storage.sh's graphroot rewrite in isolation —
# no real podman, no root needed (the id -u == 0 gate lives in the caller,
# bootstrap/podman/install.sh, on purpose — see that file's comment).
#
# Run: tests/bootstrap/podman_storage_test.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# shellcheck source=../../bootstrap/lib/podman_storage.sh
source "$REPO_DIR/bootstrap/lib/podman_storage.sh"

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

CONF="$TMP/etc/containers/storage.conf"
HOME_DIR="$TMP/home/aw-remote-host"
EXPECTED_ROOT="$HOME_DIR/.local/share/containers/storage"

configure_podman_graphroot "$CONF" "$HOME_DIR" >/dev/null
expect "writes the conf file" "1" "$([ -f "$CONF" ] && echo 1 || echo 0)"
expect "graphroot points under \$HOME, not /var/lib/containers" \
  "graphroot = \"$EXPECTED_ROOT\"" "$(grep 'graphroot' "$CONF")"
expect "creates the storage dir itself" "1" "$([ -d "$EXPECTED_ROOT" ] && echo 1 || echo 0)"

# A different, pre-existing conf (simulating the podman package's own
# default) must be REPLACED, not merged around — a leftover
# graphroot = "/var/lib/containers/storage" line would still send podman to
# the ephemeral location.
cat > "$CONF" <<'EOF'
[storage]
driver = "overlay"
graphroot = "/var/lib/containers/storage"
EOF
configure_podman_graphroot "$CONF" "$HOME_DIR" >/dev/null
expect "overwrites a pre-existing package-default conf" \
  "graphroot = \"$EXPECTED_ROOT\"" "$(grep 'graphroot' "$CONF")"
expect "old default graphroot is gone" "0" "$(grep -c '/var/lib/containers/storage' "$CONF")"

# Idempotent — must not error or duplicate content on a second run against
# an already-correct conf (every module's install.sh can call this).
BEFORE="$(cat "$CONF")"
configure_podman_graphroot "$CONF" "$HOME_DIR" >/dev/null
configure_podman_graphroot "$CONF" "$HOME_DIR" >/dev/null
AFTER="$(cat "$CONF")"
expect "re-running is idempotent" "$BEFORE" "$AFTER"

# A different HOME (a different host, or a test) must land in a different,
# still-under-that-HOME graphroot — not a hardcoded path.
OTHER_HOME="$TMP/home/someone-else"
OTHER_CONF="$TMP/etc/containers/storage-other.conf"
configure_podman_graphroot "$OTHER_CONF" "$OTHER_HOME" >/dev/null
expect "graphroot follows \$HOME, not hardcoded" \
  "graphroot = \"$OTHER_HOME/.local/share/containers/storage\"" \
  "$(grep 'graphroot' "$OTHER_CONF")"

# runroot must be written as well. Podman refuses to start at all against a
# storage.conf that omits it ("runroot must be set"), so a graphroot-only conf
# installs podman and bricks it in the same step.
expect "writes runroot" \
  "runroot = \"/run/containers/storage\"" "$(grep 'runroot' "$CONF")"

# ...and it must NOT be under $HOME: runroot is per-boot runtime state (locks,
# active mounts). Persisted on the volume it would outlive a container recreate
# as stale locks pointing at mounts that no longer exist.
expect "runroot is not under \$HOME" "0" "$(grep -c "runroot = \"$HOME_DIR" "$CONF")"

# The repair case: a host bootstrapped by the graphroot-only version already
# has the CORRECT graphroot, so a guard that only checked graphroot would
# return early and leave podman permanently unable to start. This is the exact
# conf that broke the aw workspace host on 2026-09-05.
cat > "$CONF" <<EOF
[storage]
driver = "overlay"
graphroot = "$EXPECTED_ROOT"
EOF
configure_podman_graphroot "$CONF" "$HOME_DIR" >/dev/null
expect "repairs a graphroot-only conf left by the previous version" \
  "runroot = \"/run/containers/storage\"" "$(grep 'runroot' "$CONF")"
expect "repair keeps the graphroot it already had" \
  "graphroot = \"$EXPECTED_ROOT\"" "$(grep 'graphroot' "$CONF")"

exit "$fail"
