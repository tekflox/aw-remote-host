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

# A stub findmnt lets tests pick the underlying filesystem type deterministically
# instead of depending on whatever $TMP happens to sit on in whatever environment
# runs this suite (e.g. a GHA runner whose own /tmp is already overlayfs would
# otherwise silently flip every "normal disk" test below onto the nested path).
mkdir -p "$TMP/bin"
cat > "$TMP/bin/findmnt" <<'STUB'
#!/bin/sh
echo "${FAKE_FSTYPE:-ext4}"
STUB
chmod +x "$TMP/bin/findmnt"
export PATH="$TMP/bin:$PATH"
export FAKE_FSTYPE=ext4

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
expect "driver stays overlay on a normal disk" \
  "driver = \"overlay\"" "$(grep 'driver' "$CONF")"
expect "no mount_program on a normal disk — native overlay is faster and works fine" \
  "0" "$(grep -c 'mount_program' "$CONF")"

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

# The regression this test exists for: a graphroot rooted on a filesystem
# that is ITSELF already overlayfs (aw-remote-host's own docker-compose
# simulator's situation — see bootstrap/lib/podman_storage.sh) must get a
# mount_program, not the plain native "overlay" driver, which fails hard
# with "'overlay' is not supported over overlayfs, a mount_program is
# required" (bug:aw-automation-byod-smoke-workspace-provisioning-timeout,
# GHA run 35860295745).
OVERLAY_CONF="$TMP/etc/containers/storage-overlayfs.conf"
OVERLAY_HOME="$TMP/home/nested"
export FAKE_FSTYPE=overlay
configure_podman_graphroot "$OVERLAY_CONF" "$OVERLAY_HOME" >/dev/null
expect "graphroot over overlayfs still uses the overlay driver" \
  "driver = \"overlay\"" "$(grep 'driver' "$OVERLAY_CONF")"
expect "graphroot over overlayfs gets a mount_program instead of falling back to vfs" \
  "mount_program = \"$PODMAN_MOUNT_PROGRAM\"" "$(grep 'mount_program' "$OVERLAY_CONF")"

# Idempotent in the nested-overlayfs case too.
BEFORE_OVERLAY="$(cat "$OVERLAY_CONF")"
configure_podman_graphroot "$OVERLAY_CONF" "$OVERLAY_HOME" >/dev/null
expect "overlayfs case is idempotent" "$BEFORE_OVERLAY" "$(cat "$OVERLAY_CONF")"

# A conf previously written with driver=overlay and no mount_program on a
# host that is actually overlayfs (exactly what 861f4aa's own fixed version
# produced before the vfs fallback — and what a host bootstrapped between
# these two versions has right now) must be REPAIRED, not left on vfs and
# not left silently missing mount_program.
cat > "$OVERLAY_CONF" <<EOF
[storage]
driver = "overlay"
runroot = "$PODMAN_RUNROOT"
graphroot = "$OVERLAY_HOME/.local/share/containers/storage"
EOF
configure_podman_graphroot "$OVERLAY_CONF" "$OVERLAY_HOME" >/dev/null
expect "repairs a pre-mount_program conf on an overlayfs host" \
  "mount_program = \"$PODMAN_MOUNT_PROGRAM\"" "$(grep 'mount_program' "$OVERLAY_CONF")"

# ...and the vfs-fallback conf 861f4aa's first version would have written
# must also be repaired forward to overlay+mount_program, not left on vfs.
cat > "$OVERLAY_CONF" <<EOF
[storage]
driver = "vfs"
runroot = "$PODMAN_RUNROOT"
graphroot = "$OVERLAY_HOME/.local/share/containers/storage"
EOF
configure_podman_graphroot "$OVERLAY_CONF" "$OVERLAY_HOME" >/dev/null
expect "repairs a vfs-fallback conf on an overlayfs host back to overlay" \
  "driver = \"overlay\"" "$(grep 'driver' "$OVERLAY_CONF")"
expect "...with a mount_program, not bare overlay" \
  "mount_program = \"$PODMAN_MOUNT_PROGRAM\"" "$(grep 'mount_program' "$OVERLAY_CONF")"

exit "$fail"
