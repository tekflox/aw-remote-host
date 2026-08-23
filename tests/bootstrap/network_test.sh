#!/usr/bin/env bash
# Tests bootstrap/lib/network.sh's CNI repair against a stubbed podman.
#
# This exists because the FIRST version of that repair shipped as a silent
# no-op: it only ran when `podman network inspect` failed, and inspect reads
# a conflist without validating it against the installed plugins, so it
# succeeds on exactly the broken config the repair was written for. The bug
# looked fixed, released, and failed identically on the next provision.
#
# A stub podman is enough to test this: the only thing the repair asks the
# real podman is its version.
#
# Run: tests/bootstrap/network_test.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/home/.config/cni/net.d"
cat > "$TMP/bin/podman" <<'STUB'
#!/bin/sh
[ "$1" = "--version" ] && { echo "podman version $FAKE_PODMAN_VERSION"; exit 0; }
exit 0
STUB
chmod +x "$TMP/bin/podman"

export PATH="$TMP/bin:$PATH"
export HOME="$TMP/home"

# shellcheck source=../bootstrap/lib/network.sh
source "$REPO_DIR/bootstrap/lib/network.sh"

fail=0
write_conflist() {
  printf '{\n   "cniVersion": "1.0.0",\n   "name": "%s"\n}\n' "$1" \
    > "$HOME/.config/cni/net.d/$1.conflist"
}
version_of() { grep -o '"cniVersion": "[^"]*"' "$HOME/.config/cni/net.d/$1.conflist"; }
expect() {
  local what="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    echo "ok   - $what"
  else
    echo "FAIL - $what: got [$got], want [$want]" >&2
    fail=1
  fi
}

# podman 3.x is the whole point: it writes 1.0.0 and cannot read it back.
export FAKE_PODMAN_VERSION=3.4.4
write_conflist aw-remote-host
write_conflist podman
repair_cni_config_version >/dev/null
expect "podman 3.x repairs our network" '"cniVersion": "0.4.0"' "$(version_of aw-remote-host)"
# The default network matters too — a container attached to any rejected
# network fails the same way, which is why this is not scoped by filename.
expect "podman 3.x repairs the default network" '"cniVersion": "0.4.0"' "$(version_of podman)"

# netavark hosts write no conflists at all, so this should be inert. If one
# is present anyway (an upgraded host), leaving it alone is correct.
export FAKE_PODMAN_VERSION=4.9.4
write_conflist aw-remote-host
repair_cni_config_version >/dev/null
expect "podman 4.x leaves configs alone" '"cniVersion": "1.0.0"' "$(version_of aw-remote-host)"

# An unreadable version must not be guessed at in either direction.
export FAKE_PODMAN_VERSION=""
write_conflist aw-remote-host
repair_cni_config_version >/dev/null
expect "unknown podman version changes nothing" '"cniVersion": "1.0.0"' "$(version_of aw-remote-host)"

# Re-running must be safe — every module's install.sh calls ensure_network.
export FAKE_PODMAN_VERSION=3.4.4
write_conflist aw-remote-host
repair_cni_config_version >/dev/null
repair_cni_config_version >/dev/null
expect "repair is idempotent" '"cniVersion": "0.4.0"' "$(version_of aw-remote-host)"

exit "$fail"
