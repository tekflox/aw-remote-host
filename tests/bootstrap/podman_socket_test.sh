#!/usr/bin/env bash
# Tests bootstrap/lib/podman_socket.sh's liveness probe — no real podman.
#
# THE INCIDENT (2026-09-11): the aw-remote-host container was restarted. /run
# is part of its writable layer, so the socket FILE survived while the
# `podman system service` holding it did not. Every check in the chain asked
# whether the file existed, so bootstrap printed "podman: API socket ready"
# over a dead socket, the workspace container was rebuilt with that dead inode
# bind-mounted in, and every Tier-2 app it managed failed with "Cannot connect
# to the Docker daemon" while the workspace's own component listing 500'd.
# Nothing reported a problem. `[ -S ]` answers a different question than the
# one every caller is asking.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n  	%s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "podman_socket.sh"

# shellcheck source=../../bootstrap/lib/podman_socket.sh
source "$DIR/../../bootstrap/lib/podman_socket.sh"

SOCK="$TMP/podman.sock"
# A real unix socket file, with nothing listening — exactly what a restarted
# container leaves behind. python is the portable way to create one.
python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])
" "$SOCK"
check "the test really made a socket file" "1" "$([ -S "$SOCK" ] && echo 1 || echo 0)"

# Stub podman: ANSWERING is the variable under test.
PODMAN_ANSWERS=0
podman() { [ "$PODMAN_ANSWERS" = "1" ]; }

PODMAN_ANSWERS=0
podman_socket_alive "$SOCK"
check "a socket file nothing answers on is NOT alive" "1" "$?"

PODMAN_ANSWERS=1
podman_socket_alive "$SOCK"
check "a socket something answers on is alive" "0" "$?"

# The file has to exist too — "podman answers" about a path with no socket is
# not a thing, and skipping the file check would make every missing socket
# look live on a host whose podman happens to reply.
PODMAN_ANSWERS=1
podman_socket_alive "$TMP/nao-existe.sock"
check "a path with no socket file is not alive" "1" "$?"

# And the stale file must be cleared out of the way, or the bring-up below it
# no-ops forever on a host that can never recover on its own.
PODMAN_ANSWERS=0
_systemd_is_init() { return 1; }
_start_socket_directly() { echo "START CALLED" >&2; return 1; }
podman_socket_default_path() { printf '%s' "$SOCK"; }
out="$(ensure_podman_socket 2>&1)"
check "a dead socket does not report success" "1" "$?"
check "the bring-up was actually attempted" "1" "$(printf '%s' "$out" | grep -c 'START CALLED')"
check "and the stale socket file was removed" "0" "$([ -S "$SOCK" ] && echo 1 || echo 0)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
