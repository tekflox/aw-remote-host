#!/usr/bin/env bash
# Tests for bootstrap/lib/container.sh. Run directly: bash container_test.sh
#
# Driven by the incident this exists to prevent (2026-09-02): postgres and
# redis verify.sh only checked pg_isready/PING, never WHICH volume was
# mounted, so a container silently left on an emptied-out legacy volume
# read as "healthy" forever and install.sh's own legacy-storage recreate
# branch (b49fbb8) never got a chance to run. See bootstrap/lib/container.sh
# for the shared resolver this test exercises — install.sh and verify.sh
# MUST agree on the expected path, or every bootstrap recreates a perfectly
# healthy container instead (a different, equally real outage).
set -uo pipefail

# Deliberately OUTSIDE bootstrap/: everything under that tree is embedded
# into the binary and extracted onto every user's machine by ExtractScripts,
# and a test file has no business shipping to a BYOD host.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/container.sh
source "$DIR/../../bootstrap/lib/container.sh"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n  	%s\n' "$1" "$2"; }
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi
}

echo "container.sh"

# Stub podman entirely — the only thing container.sh asks it is `inspect`,
# and nothing about this test should touch a real container runtime.
FAKE_INSPECT_OUTPUT=""
FAKE_INSPECT_FAIL=0
podman() {
  if [ "$1" = "inspect" ]; then
    [ "$FAKE_INSPECT_FAIL" = "1" ] && return 1
    printf '%s' "$FAKE_INSPECT_OUTPUT"
    return 0
  fi
  echo "podman: unstubbed subcommand invoked by test: $*" >&2
  return 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP/home"
mkdir -p "$HOME"

# --- correct mount passes -----------------------------------------------
unset AW_POSTGRES_HOST_DIR 2>/dev/null || true
expected="$(resolve_data_dir AW_POSTGRES_HOST_DIR postgres-data)"
check "resolve_data_dir defaults under \$HOME" "$HOME/postgres-data" "$expected"

FAKE_INSPECT_OUTPUT="$expected"
check "correct mount matches the resolved default data dir" \
  "$expected" "$(mount_source aw-remote-host-postgres /var/lib/postgresql/data)"

# --- wrong mount (named volume) fails ------------------------------------
FAKE_INSPECT_OUTPUT="/var/lib/containers/storage/volumes/aw-remote-host-postgres-data/_data"
actual="$(mount_source aw-remote-host-postgres /var/lib/postgresql/data)"
if [ "$actual" != "$expected" ]; then
  ok "a named-volume mount does not match the expected data dir"
else
  bad "a named-volume mount does not match the expected data dir" "both resolved to [$actual]"
fi

# --- the override env var is honoured identically on both call sites ----
# (install.sh and verify.sh each call resolve_data_dir independently — this
# locks in that calling it twice with the same env produces the same path,
# which is the entire point of sharing one resolver instead of two copies.)
export AW_POSTGRES_HOST_DIR="$TMP/custom-pg-data"
install_side="$(resolve_data_dir AW_POSTGRES_HOST_DIR postgres-data)"
verify_side="$(resolve_data_dir AW_POSTGRES_HOST_DIR postgres-data)"
check "override resolves identically across independent calls" "$install_side" "$verify_side"
check "override value itself is honoured, not just the default" "$TMP/custom-pg-data" "$install_side"
unset AW_POSTGRES_HOST_DIR

# --- podman-unreadable is treated as unknown, not a crash ----------------
FAKE_INSPECT_FAIL=1
mount_source aw-remote-host-postgres /var/lib/postgresql/data >/dev/null
rc=$?
check "unreadable podman does not crash the caller (set -e safe)" "0" "$rc"
out="$(mount_source aw-remote-host-postgres /var/lib/postgresql/data)"
check "unreadable podman yields no source (treated as wrong/unknown)" "" "$out"
FAKE_INSPECT_FAIL=0

# --- trailing slash is normalised, so a cosmetic difference alone never
#     trips the recreate path ---------------------------------------------
export AW_REDIS_HOST_DIR="$TMP/redis-data/"
expected_redis="$(resolve_data_dir AW_REDIS_HOST_DIR redis-data)"
check "a trailing slash in the override does not survive normalisation" \
  "$TMP/redis-data" "$expected_redis"
FAKE_INSPECT_OUTPUT="$TMP/redis-data"
check "a mount reported without the trailing slash still matches" \
  "$expected_redis" "$(mount_source aw-remote-host-redis /data)"
unset AW_REDIS_HOST_DIR

# --- symlinks are NOT resolved, by deliberate design ---------------------
# podman reports a bind mount's Source as the literal argument the
# container was created with — it does not resolve symlinks in it. If this
# resolver chased symlinks (e.g. via realpath) while podman's own report
# stayed literal, a symlinked $HOME would make verify.sh see a "different"
# path than the container was actually created with and recreate a
# perfectly healthy container on every single boot — the exact failure
# mode flagged as the biggest risk when this helper was written. Lock in
# that resolve_data_dir stays purely lexical.
symlinked_home="$TMP/home-via-symlink"
ln -s "$HOME" "$symlinked_home"
literal_path="$symlinked_home/postgres-data"
export AW_POSTGRES_HOST_DIR="$literal_path"
resolved="$(resolve_data_dir AW_POSTGRES_HOST_DIR postgres-data)"
check "resolve_data_dir does not chase a symlink in the override" "$literal_path" "$resolved"
FAKE_INSPECT_OUTPUT="$literal_path"
check "mount_source agrees when podman reports that same literal (symlinked) path" \
  "$resolved" "$(mount_source aw-remote-host-postgres /var/lib/postgresql/data)"
unset AW_POSTGRES_HOST_DIR

# ---------------------------------------------------------------------------
# container_is_live / start_or_discard
#
# The 2026-09-10 outage in one sentence: the outer container was recreated, so
# every nested container's process died, but podman's DB (on the surviving
# graphroot) still said "running" — and `podman start` on a container already
# recorded as running returns 0 WITHOUT STARTING ANYTHING. bootstrap therefore
# reported success over a host with nothing running on it.
# ---------------------------------------------------------------------------

# Re-stub podman for the lifecycle calls. Records what it was asked to do so a
# test can assert the container was actually discarded, not merely "handled".
FAKE_RUNNING="true"      # what .State.Running reports
FAKE_PID="0"             # what .State.Pid reports
PODMAN_CALLS=""
podman() {
  PODMAN_CALLS="$PODMAN_CALLS $1"
  case "$1" in
    inspect)
      case "$*" in
        *State.Running*) printf '%s' "$FAKE_RUNNING" ;;
        *State.Pid*)     printf '%s' "$FAKE_PID" ;;
      esac
      return 0 ;;
    start|stop|rm) return 0 ;;
    *) echo "podman: unstubbed subcommand invoked by test: $*" >&2; return 1 ;;
  esac
}
# The /proc probe is gated on rootful Linux. Force that branch on so the test
# exercises the real code path on any machine CI happens to run on.
uname() { echo Linux; }
id() { echo 0; }

FAKE_RUNNING="true"; FAKE_PID="$$"   # our own pid: guaranteed to be in /proc
PODMAN_CALLS=""
start_or_discard aw-test-c testmod >/dev/null 2>&1
check "a genuinely live container is kept" "0" "$?"
case "$PODMAN_CALLS" in *rm*) bad "a live container must not be removed" "saw rm in:$PODMAN_CALLS" ;; *) ok "a live container is not removed" ;; esac

# THE REGRESSION. podman says running, no such process. Before this fix the
# bare `podman start || true` returned 0 here and bootstrap carried on.
FAKE_RUNNING="true"; FAKE_PID="999999999"
PODMAN_CALLS=""
start_or_discard aw-test-c testmod >/dev/null 2>&1
check "a container podman calls running with a dead pid is discarded" "1" "$?"
case "$PODMAN_CALLS" in *rm*) ok "the dead-but-running container is removed so it gets rebuilt" ;; *) bad "stale container must be removed" "no rm in:$PODMAN_CALLS" ;; esac

# A pid podman cannot report at all is not alive either.
FAKE_RUNNING="true"; FAKE_PID="0"
start_or_discard aw-test-c testmod >/dev/null 2>&1
check "pid 0 is not alive" "1" "$?"

# An honest "not running" needs no /proc lookup to be believed.
FAKE_RUNNING="false"; FAKE_PID="$$"
start_or_discard aw-test-c testmod >/dev/null 2>&1
check "a container that fails to start is discarded" "1" "$?"

# Off rootful-Linux the /proc probe would be meaningless (the pid lives in
# another namespace or a VM), and a false negative there would discard a
# HEALTHY container on every bootstrap — worse than the bug being fixed.
# podman own report must be taken at face value.
uname() { echo Darwin; }
FAKE_RUNNING="true"; FAKE_PID="999999999"
PODMAN_CALLS=""
start_or_discard aw-test-c testmod >/dev/null 2>&1
check "off rootful-Linux, podman own report is trusted" "0" "$?"
case "$PODMAN_CALLS" in *rm*) bad "must not discard on a non-Linux host" "saw rm in:$PODMAN_CALLS" ;; *) ok "no discard on a non-Linux host" ;; esac
uname() { echo Linux; }

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
