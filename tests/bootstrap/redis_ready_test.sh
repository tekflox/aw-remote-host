#!/usr/bin/env bash
# Tests bootstrap/lib/redis_ready.sh — no real redis, no podman.
#
# THE INCIDENT (twice on 2026-09-11): a redis replaying its append-only file
# answers PING with "LOADING Redis is loading the dataset in memory" AND
# redis-cli exits 0. install.sh checked only the exit status, so it announced
# "redis: ready" mid-load; verify.sh ran straight after, got LOADING instead
# of PONG, and failed the module — stopping the chain before postgres and the
# workspace ever ran. Both halves are the same mistake: reading "the server
# answered" as "the server is ready".
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/redis_ready.sh
source "$DIR/../../bootstrap/lib/redis_ready.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n  	%s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "redis_ready.sh"

# Replace the two things that would touch the outside world.
#
# The call counter lives in a FILE, not a variable: redis_ping is invoked
# through $( ), which runs it in a subshell, so any counter it bumps in memory
# dies with that subshell. (Cost this test two wrong failures before the stub
# was the thing at fault rather than the code.)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
REPLIES=()
reset_probe() { : > "$TMP/calls"; }
probes() { wc -l < "$TMP/calls" | tr -d ' '; }
podman() {
  echo x >> "$TMP/calls"
  local n; n=$(( $(wc -l < "$TMP/calls") - 1 ))
  local last=$(( ${#REPLIES[@]} - 1 ))
  [ "$n" -gt "$last" ] && n="$last"
  printf '%s' "${REPLIES[$n]}"
}
sleep() { :; }   # the wait is the behaviour under test, not the delay

REPLIES=("PONG"); reset_probe
redis_wait_ready fake 5 >/dev/null 2>&1
check "a real PONG is ready immediately" "0" "$?"
check "and costs exactly one probe" "1" "$(probes)"

# THE REGRESSION. Exit status alone would have called this ready on probe 1.
REPLIES=("LOADING Redis is loading the dataset in memory"
         "LOADING Redis is loading the dataset in memory"
         "PONG")
reset_probe
redis_wait_ready fake 10 >/dev/null 2>&1
check "LOADING is waited out, not accepted as ready" "0" "$?"
check "and it kept probing until the real PONG" "3" "$(probes)"

REPLIES=("LOADING Redis is loading the dataset in memory"); reset_probe
redis_wait_ready fake 3 >/dev/null 2>&1
check "a redis that never finishes loading fails" "1" "$?"
check "after exactly the attempts it was given" "3" "$(probes)"

# A container that cannot be reached at all is not "ready" either — the empty
# reply must not slip through whatever comparison is used.
REPLIES=(""); reset_probe
redis_wait_ready fake 2 >/dev/null 2>&1
check "no answer at all is not ready" "1" "$?"

REPLIES=("ERR something else"); reset_probe
redis_wait_ready fake 2 >/dev/null 2>&1
check "an unexpected reply is not ready" "1" "$?"

# The LOADING line is the only thing that explains a stalled bootstrap, and
# announcing it on every probe would bury the log instead.
REPLIES=("LOADING x" "LOADING x" "LOADING x" "PONG"); reset_probe
out="$(redis_wait_ready fake 10 2>&1)"
check "the wait is explained once, not per probe" "1" "$(printf '%s\n' "$out" | grep -c 'loading its dataset')"

echo
echo "redis_aof_corrupted / redis_repair_aof (2026-09-28 aw-hosted-crispal AOF-corruption loop)"

# A different podman stub than the PING-probe one above: these calls are
# `podman logs` and `podman rm`, not `podman exec ... PING`, so they get
# their own fake rather than overloading the REPLIES/probes counter.
LOG_OUTPUT=""
RM_CALLS=0
podman() {
  case "$1" in
    logs) printf '%s' "$LOG_OUTPUT" ;;
    rm) RM_CALLS=$((RM_CALLS + 1)) ;;
  esac
}

LOG_OUTPUT="1:M 28 Sep 2026 20:26:48.203 * DB loaded from base file appendonly.aof.27.base.rdb: 0.001 seconds
1:M 28 Sep 2026 20:26:48.258 # Bad file format reading the append only file appendonly.aof.27.incr.aof: make a backup of your AOF file, then use ./redis-check-aof --fix <filename.manifest>"
if redis_aof_corrupted fake; then ok "the known AOF-corruption log line is detected"; else bad "the known AOF-corruption log line is detected" "not detected"; fi

LOG_OUTPUT="1:M 28 Sep 2026 20:26:48.203 * Ready to accept connections"
if redis_aof_corrupted fake; then bad "an unrelated log is not mistaken for AOF corruption" "false positive"; else ok "an unrelated log is not mistaken for AOF corruption"; fi

# redis_repair_aof does real filesystem moves (no podman stub needed beyond
# the `rm` above) — a real tmpdir stands in for $DATA_DIR.
REPAIR_DATA_DIR="$TMP/redis-data"
mkdir -p "$REPAIR_DATA_DIR/appendonlydir"
: > "$REPAIR_DATA_DIR/appendonlydir/appendonly.aof.27.incr.aof"
RM_CALLS=0
redis_repair_aof fake "$REPAIR_DATA_DIR" >/dev/null 2>&1
check "repair discards the dead container" "1" "$RM_CALLS"
check "repair moves the whole appendonlydir aside, not just the corrupt file" "1" \
  "$([ ! -d "$REPAIR_DATA_DIR/appendonlydir" ] && echo 1 || echo 0)"
moved_dir="$(find "$REPAIR_DATA_DIR" -maxdepth 1 -name 'appendonlydir.corrupt-*')"
check "the moved-aside dir keeps the original AOF data" "1" \
  "$([ -n "$moved_dir" ] && [ -f "$moved_dir/appendonly.aof.27.incr.aof" ] && echo 1 || echo 0)"

# A repair with nothing to move (e.g. a second call, or a fresh data dir)
# must not crash under set -uo pipefail — it's a no-op, not an error.
EMPTY_DATA_DIR="$TMP/redis-data-empty"
mkdir -p "$EMPTY_DATA_DIR"
redis_repair_aof fake "$EMPTY_DATA_DIR" >/dev/null 2>&1
check "repair with no appendonlydir present does not fail" "0" "$?"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
