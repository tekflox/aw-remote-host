#!/usr/bin/env bash
# One definition of "is redis actually ready", shared by redis/install.sh and
# redis/verify.sh.
#
# THE INCIDENT THIS EXISTS TO PREVENT (hit twice: 2026-09-11 morning and
# afternoon, both times taking down a bootstrap that was otherwise fine).
# A redis that is replaying its append-only file answers PING with
#     LOADING Redis is loading the dataset in memory
# and `redis-cli` EXITS 0 while doing it. install.sh's readiness loop only
# checked the exit status, so it declared "redis: ready" the moment the
# container accepted a connection — while the dataset was still loading — and
# verify.sh, running immediately after, got LOADING instead of PONG and failed
# the whole module. The module chain stops there, so postgres and the
# workspace never got their turn.
#
# Both halves of that bug are one mistake: treating "the server answered" as
# "the server is ready". LOADING is neither ready nor broken, it is NOT YET,
# and the only correct response to it is to wait. That it appeared right after
# a recreate is not a coincidence — a recreate is exactly when there is a
# dataset on disk to replay, i.e. when the data we were careful to preserve is
# being read back.
#
# Kept in lib/ for the reason bootstrap/lib/container.sh's header spells out:
# when install.sh and verify.sh judge the same condition by two separate
# copies of the logic, they drift, and a drifted pair either fails forever or
# recreates a healthy container on every boot.
#
# Not meant to be executed directly — only sourced.

# redis_ping <container>
#
# Prints redis's reply to PING, or nothing if the container could not be
# reached at all. Never fails the caller under `set -e`.
redis_ping() {
  podman exec "$1" redis-cli PING 2>/dev/null || true
}

# redis_wait_ready <container> [attempts]
#
# Waits for a real PONG. Returns 0 on PONG, 1 if it never arrives.
#
# LOADING is reported while waiting rather than swallowed: on a large dataset
# this is the only line that explains why bootstrap is sitting still, and its
# absence is what made the original failure look like a redis that was simply
# broken.
redis_wait_ready() {
  local container="$1" attempts="${2:-60}" reply="" announced=0
  local i
  for ((i = 0; i < attempts; i++)); do
    reply="$(redis_ping "$container")"
    case "$reply" in
      PONG) return 0 ;;
      LOADING*)
        if [ "$announced" = "0" ]; then
          echo "redis: loading its dataset from disk — waiting (this is the data surviving a recreate)"
          announced=1
        fi
        ;;
    esac
    sleep 1
  done
  echo "redis: never answered PONG (last reply: ${reply:-<no answer>})" >&2
  return 1
}

# redis_aof_corrupted <container>
#
# True when <container>'s own log shows the exact string Redis prints for a
# corrupted append-only file. Confirmed live on aw-hosted-crispal
# (2026-09-28): a redis whose incr AOF file is unreadable crashes ~100ms
# after accepting the base RDB on every restart, and since install.sh's own
# self-heal recreates the container against the SAME bind-mounted data, it
# crashed again every ~5 minutes forever — see redis_repair_aof for the fix.
redis_aof_corrupted() {
  local container="$1"
  podman logs --tail 50 "$container" 2>&1 | grep -q 'Bad file format reading the append only file'
}

# redis_repair_aof <container> <data_dir>
#
# ONE bounded repair attempt for a redis stuck in the corrupted-AOF crash
# loop redis_aof_corrupted detects: discards the dead container and moves
# the WHOLE appendonlydir aside (not just the offending incr file — Redis
# 7's multi-part AOF manifest would otherwise point at a file that no
# longer exists and fail differently, not more gracefully) so the caller's
# own create step starts clean. This redis is documented (see install.sh)
# as an internal status/reconciliation cache, not user data, so discarding
# it is an acceptable, fully-unattended-safe recovery — the simpler
# equivalent of the manual `redis-check-aof --fix` recovery this replaces.
#
# Does not retry itself and does not re-create the container — the caller
# re-runs its own `podman run`, and if THAT still fails, the failure must
# surface normally (exit 1) instead of looping here too.
redis_repair_aof() {
  local container="$1" data_dir="$2"
  local corrupt_dir
  corrupt_dir="${data_dir}/appendonlydir.corrupt-$(date +%s)"
  echo "redis: corrupted AOF detected in $container's log — discarding the container and moving $data_dir/appendonlydir aside"
  podman rm -f "$container" >/dev/null 2>&1 || true
  if [ -d "$data_dir/appendonlydir" ]; then
    mv "$data_dir/appendonlydir" "$corrupt_dir"
    echo "redis: moved appendonlydir aside to $corrupt_dir"
  else
    echo "redis: no appendonlydir present at $data_dir — nothing to move"
  fi
}
