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
