#!/usr/bin/env bash
# Tests bootstrap/lib/postgres_ready.sh — no real postgres, no podman.
#
# THE INCIDENT (2026-09-12, the first clean "host with us" install): postgres
# install.sh waited on a bare `pg_isready` and broke out the moment it exited
# 0. The next command died with "FATAL: the database system is shutting down",
# set -e killed the module before CREATE DATABASE aw_workspace, and the
# workspace crash-looped on `database "aw_workspace" does not exist`.
#
# pg_isready was not wrong, it was answering a different question. During
# initdb the postgres entrypoint runs a TEMPORARY server with
# listen_addresses='' — reachable on the unix socket, never on TCP. A socket
# probe reports that server ready; a TCP probe cannot. So these tests pin the
# probe's SHAPE, not its outcome: drop the -h and the incident is back with
# every test still green if they only checked exit codes.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/postgres_ready.sh
source "$DIR/../../bootstrap/lib/postgres_ready.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n  \t%s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "postgres_ready.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# The stub records every invocation to a FILE (podman runs in subshells) and
# decides by SUB-COMMAND, so a probe that forgets -h is visible, not just a
# probe that fails.
#
# TCP_UP=no models the exact window the incident fell into: the unix socket
# answers (initdb's temporary server) while TCP does not.
SOCKET_UP=yes
TCP_UP=yes
DB_ROWS=""
podman() {
  printf '%s\n' "$*" >> "$TMP/calls"
  local args="$*"
  case "$args" in
    *pg_isready*)
      case "$args" in
        *"-h 127.0.0.1"*) [ "$TCP_UP" = yes ] ;;
        *)                [ "$SOCKET_UP" = yes ] ;;
      esac ;;
    *pg_database*)
      case "$args" in
        *"-h 127.0.0.1"*) [ "$TCP_UP" = yes ] || return 1 ;;
      esac
      printf '%s' "$DB_ROWS" ;;
    *psql*)
      case "$args" in
        *"-h 127.0.0.1"*) [ "$TCP_UP" = yes ] ;;
        *)                [ "$SOCKET_UP" = yes ] ;;
      esac ;;
    *) return 1 ;;
  esac
}
sleep() { :; }   # the wait is the behaviour under test, not the delay
reset() { : > "$TMP/calls"; }
probed_tcp() { grep -c -- '-h 127.0.0.1' "$TMP/calls" 2>/dev/null | tr -d ' '; }

# --- the incident, reproduced --------------------------------------------
SOCKET_UP=yes; TCP_UP=no; reset
postgres_ready pg
check "initdb's socket-only server is NOT ready" "1" "$?"

SOCKET_UP=yes; TCP_UP=no; reset
postgres_wait_ready pg 3
check "and waiting on it eventually gives up rather than lying" "1" "$?"

# --- the probe's shape, which is what actually fixed it -------------------
# Each probe is pinned SEPARATELY and on purpose. Asserting only "some call
# used -h" lets the pg_isready lose its -h while the psql below still
# satisfies the assertion — which is the original incident restored with a
# green suite. (Confirmed: that mutant survived until this test split in two.)
SOCKET_UP=yes; TCP_UP=yes; reset
postgres_ready pg >/dev/null 2>&1
if grep 'pg_isready' "$TMP/calls" | grep -q -- '-h 127.0.0.1'; then
  ok "pg_isready itself goes over TCP — a socket probe IS the incident"
else
  bad "pg_isready goes over TCP" "socket-only in [$(grep pg_isready "$TMP/calls")]"
fi

SOCKET_UP=yes; TCP_UP=yes; reset
postgres_ready pg >/dev/null 2>&1
if grep 'psql' "$TMP/calls" | grep -q -- '-h 127.0.0.1'; then
  ok "and so does the query that follows it"
else
  bad "the query goes over TCP" "socket-only in [$(grep psql "$TMP/calls")]"
fi

# --- the real server -----------------------------------------------------
SOCKET_UP=yes; TCP_UP=yes; reset
postgres_ready pg
check "a server accepting TCP is ready" "0" "$?"

SOCKET_UP=yes; TCP_UP=yes; reset
postgres_wait_ready pg 5
check "and waiting returns immediately" "0" "$?"

SOCKET_UP=no; TCP_UP=no; reset
postgres_ready pg
check "nothing up at all is not ready" "1" "$?"

# --- readiness must mean ready to TRANSACT, not just to connect ----------
SOCKET_UP=yes; TCP_UP=yes; reset
postgres_ready pg >/dev/null 2>&1
if grep -q 'psql' "$TMP/calls"; then
  ok "readiness runs a real query, not only a startup packet"
else
  bad "readiness runs a real query" "no psql in [$(cat "$TMP/calls")]"
fi

# --- the database check the missing verify let through -------------------
TCP_UP=yes; DB_ROWS="1"; reset
postgres_has_database pg aw_workspace
check "an existing database is found" "0" "$?"

TCP_UP=yes; DB_ROWS=""; reset
postgres_has_database pg aw_workspace
check "a MISSING database is reported missing — the whole incident" "1" "$?"

TCP_UP=yes; DB_ROWS=""; reset
postgres_has_database pg aw_workspace >/dev/null 2>&1
if [ "$(probed_tcp)" -ge 1 ]; then
  ok "the database check goes over TCP too"
else
  bad "the database check goes over TCP" "no -h in [$(cat "$TMP/calls")]"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
