#!/usr/bin/env bash
# "Is postgres ready?" has a wrong answer that looks exactly like the right
# one during the first thirty seconds of a fresh host's life.
#
# THE INCIDENT (2026-09-12, first clean "host with us" install): postgres
# install.sh waited with
#
#     podman exec "$CONTAINER_NAME" pg_isready -U postgres
#
# and broke out of the loop the moment that exited 0. The very next command
# died:
#
#     psql: error: connection to server on socket "/var/run/postgresql/..."
#     failed: FATAL:  the database system is shutting down
#
# and `set -euo pipefail` took the whole module down with it — before
# CREATE DATABASE aw_workspace ever ran. The workspace container then
# crash-looped on `database "aw_workspace" does not exist`, and the new
# workspace never came up at all.
#
# WHY pg_isready LIED: the official postgres entrypoint runs initdb against a
# TEMPORARY server so it can apply POSTGRES_PASSWORD and the init scripts
# without exposing a half-built database. That server is started with
# `listen_addresses=''` — it accepts connections ONLY on the unix socket —
# and is then shut down and replaced by the real one. `pg_isready` with no
# host talks to that socket, so it cheerfully reports the temporary server as
# ready, and whatever you run next races its shutdown.
#
# That is this codebase's recurring bug wearing yet another costume: a thing
# ANSWERED, and answering was read as being ready. `podman ps` said Up for a
# dead PID; `redis-cli PING` exited 0 while replying LOADING; a socket file
# existed with nothing behind it; a cached image was read as a current one.
#
# WHAT SEPARATES THEM is not a longer wait — a longer wait just moves the
# race — but the one difference the temporary server cannot fake: it does not
# listen on TCP. Probing 127.0.0.1 therefore answers the question actually
# being asked, "can the thing that will still be here in a second accept a
# connection", and no amount of initdb timing changes that.

# postgres_ready <container> -- true when the REAL server accepts TCP work.
postgres_ready() {
  local c="$1"
  # -h 127.0.0.1 is the entire point; dropping it reintroduces the incident.
  podman exec "$c" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 || return 1
  # And then actually transact. pg_isready only completes a startup packet;
  # a server that accepts connections while still recovering answers this
  # differently, and "ready" has to mean ready for the CREATE DATABASE that
  # comes next.
  podman exec "$c" psql -h 127.0.0.1 -U postgres -tAc "SELECT 1;" >/dev/null 2>&1
}

# postgres_wait_ready <container> <attempts> -- 0 once ready, 1 if it never is.
postgres_wait_ready() {
  local c="$1" attempts="${2:-60}" i=0
  while [ "$i" -lt "$attempts" ]; do
    if postgres_ready "$c"; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

# postgres_has_database <container> <name> -- true when <name> exists.
#
# Exists so install.sh and verify.sh ask it with ONE definition. verify.sh's
# header already tells this story for the data-dir mount: anything install.sh
# guarantees that verify.sh does not check is unreachable the moment the
# container is merely up, because RunModule skips install.sh once verify.sh
# exits 0. The aw_workspace database was exactly that gap.
postgres_has_database() {
  podman exec "$1" psql -h 127.0.0.1 -U postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname='$2'" 2>/dev/null | grep -q 1
}
