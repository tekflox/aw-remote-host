#!/usr/bin/env bash
# Shared helpers for the "is this container using the storage we think it
# is" check that postgres/redis need and workspace already had.
#
# Sourced by bootstrap/{postgres,redis}/{install,verify}.sh.
#
# THE INCIDENT THIS EXISTS TO PREVENT (2026-09-02): postgres/verify.sh only
# ran `pg_isready` + `SELECT 1`, and redis/verify.sh only ran `PING`.
# Neither checked WHICH volume was actually mounted. install.sh already had
# a "container is on legacy storage -> recreate on $DATA_DIR" self-heal
# (added in b49fbb8: postgres/install.sh:43-55, redis/install.sh:33-45),
# but internal/bootstrap/runner.go's RunModule skips install.sh entirely
# once verify.sh exits 0 — so that self-heal was unreachable on any host
# whose container was merely UP. A host ran on the wrong named volume for
# hours before anyone noticed, because "healthy" and "correct storage" were
# never the same check.
#
# This is the SAME bug class bootstrap/workspace/verify.sh already
# documents and fixes for a different symptom (a missing --init): "Anything
# install.sh guarantees about HOW the container was created has to be
# asserted here too, or it only ever applies to hosts that had no container
# yet." This file is that assertion for postgres/redis's storage location,
# generalised so both modules share ONE definition of "the expected data
# dir" instead of each verify.sh guessing independently.
#
# THE ONE RULE THAT MATTERS: install.sh and verify.sh must compute the
# expected path through resolve_data_dir(), never by re-deriving it inline.
# If they ever drift — different $HOME, the override env var read in one
# process's environment but not the other's, a trailing slash — verify.sh
# fails on every single run, install.sh "self-heals" a perfectly healthy
# container on every single bootstrap, and production Postgres restarts
# with nobody noticing why. That failure mode is worse than the one this
# file fixes, so treat any future edit to either function as production
# infra, not shell scripting.
#
# Not meant to be executed directly — only sourced.

# _normalize_path prints $1 with a single trailing slash stripped, and
# NOTHING ELSE. Deliberately does not chase symlinks (no realpath, no
# readlink -f): podman reports a bind mount's Source as the literal
# argument the container was created with — it does NOT resolve symlinks in
# it. If this normaliser resolved symlinks while podman's own report stays
# literal, a symlinked $HOME would make every verify.sh run see a
# "different" path than the container actually has and recreate a healthy
# container on every boot — the exact outage class the file comment above
# warns about, just moved one layer down. Trailing-slash stripping is safe
# because it changes nothing podman itself would ever report differently.
_normalize_path() {
  printf '%s' "${1%/}"
}

# resolve_data_dir <override_env_name> <default_basename>
#
# Prints the ONE expected data dir for a datastore module: the value of the
# env var named by <override_env_name> if it is set, else
# "$HOME/<default_basename>". Both install.sh and verify.sh must call this
# — never inline the "${AW_X_HOST_DIR:-${HOME}/x-data}" fallback themselves
# — or the drift the file comment above warns about becomes possible again.
#
# Uses eval-based indirection rather than bash's `${!name:-default}` on
# purpose: these scripts run via `bash <path>` wherever `bash` resolves on
# the host, which on a clean BYOD Mac is still the system /bin/bash (3.2) —
# too old to reliably combine indirect expansion with a default value.
# <override_env_name> is always a literal this repo's own
# install.sh/verify.sh pass in, never external input, so the eval is safe.
resolve_data_dir() {
  local override_name="$1" default_basename="$2"
  local override_value
  override_value="$(eval "printf '%s' \"\${${override_name}:-}\"")"
  _normalize_path "${override_value:-${HOME}/${default_basename}}"
}

# mount_source <container> <destination>
#
# Prints the HOST-side source of the bind mount at <destination> inside
# <container>, or nothing if there is no such mount, the container does not
# exist, or podman itself cannot answer right now. Callers must treat empty
# output as "wrong/unknown", never as "assume it's fine" — same discipline
# bootstrap/lib/network.sh follows for an unreadable podman version probe.
# Never crashes the caller, even under `set -euo pipefail`.
mount_source() {
  local container="$1" destination="$2"
  local raw
  raw="$(podman inspect "$container" \
    --format "{{range .Mounts}}{{if eq .Destination \"$destination\"}}{{.Source}}{{end}}{{end}}" 2>/dev/null || true)"
  [ -n "$raw" ] || return 0
  _normalize_path "$raw"
}
