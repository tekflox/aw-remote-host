#!/usr/bin/env bash
# The single place this repo declares WHICH podman it needs — sourced by
# bootstrap/podman/{install,verify}.sh so both agree, and by
# bootstrap/lib/network.sh for the version probe it already had.
#
# WHY A FLOOR HAS TO EXIST AT ALL, and why it has to live in verify.sh:
# internal/bootstrap/runner.go's RunModule skips install.sh entirely when
# verify.sh exits 0 (AlreadyOK). podman/verify.sh used to assert only that
# `podman info` works and the API socket is up — both true on 4.3.1. So a
# re-provision run whose whole point was moving podman would report success,
# skip the install, and leave the old version in place. That is the failure
# mode runner.go's own header warns about ("a verify.sh that only checks 'is
# it up' makes every install.sh guarantee apply solely to hosts that had
# nothing yet"), and podman is the third module to learn it after
# workspace/verify.sh (missing --init) and {postgres,redis}/verify.sh
# (container on the wrong storage, 2026-09-02 incident).
#
# WHY THE ASSERTION IS CONDITIONAL RATHER THAN `major >= 5 || exit 1`:
# an unconditional floor BRICKS every BYOD host on Debian 12. bookworm's apt
# offers only 4.3.1 (no backports podman, and Kubic ships an OLDER 3.4.2), so
# verify would fail forever; install.sh's `ensure_cmd podman` no-ops when
# podman already exists, so nothing could ever satisfy it; and runner.go's
# Run() stops at the first unhealthy module, meaning postgres, redis and the
# workspace itself would never start again. A guard that takes the host down
# is worse than the drift it was guarding against.
#
# So the assertion fires only when it is SATISFIABLE: installed major is
# below the floor AND this host's package manager actually offers something
# at or above it. On bookworm that is never true, and the module stays green
# on 4.3.1 exactly as it does today.
#
# Deliberately NOT gated on `grep trixie /etc/os-release`: that bakes one
# host's distro into a module every BYOD user runs, and silently fails to
# fire on Ubuntu 24.04+/Fedora, which reach the floor by their own schedule.
# The package manager already knows the answer — ask it.
#
# Not meant to be executed directly — only sourced.

# PODMAN_MIN_MAJOR is the major version the workspace wants. 5 is where
# `podman network update` arrives, which is what redirecting a running
# container's DNS through a VPN needs; 4.x cannot express it.
PODMAN_MIN_MAJOR="${PODMAN_MIN_MAJOR:-5}"

# podman_major prints podman's installed major version, or nothing if it
# can't be read. Lived in network.sh until the floor above needed it too.
podman_major() {
  podman --version 2>/dev/null | awk '{print $3}' | cut -d. -f1
}

# _major_of prints the leading integer of a package version string, or
# nothing when there isn't one. Debian versions carry epochs and suffixes
# ("100:3.4.2-5", "5.4.2+ds1-2+b2"), so strip an epoch first and then take
# digits up to the first dot.
_major_of() {
  printf '%s\n' "${1#*:}" | sed -n 's/^\([0-9][0-9]*\)\..*$/\1/p'
}

# podman_candidate_major prints the major version of the podman this host's
# package manager WOULD install right now, or nothing when that cannot be
# determined. Printing nothing is the safe answer everywhere: every caller
# treats "unknown" as "do not fail", so a package manager this doesn't
# understand can never take a host down.
podman_candidate_major() {
  local ver=""
  if command -v apt-cache >/dev/null 2>&1; then
    ver="$(apt-cache policy podman 2>/dev/null | awk '/Candidate:/{print $2; exit}')"
  elif command -v dnf >/dev/null 2>&1; then
    ver="$(dnf --quiet --cacheonly info podman 2>/dev/null | awk '/^Version/{print $3; exit}')"
  elif command -v pacman >/dev/null 2>&1; then
    ver="$(pacman -Si podman 2>/dev/null | awk '/^Version/{print $3; exit}')"
  fi
  case "$ver" in
    '' | '(none)') return 0 ;;
  esac
  _major_of "$ver"
}

# podman_version_floor_unsatisfiable echoes a human-readable reason and
# returns 0 when the floor CANNOT be met on this host, so callers can say so
# once instead of each inventing their own wording. Returns 1 when the floor
# is either already met or reachable.
#
# The three "unknown" cases (unreadable installed version, unreadable
# candidate, no recognised package manager) all land here on purpose — this
# is the branch that does not fail the module.
podman_version_floor_status() {
  local installed candidate
  installed="$(podman_major)"
  case "$installed" in
    '' | *[!0-9]*) echo "unknown"; return 0 ;;
  esac
  if [ "$installed" -ge "$PODMAN_MIN_MAJOR" ]; then
    echo "met"
    return 0
  fi
  candidate="$(podman_candidate_major)"
  case "$candidate" in
    '' | *[!0-9]*) echo "unreachable"; return 0 ;;
  esac
  if [ "$candidate" -ge "$PODMAN_MIN_MAJOR" ]; then
    echo "upgradable"
  else
    echo "unreachable"
  fi
}

# assert_podman_version_floor exits 1 ONLY in the "upgradable" case — podman
# is below the floor and this host can actually reach it, so failing here is
# what forces runner.go to run install.sh instead of reporting a success that
# changed nothing. Every other case passes, loudly enough to be greppable.
assert_podman_version_floor() {
  local status
  status="$(podman_version_floor_status)"
  case "$status" in
    met)
      return 0
      ;;
    unreachable)
      echo "podman: $(podman --version 2>/dev/null) is below the wanted major ${PODMAN_MIN_MAJOR}, and this host's package manager offers nothing newer — continuing, since failing here would take postgres/redis/workspace down with it"
      return 0
      ;;
    upgradable)
      echo "podman: installed major $(podman_major) is below ${PODMAN_MIN_MAJOR} but this host's package manager offers $(podman_candidate_major).x — install.sh must upgrade it" >&2
      return 1
      ;;
    *)
      echo "podman: could not read an installed version to compare against the wanted major ${PODMAN_MIN_MAJOR} — not guessing"
      return 0
      ;;
  esac
}

# upgrade_podman_to_floor upgrades podman when the floor is reachable.
#
# This exists because `ensure_cmd podman install_podman_linux` no-ops the
# moment podman is on PATH at ANY version. Without this, a host whose distro
# offers 5.x while 4.x is installed would fail verify, run an install.sh that
# does nothing, fail verify again, and take the whole module chain down —
# turning the guard above into the very brick it was written to avoid. Only
# runs in the "upgradable" case, so it is a no-op on bookworm.
upgrade_podman_to_floor() {
  [ "$(podman_version_floor_status)" = "upgradable" ] || return 0
  echo "podman: upgrading from $(podman_major).x toward ${PODMAN_MIN_MAJOR}+ (candidate $(podman_candidate_major).x)"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y --only-upgrade podman
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf upgrade -y podman
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm podman
  fi
}
