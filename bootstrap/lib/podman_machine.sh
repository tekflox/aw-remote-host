#!/usr/bin/env bash
# Sizing + undersized-diagnosis for macOS podman machines — sourced by
# bootstrap/podman/{install,verify}.sh so both agree, mirroring the
# install-action + verify-assertion split in bootstrap/lib/podman_version.sh.
#
# THE INCIDENT this exists to prevent: `podman machine init`'s own default is
# 2GiB RAM / 2 CPUs, which is enough for nothing — on a real workspace
# (postgres + redis + the workspace itself + several Tier-2 app containers)
# it OOM-killed services in a loop (exit -9), and nothing in bootstrap's own
# output named memory as the cause. The fix lives in TWO places because it
# is two different problems: sizing a FRESH `machine init` at install time is
# genuinely just a setting (set it right once, nothing to warn about); an
# ALREADY-RUNNING undersized machine is not a setting, it's an outage —
# `podman machine set` needs stop+start, which kills every running
# container including the workspace — so that case gets a diagnosis instead
# of an auto-fix. See bootstrap/podman/verify.sh for where that diagnosis
# is wired in.
#
# All functions here are PURE (values in, values out, no podman/sysctl calls
# inside) so tests/bootstrap/podman_machine_test.sh runs on Linux CI with no
# macOS and no real podman machine.
#
# Not meant to be executed directly — only sourced.

# podman_machine_recommended_size prints "mem_mb cpus" sized from this
# host's PHYSICAL memory/CPU count, not app count — apps are installed by
# the workspace after bootstrap, so bootstrap can't know how many there will
# be, and coupling VM size to marketplace state would make sizing drift
# every time the operator installs or removes an app.
#
# memory: host_mem_mb / 3, clamped to [3072, 16384]. A third (not half)
# because the Mac also runs agent sandboxes, browsers and the human's own
# apps, and applehv/vfkit allocates guest pages lazily — generosity here is
# cheap, but an unbounded share invites host-side memory pressure. Anchors:
# a 24GB/15-core host lands on 8192 (the hand-validated live value this was
# built from); an 8GB MacBook lands on the 3072 floor (above the 2048
# default that OOMed, still leaves 5GB for macOS); a 64GB Mac Pro is capped
# at the 16384 ceiling (a quarter of RAM, not all of it).
#
# cpus: ncpu / 2, clamped to [2, 8]. vCPUs are time-shared, not reserved, so
# this is cheaper to be generous with than memory.
podman_machine_recommended_size() {
  local host_mem_mb="$1" ncpu="$2"
  local mem_mb cpus

  mem_mb=$(( host_mem_mb / 3 ))
  if [ "$mem_mb" -lt 3072 ]; then mem_mb=3072; fi
  if [ "$mem_mb" -gt 16384 ]; then mem_mb=16384; fi

  cpus=$(( ncpu / 2 ))
  if [ "$cpus" -lt 2 ]; then cpus=2; fi
  if [ "$cpus" -gt 8 ]; then cpus=8; fi

  printf '%s %s\n' "$mem_mb" "$cpus"
}

# podman_machine_undersized returns 0 (true) when a RUNNING machine's
# current memory/cpus fall below what this host should be running, 1
# otherwise.
#
# The memory threshold is min(recommended_mem_mb, 4096), not just
# recommended_mem_mb — a fresh 8GB-host machine our own formula inited at
# 3072 must NOT warn (nothing is wrong, it's exactly what we chose), while a
# 24GB host still sitting on podman's 2048 default MUST. The 4096 MB
# absolute cap also keeps a deliberate hand-set >=4GiB machine on a big host
# quiet — a warning that contradicts an operator's own working choice
# becomes a permanently-amber row people learn to ignore.
podman_machine_undersized() {
  local cur_mem_mb="$1" cur_cpus="$2" host_mem_mb="$3" ncpu="$4"
  local recommended_mem_mb recommended_cpus threshold_mem_mb

  read -r recommended_mem_mb recommended_cpus < <(podman_machine_recommended_size "$host_mem_mb" "$ncpu")

  threshold_mem_mb="$recommended_mem_mb"
  if [ "$threshold_mem_mb" -gt 4096 ]; then threshold_mem_mb=4096; fi

  if [ "$cur_mem_mb" -lt "$threshold_mem_mb" ] || [ "$cur_cpus" -lt 2 ]; then
    return 0
  fi
  return 1
}

# podman_machine_size_message prints the human-readable warning for an
# undersized RUNNING machine, including the literal resize command — this
# is not auto-applied (see the incident note above: it needs stop+start,
# which is an outage), so the operator has to run it themselves.
podman_machine_size_message() {
  local cur_mem_mb="$1" cur_cpus="$2" host_mem_mb="$3" ncpu="$4"
  local recommended_mem_mb recommended_cpus

  read -r recommended_mem_mb recommended_cpus < <(podman_machine_recommended_size "$host_mem_mb" "$ncpu")

  printf 'podman machine is undersized (%sMB/%s cpus running, %sMB/%s cpus recommended for this host) — containers can OOM-kill under real load. Resize it: podman machine stop && podman machine set --memory %s --cpus %s && podman machine start\nThen re-run '"'"'aw-remote-host status'"'"' to confirm this warning clears.\n' \
    "$cur_mem_mb" "$cur_cpus" "$recommended_mem_mb" "$recommended_cpus" "$recommended_mem_mb" "$recommended_cpus"
}
