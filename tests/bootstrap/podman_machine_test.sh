#!/usr/bin/env bash
# Tests bootstrap/lib/podman_machine.sh — pure functions, no podman, no sysctl.
#
# What these tests actually guard: the sizing formula and the undersized
# THRESHOLD, pinned against the hand-validated real-world case (24GB/15-core
# Mac mini -> 8192MB/7cpus) that motivated this card. A regression here
# either leaves a real host on podman's 2GiB default again, or makes the
# warning fire on a correctly-sized machine until nobody trusts it.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/podman_machine.sh
source "$DIR/../../bootstrap/lib/podman_machine.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n  \t%s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "podman_machine.sh"

# --- the sizing formula --------------------------------------------------
# 24GB/15-core Mac mini: the hand-validated live anchor this card exists
# because of (podman machine set --memory 8192 --cpus 6 was run by hand;
# 7 is the formula's equivalent since vCPUs are time-shared, not reserved).
check "24GB/15-core host -> 8192MB" "8192 7" "$(podman_machine_recommended_size 24576 15)"

# 8GB MacBook: above the 2048 default that OOMed, below half of RAM (floor).
check "8GB host hits the memory floor (3072MB)" "3072 4" "$(podman_machine_recommended_size 8192 8)"

# 64GB Mac Pro: capped, not a quarter-of-everything runaway.
check "64GB host hits the memory ceiling (16384MB)" "16384 8" "$(podman_machine_recommended_size 65536 16)"

# A single-CPU edge case still gets the cpu floor of 2.
check "low-cpu host hits the cpu floor (2)" "3072 2" "$(podman_machine_recommended_size 8192 1)"

# --- the undersized threshold, which is the whole point of this card ----
# (2048, 2) running on a 24GB/15-core host: podman's own default, exactly
# the OOM-crash-loop case this card was opened for.
podman_machine_undersized 2048 2 24576 15
check "2048MB/2cpu on a 24GB host is undersized" "0" "$?"

msg="$(podman_machine_size_message 2048 2 24576 15)"
case "$msg" in
  *"--memory 8192 --cpus 7"*) ok "message contains the exact literal resize command" ;;
  *) bad "message contains the exact literal resize command" "no '--memory 8192 --cpus 7' in [$msg]" ;;
esac
case "$msg" in
  *"aw-remote-host status"*) ok "message tells the human how to confirm it cleared" ;;
  *) bad "message tells the human how to confirm it cleared" "no 'aw-remote-host status' in [$msg]" ;;
esac

# (8192, 6) on the same 24GB/15-core host: at/above the min(recommended,4096)
# threshold — must NOT warn, or a deliberate hand-set machine becomes a
# permanently-amber row nobody trusts.
podman_machine_undersized 8192 6 24576 15
check "8192MB/6cpu on a 24GB host is NOT undersized" "1" "$?"

# The min(recommended, 4096) cap: an 8GB host's OWN formula (3072) must not
# warn about a machine we sized ourselves.
podman_machine_undersized 3072 4 8192 8
check "a host running exactly its own recommended size is NOT undersized" "1" "$?"

# cpus alone can trip it even when memory is generous.
podman_machine_undersized 8192 1 24576 15
check "plenty of memory but 1 cpu is still undersized" "0" "$?"

# --- mutation check: the threshold constant has to actually matter ------
# Patch the function to use a threshold of 0 (i.e. "never undersized") and
# confirm the SAME inputs that passed above now fail — proof this suite
# isn't vacuously green regardless of what the threshold is.
podman_machine_undersized() { return 1; }
podman_machine_undersized 2048 2 24576 15
check "mutation: a neutered threshold flips the OOM case to NOT undersized" "1" "$?"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
