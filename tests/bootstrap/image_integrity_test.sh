#!/usr/bin/env bash
# Tests bootstrap/lib/image_integrity.sh — no podman, no images.
#
# THE INCIDENT (2026-09-12/13, workspace `crispal`): two failures, one cause.
#
#   sudo: /usr/bin/sudo must be owned by uid 0 and have the setuid bit set
#   apache2: could not open error log file /var/log/apache2/error.log
#
# The first broke every app installer that shells out to sudo; the second
# crash-looped any container using the /dev/stderr logging convention the
# official nginx/httpd/wordpress images use. Same image, same digest, same
# file size — the EXTRACTION differed. Inside a userns-remapped host a chown
# by a process that is not real root clears setuid bits.
#
# Nothing upstream caught it because every check asks whether the image is
# THERE or whether the tag is CURRENT. Both say yes to a silently wrong layer.
#
# What these tests guard is the two ways this check can be worse than useless:
# refusing to boot a host over a probe that could not run, and "repairing" with
# a plain pull — which is a NO-OP when the digest is already local, so the bad
# layer survives and the repair reports success.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/image_integrity.sh
source "$DIR/../../bootstrap/lib/image_integrity.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n       %s\n' "$1" "$2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "image_integrity.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
MODE="4755"; RUN_FAILS=no; RMI_SEEN=no; PULL_OK=yes; PULL_MODE=""
podman() {
  printf '%s\n' "$1" >> "$TMP/calls"
  case "$1" in
    run)  [ "$RUN_FAILS" = yes ] && return 1; printf '%s\n' "$MODE" ;;
    rmi)  RMI_SEEN=yes ;;
    pull) [ "$PULL_OK" = yes ] || return 1
          [ -n "$PULL_MODE" ] && MODE="$PULL_MODE" ;;
    *) return 1 ;;
  esac
}
reset(){ : > "$TMP/calls"; RMI_SEEN=no; }
saw(){ grep -qx "$1" "$TMP/calls" 2>/dev/null; }

# --- reading the layer ------------------------------------------------------
MODE="4755"; reset; image_layer_intact img
check "setuid present is intact" "0" "$?"

MODE="755"; reset; image_layer_intact img
check "setuid stripped is NOT intact — the incident" "1" "$?"

MODE="4711"; reset; image_layer_intact img
check "any leading 4 counts as setuid" "0" "$?"

MODE="0755"; reset; image_layer_intact img
check "a zero-padded plain mode is still not setuid" "1" "$?"

MODE=""; reset; image_layer_intact img
check "an image with no sudo is not judged" "0" "$?"

RUN_FAILS=yes; reset; image_layer_intact img
check "a probe that cannot RUN is not a verdict" "0" "$?"
RUN_FAILS=no

# --- repairing it -----------------------------------------------------------
# The whole reason repair exists as its own step: `podman pull` on a digest
# that is already local does nothing, so the bad layer survives a pull. The
# image must be REMOVED first.
MODE="755"; PULL_MODE="4755"; PULL_OK=yes; reset
repair_image_layer img >/dev/null 2>&1
check "repair succeeds when re-extraction fixes it" "0" "$?"
[ "$RMI_SEEN" = yes ] && ok "repair REMOVES the image before pulling" \
                      || bad "repair removes first" "no rmi — a pull alone is a no-op"

MODE="755"; PULL_MODE="755"; PULL_OK=yes; reset
repair_image_layer img >/dev/null 2>&1
check "a re-extraction that changes nothing is reported as failure" "1" "$?"

MODE="755"; PULL_MODE="755"; PULL_OK=yes
out="$(repair_image_layer img 2>&1 >/dev/null)"
case "$out" in
  *"not a stale layer"*) ok "...and says to look at the host, not to retry" ;;
  *) bad "the message names the real cause" "got: $out" ;;
esac

MODE="755"; PULL_OK=no; reset
repair_image_layer img >/dev/null 2>&1
check "a failed re-pull is a failure, not a shrug" "1" "$?"

MODE="755"; PULL_OK=no
out="$(repair_image_layer img 2>&1 >/dev/null)"
case "$out" in
  *"NO copy"*) ok "...and warns the host is now imageless" ;;
  *) bad "warns about the removed image" "got: $out" ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
