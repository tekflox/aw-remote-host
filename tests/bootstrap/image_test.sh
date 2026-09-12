#!/usr/bin/env bash
# Tests bootstrap/lib/image.sh — no registry, no podman.
#
# THE INCIDENT (2026-09-12): workspace/install.sh recreated the workspace with
# `if podman image exists "$IMAGE"` and $IMAGE defaults to a MOVING tag
# (:latest). Every recreate on a host that had ever pulled it — the Update
# button's recreate included — rebuilt from the cached copy and announced
# success. The workspace ran a weeks-old image while the log, the control
# plane and the operator all believed it had just been updated.
#
# What these tests actually guard is the SPLIT: a digest pin must be trusted
# from cache (re-pulling immutable bytes is pure waste) and a moving tag must
# never be. Get either half wrong and you have the bug back, or a pull on
# every boot of a host that is already correct.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/image.sh
source "$DIR/../../bootstrap/lib/image.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n  \t%s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "image.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# The two outside-world calls, stubbed. HAVE_LOCAL/PULL_OK drive them; the
# call log goes to a FILE because podman is invoked from subshells.
HAVE_LOCAL=no
PULL_OK=yes
podman() {
  echo "$*" >> "$TMP/calls"
  case "$1" in
    image) [ "$HAVE_LOCAL" = yes ] ;;
    pull)  [ "$PULL_OK" = yes ] ;;
    *)     return 1 ;;
  esac
}
reset() { : > "$TMP/calls"; }
pulled() { grep -c '^pull' "$TMP/calls" 2>/dev/null | tr -d ' '; }

PIN="ghcr.io/x/aw-workspace@sha256:$(printf 'a%.0s' {1..64})"
TAG="ghcr.io/x/aw-workspace:latest"

# --- which references are immutable -------------------------------------
image_is_pinned "$PIN"; check "a digest reference is pinned" "0" "$?"
image_is_pinned "$TAG"; check ":latest is not pinned" "1" "$?"
image_is_pinned "ghcr.io/x/aw-workspace:v0.1.107"
check "a version tag is not pinned either — tags can be moved" "1" "$?"
image_is_pinned "ghcr.io/x/aw-workspace"
check "a bare name is not pinned" "1" "$?"

# --- the moving tag, which is the whole point ---------------------------
HAVE_LOCAL=yes; PULL_OK=yes; reset
ensure_image_current "$TAG" workspace >/dev/null 2>&1
check "a moving tag is pulled EVEN WHEN a local copy exists" "1" "$(pulled)"

HAVE_LOCAL=no; PULL_OK=yes; reset
ensure_image_current "$TAG" workspace >/dev/null 2>&1
check "a moving tag with no local copy is pulled" "1" "$(pulled)"

# --- the digest pin, which must NOT cost a pull -------------------------
HAVE_LOCAL=yes; PULL_OK=yes; reset
ensure_image_current "$PIN" workspace >/dev/null 2>&1
check "a local digest pin is trusted without a pull" "0" "$(pulled)"

HAVE_LOCAL=no; PULL_OK=yes; reset
ensure_image_current "$PIN" workspace >/dev/null 2>&1
check "a digest pin that is absent is still pulled" "1" "$(pulled)"

# --- failure must not become an outage ----------------------------------
HAVE_LOCAL=yes; PULL_OK=no; reset
ensure_image_current "$TAG" workspace >/dev/null 2>&1
check "an offline host falls back to its local copy" "0" "$?"

HAVE_LOCAL=yes; PULL_OK=no
out="$(ensure_image_current "$TAG" workspace 2>&1 >/dev/null)"
case "$out" in
  *STALE*) ok "and SAYS the copy may be stale — a silent fallback is the bug" ;;
  *) bad "the stale fallback warns" "no STALE in [$out]" ;;
esac

HAVE_LOCAL=no; PULL_OK=no
ensure_image_current "$TAG" workspace >/dev/null 2>&1
check "no pull and no local copy is a failure, not a shrug" "1" "$?"

HAVE_LOCAL=no; PULL_OK=no
ensure_image_current "$PIN" workspace >/dev/null 2>&1
check "an unpullable pinned image fails too" "1" "$?"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
