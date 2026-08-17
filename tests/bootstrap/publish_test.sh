#!/usr/bin/env bash
# Tests for bootstrap/lib/publish.sh. Run directly: bash publish_test.sh
#
# Driven by the failure it exists to prevent: aw-remote-host could not install
# on any machine already using 5432 or 6379, because a hard-coded `-p` turned
# someone else's running database into a fatal bootstrap error.
set -uo pipefail

# Deliberately OUTSIDE bootstrap/: everything under that tree is embedded into
# the binary and extracted onto every user's machine by ExtractScripts, and a
# test file has no business shipping to a BYOD host.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bootstrap/lib/publish.sh
source "$DIR/../../bootstrap/lib/publish.sh"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n  	%s\n' "$1" "$2"; }
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi
}

# Deterministic: stub the probe instead of binding real ports, so the suite
# does not depend on what happens to be listening on the machine running it.
FREE_PORTS=""
port_in_use() { case " $FREE_PORTS " in *" $1 "*) return 1;; *) return 0;; esac; }

echo "publish.sh"

# --- default: port free -> publish on loopback -------------------------------
FREE_PORTS="5432"
check "free port publishes the default loopback bind" \
  "-p 127.0.0.1:5432:5432" \
  "$(publish_args postgres 5432 "" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"

# --- the regression: port taken -> skip, do NOT fail -------------------------
FREE_PORTS=""
out="$(publish_args redis 6379 "" 2>/dev/null)"
check "taken port emits no -p at all (install proceeds)" "" "$out"

rc=$?
check "taken port still exits 0" "0" "$rc"

# The skip has to be audible — nothing depends on the publish, but a silent
# loss of psql/redis-cli access is the shape of every bug in this project.
warn="$(publish_args redis 6379 "" 2>&1 >/dev/null)"
case "$warn" in
  *"already in use"*) ok "taken port warns on stderr" ;;
  *) bad "taken port warns on stderr" "no warning: $warn" ;;
esac
case "$warn" in
  *AW_REDIS_PUBLISH*) ok "warning names the override env var" ;;
  *) bad "warning names the override env var" "missing: $warn" ;;
esac
case "$warn" in
  *"by container"*|*"podman network"*) ok "warning says why it is safe" ;;
  *) bad "warning says why it is safe" "missing rationale: $warn" ;;
esac

# --- explicit disable --------------------------------------------------------
FREE_PORTS="6379"
for v in none NONE off no false; do
  check "publish=$v disables the publish" "" "$(publish_args redis 6379 "$v" 2>/dev/null)"
done

# --- explicit override -------------------------------------------------------
FREE_PORTS="15432"
check "custom bind is used verbatim, container port preserved" \
  "-p 127.0.0.1:15432:5432" \
  "$(publish_args postgres 5432 "127.0.0.1:15432" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"

FREE_PORTS="5432"
check "a 0.0.0.0 bind is honoured (deliberate LAN exposure)" \
  "-p 0.0.0.0:5432:5432" \
  "$(publish_args postgres 5432 "0.0.0.0:5432" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"

# The HOST side of the override is what gets probed, not the container port —
# otherwise moving postgres to 15432 would still test 5432 and skip wrongly.
FREE_PORTS="15432"
check "conflict check uses the host port from the override" \
  "-p 127.0.0.1:15432:5432" \
  "$(publish_args postgres 5432 "127.0.0.1:15432" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
