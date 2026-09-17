#!/usr/bin/env bash
# Tests entrypoint.sh's PID-1 responsibilities: forwarding SIGTERM to the
# child so `podman stop` doesn't burn its full timeout into a SIGKILL, and
# the heartbeat watcher recycling a wedged-but-alive child that a plain
# `wait`-for-exit loop would never notice. See entrypoint.sh's own header
# comment (resilience:hosted-entrypoint-signal-and-hang-supervision) for the
# incident this exists to prevent.
#
# entrypoint.sh isn't a sourced library like the rest of tests/bootstrap/ —
# it's the whole PID-1 script, hardcoded at /run/aw-remote-host and driven by
# the real aw-remote-host binary. Neither is safe to use from a test: this CI
# job runs on a real bare-metal host that may have its own /run/aw-remote-host
# already in use by a live instance, and there's no aw-remote-host binary to
# hand it here anyway. So every hardcoded /run/aw-remote-host and
# /var/run/tailscale path is rewritten (sed, not a code change) into a tmpdir
# before running, and a fake aw-remote-host stands in on PATH — it only needs
# to model the two things entrypoint.sh's contract actually depends on:
# touching $AW_REMOTE_HOST_HEARTBEAT_FILE on each simulated "read", and
# exiting cleanly on SIGTERM. A wedge is simulated by SIGSTOP-ing that fake
# process from the test itself — genuinely unresponsive to everything but
# SIGKILL, the same as a real hung syscall would leave it.
#
# Run: tests/bootstrap/entrypoint_test.sh
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$DIR/../.." && pwd)"
ENTRY_SRC="$REPO_DIR/entrypoint.sh"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n  	%s\n' "$1" "$2"; }
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi
}

echo "entrypoint.sh"

TMP="$(mktemp -d)"
ENTRY_PID=""
CHILD_REAL_PID=""

stop_scenario() {
  if [ -n "$ENTRY_PID" ]; then
    kill -TERM "$ENTRY_PID" 2>/dev/null
    local i=0
    while kill -0 "$ENTRY_PID" 2>/dev/null && [ "$i" -lt 25 ]; do sleep 0.2; i=$((i + 1)); done
    kill -9 "$ENTRY_PID" 2>/dev/null
  fi
  # entrypoint's own trap only reaps the CURRENT child + heartbeat watcher —
  # it never touches the chown-wait or tailscaled-supervisor loops it also
  # backgrounds, so those would otherwise leak into the CI runner as orphaned
  # `while true` processes. Sweep anything left from this scenario's copy.
  [ -n "${ENTRY_COPY:-}" ] && pkill -9 -f "$ENTRY_COPY" 2>/dev/null
  if [ -n "$CHILD_REAL_PID" ]; then
    kill -CONT "$CHILD_REAL_PID" 2>/dev/null
    kill -9 "$CHILD_REAL_PID" 2>/dev/null
  fi
  ENTRY_PID=""
  CHILD_REAL_PID=""
}

cleanup() {
  stop_scenario
  pkill -9 -f "$TMP" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- fake aw-remote-host on PATH ------------------------------------------
mkdir -p "$TMP/bin"
cat > "$TMP/bin/aw-remote-host" <<'FAKE'
#!/usr/bin/env bash
set -u
trap 'echo term >> "${FAKE_EVENTS_FILE:-/dev/null}"; exit 0' TERM
: > "${AW_REMOTE_HOST_HEARTBEAT_FILE:-/dev/null}" 2>/dev/null
while true; do
  sleep "${FAKE_HEARTBEAT_INTERVAL:-1}"
  : > "${AW_REMOTE_HOST_HEARTBEAT_FILE:-/dev/null}" 2>/dev/null
done
FAKE
chmod +x "$TMP/bin/aw-remote-host"
export PATH="$TMP/bin:$PATH"

# run_scenario <name> — starts a fresh entrypoint.sh copy with its own
# RUN_DIR/HOME, reading STALE / CHECK_INTERVAL / FAKE_HB_INTERVAL from the
# caller's environment (defaults chosen to keep the test fast).
run_scenario() {
  SCEN="$TMP/$1"
  RUN_DIR="$SCEN/run"
  mkdir -p "$RUN_DIR" "$SCEN/home/.aw-remote-host"
  # A non-empty credentials.json marks the host as already-linked, so the
  # entrypoint doesn't refuse to start for lack of AW_REMOTE_HOST_TOKEN.
  echo '{}' > "$SCEN/home/.aw-remote-host/credentials.json"
  ENTRY_COPY="$SCEN/entrypoint.sh"
  sed -e "s#/run/aw-remote-host#$RUN_DIR#g" \
      -e "s#/var/run/tailscale#$SCEN/tailscale#g" \
      "$ENTRY_SRC" > "$ENTRY_COPY"
  chmod +x "$ENTRY_COPY"
  : > "$SCEN/events"
  HOME="$SCEN/home" \
  FAKE_EVENTS_FILE="$SCEN/events" \
  AW_REMOTE_HOST_HEARTBEAT_STALE_SECONDS="${STALE:-3}" \
  AW_REMOTE_HOST_HEARTBEAT_CHECK_INTERVAL="${CHECK_INTERVAL:-1}" \
  FAKE_HEARTBEAT_INTERVAL="${FAKE_HB_INTERVAL:-1}" \
  bash "$ENTRY_COPY" >"$SCEN/stdout.log" 2>"$SCEN/stderr.log" &
  ENTRY_PID=$!
}

wait_for_child_pid() {
  local file="$RUN_DIR/child.pid" tries=0
  while [ ! -s "$file" ] && [ "$tries" -lt 50 ]; do
    sleep 0.2
    tries=$((tries + 1))
  done
  cat "$file" 2>/dev/null
}

wait_while_alive() { # wait_while_alive <pid> <max_tries (x0.2s)>
  local pid="$1" max="$2" i=0
  while kill -0 "$pid" 2>/dev/null && [ "$i" -lt "$max" ]; do sleep 0.2; i=$((i + 1)); done
}

# === scenario 1: SIGTERM -> forwarded to the child, clean exit =============
run_scenario scenario1
CHILD_REAL_PID="$(wait_for_child_pid)"
check "scenario1: child started" "1" \
  "$([ -n "$CHILD_REAL_PID" ] && kill -0 "$CHILD_REAL_PID" 2>/dev/null && echo 1 || echo 0)"

kill -TERM "$ENTRY_PID"
wait_while_alive "$ENTRY_PID" 25
check "scenario1: entrypoint exits promptly on SIGTERM (not the 10s retry sleep)" "1" \
  "$(kill -0 "$ENTRY_PID" 2>/dev/null && echo 0 || echo 1)"
check "scenario1: child received and handled the forwarded TERM" "term" "$(cat "$SCEN/events" 2>/dev/null)"
check "scenario1: child process is gone too" "1" \
  "$(kill -0 "$CHILD_REAL_PID" 2>/dev/null && echo 0 || echo 1)"
check "scenario1: status file ends stopped" "status=stopped" "$(cat "$RUN_DIR/status" 2>/dev/null)"
stop_scenario

# === scenario 2: SIGSTOP-simulated wedge -> recycled by the heartbeat watcher
STALE=2 CHECK_INTERVAL=1 FAKE_HB_INTERVAL=1
run_scenario scenario2
CHILD_REAL_PID="$(wait_for_child_pid)"
check "scenario2: child started" "1" \
  "$([ -n "$CHILD_REAL_PID" ] && kill -0 "$CHILD_REAL_PID" 2>/dev/null && echo 1 || echo 0)"

# Freeze it exactly like a hung syscall would: alive, but unable to touch its
# own heartbeat or react to a plain SIGTERM.
kill -STOP "$CHILD_REAL_PID"
wait_while_alive "$CHILD_REAL_PID" 60
check "scenario2: watcher kills the wedged child even though SIGSTOP made it TERM-proof" "1" \
  "$(kill -0 "$CHILD_REAL_PID" 2>/dev/null && echo 0 || echo 1)"
check "scenario2: watcher logged why it escalated" "1" \
  "$(grep -c 'looks wedged rather than merely idle' "$SCEN/stderr.log" 2>/dev/null)"

NEW_PID=""
tries=0
# The restart loop's own retry pause (entrypoint.sh's hardcoded `sleep 10`
# between a child exiting and the next one starting) sits between the kill
# above and a fresh child.pid — the poll budget has to clear that, not just
# the watcher's own timing.
while [ "$tries" -lt 80 ]; do
  NEW_PID="$(cat "$RUN_DIR/child.pid" 2>/dev/null)"
  [ -n "$NEW_PID" ] && [ "$NEW_PID" != "$CHILD_REAL_PID" ] && break
  sleep 0.2
  tries=$((tries + 1))
done
check "scenario2: the restart loop recycled it with a fresh child" "1" \
  "$([ -n "$NEW_PID" ] && [ "$NEW_PID" != "$CHILD_REAL_PID" ] && echo 1 || echo 0)"
stop_scenario

# === scenario 3: healthy idle child is never killed ========================
STALE=2 CHECK_INTERVAL=1 FAKE_HB_INTERVAL=1
run_scenario scenario3
CHILD_REAL_PID="$(wait_for_child_pid)"
check "scenario3: child started" "1" \
  "$([ -n "$CHILD_REAL_PID" ] && kill -0 "$CHILD_REAL_PID" 2>/dev/null && echo 1 || echo 0)"

# Outlive several stale-threshold windows while the fake keeps touching its
# heartbeat — long enough that an off-by-one or a wrong-file comparison in
# the watcher would already have killed it.
sleep $(( (STALE + CHECK_INTERVAL) * 3 ))

check "scenario3: a healthy idle child survives repeated watcher passes" "1" \
  "$(kill -0 "$CHILD_REAL_PID" 2>/dev/null && echo 1 || echo 0)"
check "scenario3: never recycled — same child pid the whole time" "$CHILD_REAL_PID" \
  "$(cat "$RUN_DIR/child.pid" 2>/dev/null)"
check "scenario3: watcher never logged a wedge" "0" \
  "$(grep -c 'looks wedged rather than merely idle' "$SCEN/stderr.log" 2>/dev/null)"
stop_scenario

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
