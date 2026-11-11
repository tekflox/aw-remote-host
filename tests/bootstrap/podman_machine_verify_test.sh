#!/usr/bin/env bash
# Integration test for bootstrap/podman/verify.sh's macOS undersized-machine
# diagnosis — runs the REAL verify.sh (not a sourced function) as a separate
# process, on Linux CI, by stubbing `uname`, `sysctl` and `podman` on PATH.
#
# What this proves that the pure-function test (podman_machine_test.sh)
# cannot: that the SET/CLEAR branch in verify.sh actually fires (the right
# machine gets inspected, the marker lands in the right place, the message
# reaches stderr) and that it stops firing once the machine is no longer
# undersized — not just that the underlying formula is correct in
# isolation. Both runs also assert verify.sh's own exit code is 0: a
# `set -euo pipefail` script that let this check fail the whole script would
# abort the bootstrap module chain on every existing undersized host, which
# is the one regression the Product Owner explicitly forbade.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY="$REPO_DIR/bootstrap/podman/verify.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n  \t%s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }

echo "verify.sh (macOS podman-machine sizing branch)"

# --- stubs: a fake Darwin host with a fake podman machine ---------------
STUBDIR="$TMP/bin"
mkdir -p "$STUBDIR"

cat > "$STUBDIR/uname" <<'STUB'
#!/usr/bin/env bash
[ "$1" = "-s" ] && { echo "Darwin"; exit 0; }
exec /usr/bin/uname "$@"
STUB

cat > "$STUBDIR/sysctl" <<'STUB'
#!/usr/bin/env bash
# called as: sysctl -n hw.memsize | sysctl -n hw.ncpu
case "$2" in
  hw.memsize) printf '%s\n' "${HOST_MEM_BYTES:?}" ;;
  hw.ncpu)    printf '%s\n' "${HOST_NCPU:?}" ;;
  *) exit 1 ;;
esac
STUB

# CUR_MEM_MB/CUR_CPUS are the RUNNING machine's current size — the thing
# under test. HOST_MEM_BYTES/HOST_NCPU are the (fixed) physical host facts.
cat > "$STUBDIR/podman" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  --version) echo "podman version 6.0.2"; exit 0 ;;
  info) exit 0 ;;
  machine)
    case "$2" in
      list)
        case "$4" in
          *Name*) printf 'podman-machine-default\ttrue\n' ;;
          *)      printf 'true\n' ;;
        esac
        ;;
      inspect)
        case "$5" in
          *Memory*) printf '%s\n' "${CUR_MEM_MB:?}" ;;
          *CPUs*)   printf '%s\n' "${CUR_CPUS:?}" ;;
          *) exit 1 ;;
        esac
        ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
STUB

chmod +x "$STUBDIR"/uname "$STUBDIR"/sysctl "$STUBDIR"/podman

FAKE_HOME="$TMP/home"
mkdir -p "$FAKE_HOME"
MARKER="$FAKE_HOME/.aw-remote-host/degradations/podman-machine-undersized"

# The hand-validated anchor case this card was opened for: a 24GB/15-core
# host whose machine is still on podman's own 2048MB/2cpu default.
export PATH="$STUBDIR:$PATH"
export HOME="$FAKE_HOME"
export HOST_MEM_BYTES=$(( 24576 * 1024 * 1024 ))
export HOST_NCPU=15

# --- SET: an undersized running machine ----------------------------------
export CUR_MEM_MB=2048
export CUR_CPUS=2
err_set="$(bash "$VERIFY" 2>&1 1>/dev/null)"
rc_set=$?

check "SET: verify.sh still exits 0 (never aborts the module chain)" "0" "$rc_set"
check "SET: the marker file was written" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
case "$err_set" in
  *"--memory 8192 --cpus 7"*) ok "SET: stderr carries the literal resize command" ;;
  *) bad "SET: stderr carries the literal resize command" "not found in [$err_set]" ;;
esac

# --- CLEAR: the same machine, now correctly sized ------------------------
export CUR_MEM_MB=8192
export CUR_CPUS=7
err_clear="$(bash "$VERIFY" 2>&1 1>/dev/null)"
rc_clear=$?

check "CLEAR: verify.sh still exits 0" "0" "$rc_clear"
check "CLEAR: the marker file was removed" "0" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
case "$err_clear" in
  *"--memory"*) bad "CLEAR: no resize command on stderr once healthy" "found one in [$err_clear]" ;;
  *) ok "CLEAR: no resize command on stderr once healthy" ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
