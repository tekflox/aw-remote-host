#!/bin/sh
# Backs the aw-remote-host healthcheck in docker-compose.yml. Reads the
# status entrypoint.sh maintains at /run/aw-remote-host/status and fails
# (docker ps / compose ps show "unhealthy") for the two failure modes that
# used to be invisible: no usable credential at all, and a fast crash-loop.
# Any other status — including the file not existing yet on a fresh boot,
# or "retrying" after a single transient failure — is healthy.
STATUS_FILE=/run/aw-remote-host/status
[ -f "$STATUS_FILE" ] || exit 0

case "$(cat "$STATUS_FILE")" in
  status=missing_token*|status=crash_loop*) exit 1 ;;
  *) exit 0 ;;
esac
