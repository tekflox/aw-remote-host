#!/usr/bin/env bash
# Shared helper: decide whether to publish a datastore's port to the host.
#
# postgres and redis each hard-coded `-p 127.0.0.1:<port>:<port>`, which made
# aw-remote-host uninstallable on any machine already using 5432 or 6379 —
# i.e. most developer boxes, and the aw.tekflox.com bare metal, where the
# bootstrap died on
#     Error: cannot listen on the TCP port: listen tcp4 127.0.0.1:6379:
#            bind: address already in use
# with no way to proceed short of stopping someone else's database.
#
# The publish is pure convenience. Nothing in the product goes through it:
# the workspace dials postgres/redis BY CONTAINER NAME over the shared podman
# network (see the REDIS_URL/DB_URL construction in workspace/install.sh), and
# both verify scripts use `podman exec`. It exists so a human on the host can
# reach the database with psql/redis-cli. So a taken port is not a reason to
# fail the install — it is a reason to skip the convenience and say so.
#
# Skipping is announced on stderr, every run, naming the port and the override.
# That is deliberate: silent degradation is this project's documented failure
# mode, and "psql: connection refused" with no explanation anywhere is exactly
# the shape of it. Nothing DEPENDS on the publish, so a loud skip is honest;
# a quiet one would not be.

# port_in_use <port> — 0 if something is already listening on it locally.
#
# Uses whichever tool the host has: ss on modern Linux, netstat on older
# images, lsof on macOS. If none is available we cannot tell, and the honest
# answer is "assume free" — podman's own bind error is then the fallback, which
# is the pre-existing behaviour rather than a new silent skip.
port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH "sport = :${port}" 2>/dev/null | grep -q . && return 0
    return 1
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    return 1
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]" && return 0
    return 1
  fi
  return 1
}

# publish_args <service> <port> <requested>
#
# Prints the `-p host:container` argument to stdout, or nothing when the
# publish is disabled or impossible. <requested> is the raw env override:
#   unset / empty  -> default 127.0.0.1:<port>
#   none | off     -> do not publish at all
#   <bind>         -> use it verbatim (e.g. 127.0.0.1:15432, or 0.0.0.0:5432)
#
# Diagnostics go to stderr so stdout stays parseable by the caller.
publish_args() {
  local service="$1" port="$2" requested="${3:-}"

  case "$(printf '%s' "$requested" | tr '[:upper:]' '[:lower:]')" in
    none|off|no|false)
      echo "${service}: host port publish disabled by request — reachable from" \
           "sibling containers as ${service} on the podman network" >&2
      return 0
      ;;
  esac

  local bind="${requested:-127.0.0.1:${port}}"
  # The port to test is the HOST side of the bind, i.e. the last colon field.
  local host_port="${bind##*:}"

  if port_in_use "$host_port"; then
    echo "${service}: host port ${host_port} is already in use — NOT publishing it." >&2
    echo "${service}: this is safe. The workspace reaches ${service} by container" >&2
    echo "${service}: name over the podman network, not through this port; only" >&2
    echo "${service}: host-side psql/redis-cli access is lost. Set" >&2
    echo "${service}: AW_$(printf '%s' "$service" | tr '[:lower:]' '[:upper:]')_PUBLISH=127.0.0.1:<free-port>" >&2
    echo "${service}: to expose it somewhere else, or =none to stop asking." >&2
    return 0
  fi

  printf -- '-p\n%s:%s\n' "$bind" "$port"
}
