# redis

**What:** a single Redis 7 container, bound to `127.0.0.1` only. Backs
caching, pub/sub, and short-lived job/queue state for the workspace
runtime.

**Why 127.0.0.1 only:** same rule as postgres — never reachable from
outside your machine. No inbound port is ever opened to the internet by
any bootstrap module.

## Install

`install.sh` pulls the digest-pinned image (see `bootstrap/manifest.json`)
via `podman` and starts it bound to `127.0.0.1:6379`. Idempotent — skips if
the container already exists.

## Verify

`verify.sh` exits `0` if `redis-cli PING` returns `PONG`.
