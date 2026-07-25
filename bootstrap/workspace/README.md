# workspace

**What:** the `aw-workspace` runtime image (F2, `ghcr.io/tekflox/aw-workspace`)
— the actual Agentic Workspace application container, running on top of the
podman + postgres + redis modules installed above, pointed at the local
Postgres via `AWSERV_DB_URL`/`AW_WORKSPACE_DB_URL` and schema-isolated via
`AW_WORKSPACE_SCHEMA=workspace_<slug>`.

**Why last:** this module depends on the other three being healthy first,
and on the workspace slug — which only exists once the CLI has dialed
`/link` and redeemed its token (see the root README and
`internal/link`). `aw-remote-host`'s CLI runs the podman/postgres/redis
modules first, dials `/link`, then runs this module with
`AW_WORKSPACE_SLUG`/`AW_POSTGRES_PASSWORD`/`AW_BACKEND_URL` set in its
environment — the user never types a slug.

## Install

`install.sh` starts (or reuses) the `aw-remote-host-workspace` container
bound to `127.0.0.1:9030`, `--restart=always`, and polls
`http://127.0.0.1:9030/api/health` until it responds. Idempotent — skips
the `podman run` if the container already exists.

## Verify

`verify.sh` exits `0` if the container exists and `/api/health` responds.
