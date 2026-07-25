# postgres

**What:** a single Postgres 16 container with the `pgvector` extension
pre-installed, bound to `127.0.0.1` only. This is the data-plane database
for your workspace (relational data + vector KB embeddings).

**Why pgvector image, not plain postgres + manual extension build:**
`pgvector/pgvector:pg16` ships the extension precompiled — no build
toolchain needed on your machine, and the exact image is digest-pinned in
`bootstrap/manifest.json` so what you run is byte-for-byte what was
audited.

**Why 127.0.0.1 only:** this database is never meant to be reachable from
outside your own machine. The control plane talks to your workspace over
the outbound `/link` connection (see repo root README), never a direct
inbound connection to Postgres.

## Install

`install.sh` pulls the pinned image via `podman`, creates a named volume
for data persistence, and starts the container bound to
`127.0.0.1:5432` (idempotent — re-running skips an already-running
container). It also runs `CREATE EXTENSION IF NOT EXISTS vector;` once the
container is healthy.

## Verify

`verify.sh` exits `0` if the container is running and
`SELECT 1` succeeds against it.
