# workspace

**What:** the `aw-workspace` runtime image — the actual Agentic Workspace
application container, running on top of the podman + postgres + redis
modules installed above.

**Why last:** this module depends on the other three being healthy first;
`bootstrap.Run` (see `internal/bootstrap/manifest.go`) installs modules in
manifest order, so this one is placed last.

**Status:** the exact image reference and startup wiring (env vars,
volumes, how it discovers the local postgres/redis) is real
implementation work for card 4 (`bootstrap-workspace` real logic) — this
directory is a placeholder skeleton so the module shape (README +
install.sh + verify.sh) is consistent across all four components.

## Install

`install.sh` is currently a stub — it prints what it would do and exits 0
under `--plan`, and errors otherwise (see card 4).

## Verify

`verify.sh` checks whether the `aw-remote-host-workspace` container is
running; not yet wired to a real health endpoint (card 4).
