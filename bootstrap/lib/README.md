# lib — dependency resolution helpers

Not a module (no `install.sh`/`verify.sh`, nothing in `manifest.json`
points here) — `deps.sh` is a sourceable shell library that module
`install.sh` scripts use to resolve their own prerequisites **without
relying on the user's package manager** (no brew/apt/dnf/pacman assumed).

## Why

A clean BYOD Mac has no Homebrew, no colima, no Docker Desktop. The
original `podman/install.sh` just `exit 1`'d in that case ("install it
manually"). The fix isn't specific to podman — any module could hit the
same problem for any prerequisite — so the resolution logic lives here as
a shared, reusable helper instead of being hardcoded into one module.

## Functions

- **`ensure_cmd <cmd> <installer_fn>`** — runs `<installer_fn>` (a shell
  function already defined by the caller) only if `<cmd>` isn't already on
  `$PATH`. Safe to call unconditionally at the top of an `install.sh`.
- **`fetch_and_extract_pkg <url> <payload_dir_name> <dest_parent_dir>`** —
  downloads a macOS `.pkg` and extracts it with `pkgutil --expand-full`
  (no sudo/admin), then copies the directory named `<payload_dir_name>`
  found inside the payload to `<dest_parent_dir>/<payload_dir_name>`. The
  "vendored binary in `$HOME`" pattern for anything macOS would normally
  expect Homebrew to install.

## Reference consumer

`bootstrap/podman/install.sh` — when `brew` isn't available on macOS, it
sources this file and calls `fetch_and_extract_pkg` to vendor a pinned
podman release into `~/podman-dist/podman/`. See
`bootstrap/podman/README.md` for that recipe, and
`internal/bootstrap/runner.go`'s `podmanVendoredBinDir()` for how later
modules (postgres/redis/workspace) still find `podman` on `$PATH` even
though it was never installed system-wide.

## Extending to a new module

1. Write an `install_vendored_<thing>()` function in the module's own
   `install.sh` (mirroring `install_vendored_podman()`) that calls
   `fetch_and_extract_pkg` (or writes its own resolution logic — `deps.sh`
   doesn't have to be the only tool used).
2. Guard the call with `ensure_cmd <cmd> install_vendored_<thing>` (or an
   inline `command -v` check) so it's a no-op when the tool is already
   present.
3. If later modules need the vendored tool on `$PATH` too, that's a
   runner-level concern, not a shell one — see how
   `internal/bootstrap/runner.go` handles it for podman and follow the
   same shape (a `<thing>VendoredBinDir()` helper checked in `runScript`).

This repo doesn't have a full dependency graph/resolver — modules still
run in the fixed order declared in `manifest.json`. This library only
solves "how does one module install its own prerequisite without a
package manager," not module-to-module ordering.

Linux keeps installing everything through the distro's package manager
(`apt-get`/`dnf`/`pacman`) — those already work standalone on a clean
machine, so there's no vendored-fetch case for Linux yet. `ensure_cmd` is
still used there for the "already installed" no-op check.

## The `degradations/` marker-dir convention

`podman_machine.sh` is the first consumer of a small convention any future
`verify.sh` can reuse for a condition that is healthy-but-risky — true
enough to flag, not safe to fail on (a `verify.sh` failure aborts the
whole module chain, which is the wrong size of hammer for "this machine is
running, just undersized").

- One file per condition under `~/.aw-remote-host/degradations/`, named
  for the condition (e.g. `podman-machine-undersized`). This is a
  **per-machine**, not per-instance, path (`internal/instance.MachineDir()`
  on the Go side) — a host serving two linked identities still has exactly
  one physical podman machine, so the marker is host-level on purpose.
- File content is the full human-readable message, including any resize
  command the operator should run — `aw-remote-host status`
  (`cmd/aw-remote-host/commands.go` `runStatus`) and the ops `Health`
  payload (`internal/ops/ops.go`, via `internal/bootstrap.ReadDegradations`)
  both just relay that content verbatim.
- **SET + CLEAR, same writer.** The check that writes a marker when the
  condition is bad must also remove it the next time it observes the
  condition as fixed. A marker that only ever gets written becomes a
  permanently-amber row nobody trusts — see the workspace-wide
  degradation-signal convention this one is modeled on.
- Never let a SET/CLEAR check fail the script it lives in — wrap it so
  every command tolerates failure (`|| true`-style) and the check itself
  can never take verify.sh's exit code with it. See
  `bootstrap/podman/verify.sh`'s `check_podman_machine_sizing` for the
  pattern (a function invoked as `check_podman_machine_sizing || true`, so
  `set -e` is ignored for its entire body per POSIX).
