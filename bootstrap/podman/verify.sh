#!/usr/bin/env bash
# Exit 0 if podman is installed and healthy, non-zero otherwise.
set -euo pipefail

if [ "$(uname -s)" = "Darwin" ]; then
  runtime_found=""
  if command -v podman >/dev/null 2>&1 && podman machine list --format '{{.Running}}' 2>/dev/null | grep -q true; then
    runtime_found="podman machine"
  elif command -v colima >/dev/null 2>&1 && colima status >/dev/null 2>&1; then
    runtime_found="colima"
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    runtime_found="Docker Desktop"
  fi

  if [ -z "$runtime_found" ]; then
    echo "podman: no container runtime found on macOS (checked: podman machine, colima, Docker Desktop)" >&2
    echo "podman: start one, e.g. 'podman machine init && podman machine start', then re-run" >&2
    exit 1
  fi

  if ! command -v podman >/dev/null 2>&1 || ! podman info >/dev/null 2>&1; then
    echo "podman: detected $runtime_found, but the 'podman' CLI isn't talking to it yet" >&2
    echo "podman: every module here drives containers via 'podman run' — run 'podman machine start' (or point podman at your $runtime_found backend), then re-run" >&2
    exit 1
  fi

  echo "podman: healthy via $runtime_found ($(podman --version))"
  exit 0
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "podman: not installed" >&2
  exit 1
fi

podman info >/dev/null
echo "podman: healthy ($(podman --version))"
