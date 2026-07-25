#!/usr/bin/env bash
# Exit 0 if podman is installed and healthy, non-zero otherwise.
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  echo "podman: not installed" >&2
  exit 1
fi

podman info >/dev/null
echo "podman: healthy ($(podman --version))"
