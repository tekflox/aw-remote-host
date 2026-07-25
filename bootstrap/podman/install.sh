#!/usr/bin/env bash
# Install podman via the distro package manager. Idempotent — safe to re-run.
set -euo pipefail

if command -v podman >/dev/null 2>&1; then
  echo "podman already installed: $(podman --version)"
  exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y podman
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y podman
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --noconfirm podman
else
  echo "no supported package manager found (need apt-get, dnf, or pacman)" >&2
  exit 1
fi

echo "podman installed: $(podman --version)"
