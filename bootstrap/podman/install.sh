#!/usr/bin/env bash
# Install/start a container runtime. Idempotent — safe to re-run.
set -euo pipefail

if [ "$(uname -s)" = "Darwin" ]; then
  # macOS has no native podman daemon — podman itself runs commands against
  # a Linux VM (a "podman machine"). colima/Docker Desktop are alternative
  # VM backends some users already have running; we detect them so the
  # error message is accurate, but every module here still drives
  # containers via the `podman` CLI, so podman itself must end up working.
  if ! command -v podman >/dev/null 2>&1; then
    if command -v brew >/dev/null 2>&1; then
      echo "podman: installing via Homebrew"
      brew install podman
    else
      echo "podman: 'podman' not found and Homebrew isn't available — install it manually: https://podman.io/docs/installation#macos" >&2
      exit 1
    fi
  fi

  if podman machine list --format '{{.Running}}' 2>/dev/null | grep -q true; then
    echo "podman: podman machine already running"
    exit 0
  fi
  if command -v colima >/dev/null 2>&1 && colima status >/dev/null 2>&1; then
    echo "podman: colima detected and running — if 'podman info' doesn't work against it, run 'podman machine init && podman machine start' instead"
    exit 0
  fi
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "podman: Docker Desktop detected and running — if 'podman info' doesn't work against it, run 'podman machine init && podman machine start' instead"
    exit 0
  fi

  echo "podman: no running container backend found — starting a podman machine"
  podman machine init 2>/dev/null || true
  podman machine start
  echo "podman: podman machine started"
  exit 0
fi

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
