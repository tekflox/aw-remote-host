#!/usr/bin/env bash
# Install/start a container runtime. Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/deps.sh
source "$SCRIPT_DIR/../lib/deps.sh"

# Pinned, validated on a real brew-less Mac (see bootstrap/podman/README.md).
PODMAN_VENDORED_VERSION="6.0.2"
PODMAN_DIST_DIR="$HOME/podman-dist"

# install_vendored_podman downloads the official macOS podman .pkg and
# extracts it into $HOME without brew/sudo/admin — the first concrete case
# of the dependency-resolution pattern in bootstrap/lib/deps.sh.
install_vendored_podman() {
  local arch pkg_arch url
  arch="$(uname -m)"
  case "$arch" in
    arm64) pkg_arch="arm64" ;;
    x86_64) pkg_arch="amd64" ;;
    *)
      echo "podman: unsupported macOS arch '$arch' for vendored install — install podman manually: https://podman.io/docs/installation#macos" >&2
      return 1
      ;;
  esac
  url="https://github.com/containers/podman/releases/download/v${PODMAN_VENDORED_VERSION}/podman-installer-macos-${pkg_arch}.pkg"

  fetch_and_extract_pkg "$url" "podman" "$PODMAN_DIST_DIR"

  cat > "$PODMAN_DIST_DIR/env.sh" <<EOF
export PATH="$PODMAN_DIST_DIR/podman/bin:\$PATH"
export CONTAINERS_HELPER_BINARY_DIR="$PODMAN_DIST_DIR/podman/bin"
export CONTAINERS_MACHINE_PROVIDER=applehv
EOF

  # Make it available for the rest of this script; internal/bootstrap/
  # runner.go's runScript() also prepends $PODMAN_DIST_DIR/podman/bin onto
  # PATH for every module it runs afterwards (see the package doc comment
  # there), so postgres/redis/workspace's install.sh see it too.
  export PATH="$PODMAN_DIST_DIR/podman/bin:$PATH"
  export CONTAINERS_HELPER_BINARY_DIR="$PODMAN_DIST_DIR/podman/bin"
  export CONTAINERS_MACHINE_PROVIDER=applehv

  if ! command -v podman >/dev/null 2>&1; then
    echo "podman: vendored install did not produce a working 'podman' binary under $PODMAN_DIST_DIR/podman/bin" >&2
    return 1
  fi
  echo "podman: vendored install OK ($(podman --version))"
}

# ensure_applehv_provider pins the podman machine provider to applehv.
# The default provider (libkrun/krunkit) is known to crash with an abort
# trap on some Mac models — Apple Virtualization + vfkit (applehv) is the
# one validated to work. Only writes when no provider is configured yet, so
# it never clobbers an existing containers.conf.
ensure_applehv_provider() {
  local conf_file="$HOME/.config/containers/containers.conf"
  mkdir -p "$(dirname "$conf_file")"
  if grep -q 'provider' "$conf_file" 2>/dev/null; then
    if ! grep -q 'provider *= *"applehv"' "$conf_file" 2>/dev/null; then
      echo "podman: $conf_file already sets a machine provider other than applehv — if 'podman machine start' aborts/crashes, set [machine] provider = \"applehv\"" >&2
    fi
    return 0
  fi
  printf '\n[machine]\nprovider = "applehv"\n' >> "$conf_file"
  echo "podman: ensured provider=applehv in $conf_file (default libkrun provider aborts on some Macs)"
}

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
      echo "podman: Homebrew not found — installing a vendored podman (no package manager/admin rights needed)"
      install_vendored_podman
    fi
  fi

  ensure_applehv_provider

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

install_podman_linux() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y podman
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y podman
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm podman
  else
    echo "no supported package manager found (need apt-get, dnf, or pacman)" >&2
    return 1
  fi
}

ensure_cmd podman install_podman_linux
echo "podman installed: $(podman --version)"

# Tier-2 (container-per-app) support needs a running podman API socket —
# see bootstrap/lib/podman_socket.sh for why this can't just check one
# fixed path (rootful vs rootless, systemd-as-init vs not, all change where
# it lives and how it comes up).
# shellcheck source=../lib/podman_socket.sh
source "$SCRIPT_DIR/../lib/podman_socket.sh"
if sock="$(ensure_podman_socket)"; then
  echo "podman: API socket ready at $sock (Tier-2 app containers enabled)"
else
  echo "podman: could not bring up an API socket — Tier-2 app containers will be unavailable" >&2
fi
