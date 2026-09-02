#!/bin/sh
# Install aw-remote-host: downloads a pinned release binary from GitHub
# Releases, verifies its SHA-256 checksum against the release's published
# checksums.txt, and installs it to ~/.local/bin.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh
#   curl -fsSL .../install.sh | AW_REMOTE_HOST_VERSION=v0.1.0 sh   # pin a version
#   curl -fsSL .../install.sh | AW_REMOTE_HOST_FORCE=1 sh          # reinstall anyway
set -eu

REPO="tekflox/aw-remote-host"
VERSION="${AW_REMOTE_HOST_VERSION:-latest}"
INSTALL_DIR="${AW_REMOTE_HOST_INSTALL_DIR:-$HOME/.local/bin}"

if [ "$VERSION" = "latest" ]; then
  VERSION="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
      sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
      head -n 1
  )"
  if [ -z "$VERSION" ]; then
    echo "aw-remote-host: could not resolve latest release" >&2
    exit 1
  fi
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "aw-remote-host: unsupported architecture $arch" >&2; exit 1 ;;
esac

case "$os" in
  linux|darwin) ;;
  *) echo "aw-remote-host: unsupported OS $os" >&2; exit 1 ;;
esac

# Already at the pinned version? Then there is nothing to do, and saying so
# is the answer — not a download that produces a byte-identical file.
#
# This sits AFTER `latest` has been resolved to a tag, because "latest" is
# not a version you can compare against, and BEFORE the download, because
# skipping the work is the whole point.
#
# It compares the binary ON DISK, which is not necessarily the one RUNNING:
# a process started before an earlier install keeps its old image (readlink
# /proc/<pid>/exe shows a `(deleted)` suffix) until whatever supervises it
# restarts it. This script installs; it does not restart anything, and it
# must not claim otherwise.
#
# AW_REMOTE_HOST_FORCE=1 reinstalls regardless — for a binary that is the
# right version and the wrong bytes (truncated download, corrupted disk).
if [ -z "${AW_REMOTE_HOST_FORCE:-}" ] && [ -x "${INSTALL_DIR}/aw-remote-host" ]; then
  installed=$("${INSTALL_DIR}/aw-remote-host" version 2>/dev/null || true)
  if [ "$installed" = "$VERSION" ]; then
    echo "aw-remote-host: already at ${VERSION} in ${INSTALL_DIR} — nothing to do"
    echo "note: this checks the binary on disk, not a running process — restart the service to pick it up"
    echo "note: set AW_REMOTE_HOST_FORCE=1 to reinstall anyway"
    exit 0
  fi
fi

asset="aw-remote-host_${VERSION}_${os}_${arch}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "aw-remote-host: downloading ${asset} (${VERSION})"
curl -fsSL "${base_url}/${asset}" -o "${tmpdir}/${asset}"
curl -fsSL "${base_url}/checksums.txt" -o "${tmpdir}/checksums.txt"

echo "aw-remote-host: verifying checksum"
(cd "$tmpdir" && grep " ${asset}\$" checksums.txt | sha256sum -c -)

echo "aw-remote-host: installing to ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"
tar -xzf "${tmpdir}/${asset}" -C "$tmpdir" aw-remote-host
install -m 0755 "${tmpdir}/aw-remote-host" "${INSTALL_DIR}/aw-remote-host"

echo "aw-remote-host: installed $("${INSTALL_DIR}/aw-remote-host" version)"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "note: ${INSTALL_DIR} is not on your PATH — add it to use 'aw-remote-host' directly" ;;
esac
