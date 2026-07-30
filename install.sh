#!/bin/sh
# Install aw-remote-host: downloads a pinned release binary from GitHub
# Releases, verifies its SHA-256 checksum against the release's published
# checksums.txt, and installs it to ~/.local/bin.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh
#   curl -fsSL .../install.sh | AW_REMOTE_HOST_VERSION=v0.1.0 sh   # pin a version
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
