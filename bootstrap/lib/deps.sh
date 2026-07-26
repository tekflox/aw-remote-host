#!/usr/bin/env bash
# Shared dependency-resolution helpers, sourced by module install.sh scripts
# that need to install a prerequisite without relying on the user's own
# package manager (no brew/apt/etc available). See bootstrap/lib/README.md
# for the extension contract — bootstrap/podman/install.sh is the reference
# consumer (vendored podman on a brew-less macOS).
#
# Not meant to be executed directly — only sourced.

# ensure_cmd <cmd> <installer_fn>
#
# Runs <installer_fn> (a shell function name, already defined by the
# caller) only if <cmd> isn't already on PATH. No-ops otherwise, so this is
# safe to call unconditionally at the top of a module's install.sh.
ensure_cmd() {
  local cmd="$1"
  local installer_fn="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  "$installer_fn"
}

# fetch_and_extract_pkg <url> <payload_dir_name> <dest_parent_dir>
#
# Downloads a macOS .pkg installer from <url> and extracts it WITHOUT sudo
# or admin rights via `pkgutil --expand-full`, then locates a directory
# named <payload_dir_name> anywhere inside the expanded payload and copies
# it to <dest_parent_dir>/<payload_dir_name> (replacing any prior copy).
#
# This is the "vendored binary" pattern for prerequisites macOS normally
# expects Homebrew to install: no package manager, no privilege escalation,
# just a pinned download + local extraction into the user's own home dir.
fetch_and_extract_pkg() {
  local url="$1"
  local payload_dir_name="$2"
  local dest_parent_dir="$3"

  local tmpdir
  tmpdir="$(mktemp -d)"

  echo "deps: downloading $url"
  curl -fsSL "$url" -o "$tmpdir/pkg.pkg"

  echo "deps: expanding pkg (pkgutil --expand-full, no sudo/admin needed)"
  local expanded="$tmpdir/expanded"
  pkgutil --expand-full "$tmpdir/pkg.pkg" "$expanded"

  local found
  found="$(find "$expanded" -type d -name "$payload_dir_name" -print -quit)"
  if [ -z "$found" ]; then
    echo "deps: couldn't find a '$payload_dir_name' directory inside the expanded pkg payload" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  mkdir -p "$dest_parent_dir"
  rm -rf "${dest_parent_dir:?}/$payload_dir_name"
  cp -R "$found" "$dest_parent_dir/"
  rm -rf "$tmpdir"
  echo "deps: extracted $payload_dir_name -> $dest_parent_dir/$payload_dir_name"
}
