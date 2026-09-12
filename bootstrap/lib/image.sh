#!/usr/bin/env bash
# "Do we have the image?" is not the same question as "do we have the image
# the tag points at right now?"
#
# THE INCIDENT THIS EXISTS TO PREVENT (2026-09-12): workspace/install.sh
# recreated the workspace container with
#
#     if podman image exists "$IMAGE"; then
#       echo "workspace: using existing local image $IMAGE"
#     else
#       podman pull "$IMAGE"
#     fi
#
# and $IMAGE defaults to ghcr.io/fredericowu/aw-workspace:LATEST. On a host
# that pulled :latest once, every later recreate — including the one the
# Update button triggers — rebuilt the container from the cached copy and
# reported success. The workspace kept running an image from weeks ago while
# the control plane, the log and the operator all believed it had just been
# updated. That is how "atualizei a remote-host e workspace, eles nao estao
# vindo com docker e podman" happened: the update was real, the image was not.
#
# It is the same bug this codebase keeps re-learning in new clothes —
# existence read as health. `podman ps` said Up for a dead PID; `redis-cli
# PING` exited 0 while answering LOADING; a socket file existed with nothing
# behind it. A cached image present, read as a cached image current, is that
# bug applied to bytes on disk.
#
# The distinction that fixes it is in the reference itself. A digest pin
# (name@sha256:...) names exactly one immutable manifest: if it is local, it
# is by definition current, and re-pulling it can only spend bandwidth to
# arrive at the identical bytes. Every other form — :latest, :v0.1.107, a
# bare name — is a POINTER the registry may move under us, so the only honest
# answer is to ask the registry.
#
# A failed pull is not fatal. A host that is offline, or a registry that is
# down, must still bring the workspace up on whatever it already has — the
# alternative is an outage caused by the update check rather than by the
# update. So the fallback is deliberate, and it SAYS SO, because a silent
# fallback here would recreate the exact failure above.

# image_is_pinned <ref> -- true when the reference names an immutable digest.
image_is_pinned() {
  case "$1" in
    *@sha256:*) return 0 ;;
    *) return 1 ;;
  esac
}

# ensure_image_current <ref> <label> [pull args...]
#
# Leaves the local store holding what <ref> resolves to NOW, and prints what
# it did. Never fails the caller: a host with no network still boots.
ensure_image_current() {
  local ref="$1" label="$2"
  shift 2

  if image_is_pinned "$ref"; then
    if podman image exists "$ref"; then
      echo "${label}: image pinned by digest and already local — $ref"
      return 0
    fi
    podman pull "$@" "$ref" >/dev/null && {
      echo "${label}: pulled pinned image $ref"; return 0; }
    echo "${label}: WARNING could not pull pinned image $ref" >&2
    return 1
  fi

  # Moving reference: ask the registry every time, cache or no cache.
  if podman pull "$@" "$ref" >/dev/null 2>&1; then
    echo "${label}: refreshed moving tag $ref"
    return 0
  fi

  if podman image exists "$ref"; then
    echo "${label}: WARNING pull of moving tag $ref failed — falling back to" \
         "the local copy, which may be STALE" >&2
    return 0
  fi

  echo "${label}: ERROR pull of $ref failed and no local copy exists" >&2
  return 1
}
