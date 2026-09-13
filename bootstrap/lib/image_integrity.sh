#!/usr/bin/env bash
# An image can be PRESENT, CURRENT, and still extracted wrong.
#
# THE INCIDENT (2026-09-12/13, workspace `crispal`): two separate failures,
# one root cause.
#
#   sudo: /usr/bin/sudo must be owned by uid 0 and have the setuid bit set
#   apache2: could not open error log file /var/log/apache2/error.log
#
# The first broke every app installer that shells out to sudo. The second
# crash-looped any container using the /dev/stderr logging convention the
# official nginx/httpd/wordpress images all use. Measured side by side:
#
#   hosted workspace:  /usr/bin/sudo      mode=755   (setuid GONE)
#   BYOD workspace:    /usr/bin/sudo      mode=4755
#   hosted workspace:  /var/log/apache2   uid=0      (should be 33)
#   BYOD workspace:    /var/log/apache2   uid=33
#
# Same image, same digest, same file size and mtime. What differed was the
# EXTRACTION: inside a userns-remapped host, a chown by a process that is not
# real root clears setuid/setgid bits, and ownership can land wrong. Removing
# the image and pulling it again produced a correct layer both times.
#
# Why nothing caught it: every check upstream asks whether the image is THERE
# (`podman image exists`) or whether the tag is CURRENT (lib/image.sh). Both
# answer yes for a layer that is silently wrong — the same "existence read as
# health" mistake this codebase keeps making, applied to file metadata.
#
# The setuid bit on sudo is the canary, not the only casualty: it is a single
# cheap probe that goes wrong exactly when the extraction did.

# image_layer_intact <image> -- true when the extracted layer kept its
# setuid metadata. A container that cannot run the probe is NOT treated as
# broken: refusing to boot a host over a check that could not be performed
# would be worse than the fault it looks for.
image_layer_intact() {
  local image="$1" mode
  mode="$(podman run --rm --entrypoint "" "$image" \
            stat -c '%a' /usr/bin/sudo 2>/dev/null | tr -d '[:space:]')" || return 0
  [ -z "$mode" ] && return 0          # no sudo in this image — nothing to judge
  case "$mode" in
    4*) return 0 ;;                   # setuid present
    *)  return 1 ;;
  esac
}

# repair_image_layer <image> [pull args...] -- re-extract a bad layer.
#
# `podman pull` alone does NOT fix this: the digest is already local, so the
# pull is a no-op and the bad layer stays. The image has to be REMOVED first,
# which is why this exists as its own step rather than another retry.
repair_image_layer() {
  local image="$1"; shift
  echo "workspace: image layer for $image lost its setuid metadata — re-extracting" >&2
  podman rmi -f "$image" >/dev/null 2>&1 || true
  if ! podman pull "$@" "$image" >/dev/null 2>&1; then
    echo "workspace: WARNING could not re-pull $image after removing it — this host" \
         "now has NO copy. Check registry reachability." >&2
    return 1
  fi
  if image_layer_intact "$image"; then
    echo "workspace: image layer re-extracted cleanly"
    return 0
  fi
  echo "workspace: WARNING $image STILL has no setuid on /usr/bin/sudo after a" \
       "clean re-pull — sudo will not work in this workspace and app installers" \
       "that use it will fail. This is not a stale layer; look at the host's" \
       "userns/subuid setup." >&2
  return 1
}
