#!/usr/bin/env bash
# Exit 0 if this node is already enrolled in the tenant mesh the way the
# environment asks for. This is the idempotency check the bootstrap runner
# uses to decide whether install.sh needs to run at all, so it has to be
# strict about the things a re-run would change and quiet about the rest.
#
# Reads the same env vars as install.sh; every one of them is optional here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/vpn.sh
source "$SCRIPT_DIR/../lib/vpn.sh"

if ! command -v tailscale >/dev/null 2>&1; then
  echo "vpn: tailscale is not installed" >&2
  exit 1
fi

STATUS_JSON="$(tailscale status --json 2>/dev/null || true)"
if [ -z "$STATUS_JSON" ]; then
  echo "vpn: 'tailscale status' returned nothing — is tailscaled running?" >&2
  exit 1
fi

COMPACT="$(printf '%s' "$STATUS_JSON" | tr -d ' \n')"
if ! printf '%s' "$COMPACT" | grep -q '"BackendState":"Running"'; then
  state="$(printf '%s' "$COMPACT" | grep -o '"BackendState":"[^"]*"' | head -1)"
  echo "vpn: node is not up (${state:-BackendState unknown})" >&2
  exit 1
fi

# Enrolled, but to the RIGHT control plane? A node pointed at a different
# headscale is a node in someone else's mesh — reporting it healthy because
# tailscaled happens to be running would be exactly the wrong answer.
if [ -n "${AW_VPN_LOGIN_SERVER:-}" ]; then
  want="${AW_VPN_LOGIN_SERVER%/}"
  have="$(tailscale debug prefs 2>/dev/null | grep -o '"ControlURL": *"[^"]*"' | head -1 | sed 's/.*"ControlURL": *"//;s/"$//')"
  have="${have%/}"
  if [ -z "$have" ]; then
    echo "vpn: could not read this node's ControlURL from 'tailscale debug prefs'" >&2
    exit 1
  fi
  if [ "$have" != "$want" ]; then
    echo "vpn: node is enrolled against $have, not $want" >&2
    exit 1
  fi
fi

# The exit-node REQUEST, checked the same way. Note what is deliberately not
# checked: whether the route was APPROVED. Approval is a headscale admin's
# action, so failing here on an unapproved route would put install.sh into a
# loop it can never win. `aw-remote-host status` reports the advertised-but-
# unapproved state instead, where a human reads it.
if [ -n "${AW_VPN_ADVERTISE_EXIT:-}" ]; then
  case "$(printf '%s' "$AW_VPN_ADVERTISE_EXIT" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on)
      # Only demanded on a host install.sh would actually have advertised on.
      # Asking for it on a host the shared rule refuses would fail forever and
      # put the runner into an install/verify loop it cannot win.
      if vpn_exit_eligible 2>/dev/null; then
        if ! tailscale debug prefs 2>/dev/null | tr -d ' \n' | grep -q '"AdvertiseRoutes":\[[^]]*"0.0.0.0/0"'; then
          echo "vpn: node is up but does not advertise an exit route" >&2
          exit 1
        fi
      fi
      ;;
  esac
fi

echo "vpn: healthy — $(tailscale ip -4 2>/dev/null | head -1) on ${AW_VPN_LOGIN_SERVER:-its configured control plane}"
