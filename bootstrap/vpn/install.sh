#!/usr/bin/env bash
# Install tailscale and enrol this node in the tenant's headscale. Idempotent.
#
# ENROLMENT ONLY. This script joins a mesh and may OFFER this node as an exit
# gate. It never selects one, and it never changes this machine's default
# route — see bootstrap/vpn/README.md for why that boundary is drawn in ink.
# Selecting a gate is `aw-remote-host vpn use-exit`, a deliberate command with
# exclusions, a dead-man's switch and a confirmation step; a bootstrap module
# that could strand the host it is provisioning would be exactly backwards.
#
# Input, all by environment variable like every other module:
#   AW_VPN_LOGIN_SERVER    required — the tenant's headscale, e.g.
#                          https://headscale.aw.tekflox.com
#   AW_VPN_AUTHKEY         required on first enrolment — a headscale pre-auth
#                          key. Not needed once this node is already up
#                          against the same login server.
#   AW_VPN_HOSTNAME        optional — node name in the mesh (default: hostname)
#   AW_VPN_ADVERTISE_EXIT  optional — 1/true/yes to offer this node as an exit
#                          gate. Still needs a headscale admin to approve the
#                          0.0.0.0/0 route before anyone can select it.
#   AW_VPN_ACCEPT_DNS      optional — 1/true/yes to accept MagicDNS. OFF by
#                          default: accepting DNS rewrites this host's
#                          resolver, so a headscale that misbehaves stops the
#                          machine resolving the control plane. That is the
#                          lockout failure mode arriving through DNS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/vpn.sh
source "$SCRIPT_DIR/../lib/vpn.sh"

LOGIN_SERVER="${AW_VPN_LOGIN_SERVER:-}"
AUTHKEY="${AW_VPN_AUTHKEY:-}"
NODE_HOSTNAME="${AW_VPN_HOSTNAME:-$(hostname -s 2>/dev/null || hostname)}"

truthy() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -z "$LOGIN_SERVER" ]; then
  echo "vpn: AW_VPN_LOGIN_SERVER is required — this module never defaults or hardcodes a control plane, because the architecture is one headscale per tenant (two headscales do not federate, which is what makes tenant isolation structural instead of a matter of getting an ACL right)." >&2
  exit 1
fi

# sudo_if_needed keeps the script readable on both kinds of host: the rootful
# install runs as uid 0 with no sudo in the picture, and the rootless one has
# a NOPASSWD sudoers entry. `sudo -n` never prompts, so a host with neither
# fails here fast and loudly rather than hanging on a password prompt nobody
# is watching (this runs from a systemd unit).
SUDO=""
if [ "$(id -u)" != "0" ]; then
  if sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  else
    echo "vpn: not running as root and 'sudo -n true' fails, so tailscaled cannot be installed as a system daemon." >&2
    echo "vpn: without root, tailscaled only runs with --tun=userspace-networking, which gives a SOCKS5/HTTP proxy and NOT a network interface — the node would look enrolled while carrying none of this machine's traffic. Refusing rather than half-installing." >&2
    exit 1
  fi
fi

install_tailscale_linux() {
  if [ ! -e /dev/net/tun ]; then
    echo "vpn: /dev/net/tun is not present, so tailscaled has no way to create the mesh interface (try 'modprobe tun', or pass the device through if this is a container)." >&2
    return 1
  fi
  if [ ! -d /run/systemd/system ]; then
    echo "vpn: systemd is not PID 1 here, and this module has no other way to keep tailscaled running." >&2
    if grep -qi microsoft /proc/version 2>/dev/null; then
      echo "vpn: this looks like a WSL2 distro — add '[boot]' + 'systemd=true' to /etc/wsl.conf, run 'wsl --shutdown' from Windows, and re-run." >&2
    fi
    return 1
  fi
  if ! command -v tailscale >/dev/null 2>&1; then
    # The upstream installer, which is what tailscale documents and what
    # handles the per-distro apt/dnf/yum repository setup and codename
    # fallbacks. It is named in bootstrap/manifest.json's "source" field so it
    # is disclosed where the README's transparency contract promises it will
    # be, rather than only buried in this script.
    echo "vpn: installing tailscale from https://tailscale.com/install.sh"
    curl -fsSL https://tailscale.com/install.sh | $SUDO sh
  fi
  $SUDO systemctl enable --now tailscaled
}

install_tailscale_darwin() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "vpn: Homebrew is not installed and this module has no vendored macOS tailscale to fall back on. Install Homebrew, or install tailscale by hand from https://tailscale.com/download/mac and re-run." >&2
    return 1
  fi
  if ! command -v tailscale >/dev/null 2>&1; then
    # Measured on Mac.Home 2026-08-25: /opt/homebrew is owned by a different
    # account than the one aw-remote-host runs as, so this fails on
    # permissions. Let it fail with brew's own message — it names the path.
    brew install tailscale
  fi
  # macOS has no systemd. The Homebrew formula ships the binaries but not a
  # privileged helper, and without the system daemon `tailscale up`/`set`
  # answer "Access denied: checkprefs access denied".
  if ! $SUDO launchctl print system/com.tailscale.tailscaled >/dev/null 2>&1; then
    $SUDO tailscaled install-system-daemon
  fi
}

case "$(uname -s)" in
  Linux) install_tailscale_linux ;;
  Darwin) install_tailscale_darwin ;;
  *)
    echo "vpn: $(uname -s) is not a platform this module knows how to install tailscale on — only Linux and macOS are supported." >&2
    exit 1
    ;;
esac

# --- enrol ------------------------------------------------------------------

UP_ARGS=(
  "--login-server=$LOGIN_SERVER"
  "--hostname=$NODE_HOSTNAME"
  # The two flags that make this phase-1 safe, set EXPLICITLY rather than left
  # to tailscale's defaults, because tailscale's defaults are to accept both.
  #   --accept-routes=false : no subnet route another node advertises gets
  #                           installed here, so nothing this machine already
  #                           reaches changes destination.
  #   --accept-dns          : off unless AW_VPN_ACCEPT_DNS opts in (see header).
  "--accept-routes=false"
  # Never --exit-node. Selecting an exit node is the step that can strand a
  # host — the /link tunnel is the only remote-management path, so a broken
  # default route takes the fix down with the machine — and it belongs to
  # `aw-remote-host vpn use-exit`, which owns the safety machinery for it.
  "--reset"
)

if truthy "${AW_VPN_ACCEPT_DNS:-}"; then
  UP_ARGS+=("--accept-dns=true")
else
  UP_ARGS+=("--accept-dns=false")
fi

ADVERTISE_EXIT=0
if truthy "${AW_VPN_ADVERTISE_EXIT:-}"; then
  # Same rule verify.sh applies, from the same function — see
  # bootstrap/lib/vpn.sh for why two copies of it would deadlock the module.
  if vpn_exit_eligible; then
    ADVERTISE_EXIT=1
  else
    echo "vpn: enrolling as a plain mesh node instead." >&2
  fi
fi

if [ "$ADVERTISE_EXIT" = "1" ]; then
  # An exit node forwards other nodes' packets, which the kernel drops unless
  # forwarding is on. Written to a drop-in so it survives a reboot — unlike
  # the host firewall (tools/host-firewall/), where NOT persisting is the
  # deliberate emergency exit. The difference is blast radius: ip_forward on a
  # machine nobody selects as an exit node changes nothing about its own
  # traffic.
  echo "vpn: enabling IP forwarding (required to serve as an exit node)"
  case "$(uname -s)" in
    Darwin)
      # Different knobs and a different file. macOS has no /etc/sysctl.d, and
      # /etc/sysctl.conf is SHARED — so this merges the two keys in rather
      # than overwriting, because discarding somebody's other kernel settings
      # to turn on forwarding would be a second, unasked-for change to their
      # machine. Written through a temp file: `cat f | ... > f` truncates f
      # before cat opens it. Mirrors internal/vpn's forwardingFor("darwin").
      $SUDO /bin/sh -c '{ cat /etc/sysctl.conf 2>/dev/null | grep -v "^net\.inet\.ip\.forwarding=" | grep -v "^net\.inet6\.ip6\.forwarding="; printf "net.inet.ip.forwarding=1\nnet.inet6.ip6.forwarding=1\n"; } > /etc/sysctl.conf.aw-new && mv /etc/sysctl.conf.aw-new /etc/sysctl.conf'
      $SUDO sysctl -w net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null
      ;;
    *)
      printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' \
        | $SUDO tee /etc/sysctl.d/99-aw-vpn-exit-node.conf >/dev/null
      $SUDO sysctl -p /etc/sysctl.d/99-aw-vpn-exit-node.conf >/dev/null
      ;;
  esac
  UP_ARGS+=("--advertise-exit-node")
fi

if [ -n "$AUTHKEY" ]; then
  UP_ARGS+=("--authkey=$AUTHKEY")
fi

echo "vpn: enrolling '$NODE_HOSTNAME' against $LOGIN_SERVER (advertise-exit=$ADVERTISE_EXIT)"
# The key is in the argv of this one call and nowhere else — not echoed above,
# not written to state.
$SUDO tailscale up "${UP_ARGS[@]}"

echo "vpn: waiting for the node to come up..."
for _ in $(seq 1 30); do
  # Whitespace stripped first so the match doesn't depend on how tailscale
  # happens to indent its JSON this release.
  if tailscale status --json 2>/dev/null | tr -d ' \n' | grep -q '"BackendState":"Running"'; then
    echo "vpn: enrolled as '$NODE_HOSTNAME' — mesh IP $(tailscale ip -4 2>/dev/null | head -1)"
    if [ "$ADVERTISE_EXIT" = "1" ]; then
      echo "vpn: this node now OFFERS itself as an exit node. It carries no other node's traffic until a headscale admin approves its 0.0.0.0/0 route, and selecting it is a separate, phase-2 action on the client side."
    fi
    exit 0
  fi
  sleep 1
done

echo "vpn: tailscaled did not reach BackendState=Running in time" >&2
tailscale status 2>&1 | head -20 >&2
exit 1
