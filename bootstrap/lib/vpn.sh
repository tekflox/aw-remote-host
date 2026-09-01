#!/usr/bin/env bash
# Shared exit-node eligibility for the vpn module.
#
# install.sh and verify.sh MUST agree about this, and the reason is concrete:
# if install.sh declines to advertise an exit route on a host while verify.sh
# still demands one, the module never converges — verify fails, install runs,
# verify fails again, forever. Two copies of the same rule drift; one function
# does not.
#
# It also has to agree with internal/vpn's Resolve(), which is the gate the
# `aw-remote-host vpn` command applies BEFORE this script ever runs. When the
# module is driven the other way — straight from the control plane, with no Go
# gate in front of it — this is the only check there is. Caught live on
# 2026-08-25: the Go probe refused a WSL2 node as an exit gate and install.sh
# advertised one anyway, which is precisely the silent disagreement that makes
# a UI list a host as something it is not.

# vpn_is_wsl reports whether this Linux is a WSL2 kernel. Note that a
# container running on a WSL2 host inherits that kernel, so containers there
# answer yes too — which is correct: they sit behind the same extra layer of
# Windows NAT.
vpn_is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null
}

# vpn_exit_eligible reports whether this host may advertise itself as an exit
# gate, printing the reason to stderr when it may not.
vpn_exit_eligible() {
  case "$(uname -s)" in
    Linux) ;;
    Darwin)
      # ALLOWED SINCE 2026-09-01, and internal/vpn's Resolve() changed in the
      # same breath — the two must keep agreeing or the module never
      # converges (see the header). macOS forwards through net.inet.* rather
      # than net.ipv4.*/net.ipv6.*, and install.sh below enables and persists
      # exactly those; there is no /etc/sysctl.d there, so persistence goes
      # to /etc/sysctl.conf, which sysctl.conf(5) says is read when the
      # system goes into multi-user mode.
      #
      # This branch runs under install.sh, which already needs $SUDO on macOS
      # for `tailscaled install-system-daemon` — so the privilege the sysctl
      # needs is the privilege this path already has. A Mac WITHOUT it never
      # reaches here: Resolve() refuses first, naming the command to run.
      return 0
      ;;
    *)
      echo "vpn: advertising an exit node needs kernel IP forwarding, which this module only knows how to enable on Linux and macOS — $(uname -s) is untested and deliberately not claimed." >&2
      return 1
      ;;
  esac
  if vpn_is_wsl; then
    # ALLOWED SINCE 2026-08-26, with the cost printed. This used to return 1,
    # and internal/vpn's Resolve() has been changed in the same breath — the
    # two must keep agreeing or the module never converges (see the header).
    # The reason for the change is in Resolve()'s WSL branch: a refusal left
    # the only machine that could be a second gate permanently out, on the
    # grounds that it had not been measured.
    echo "vpn: WARNING — this is a WSL2 distro. It can forward, but its network is NATed again by the Windows host it runs inside, so everything routed through it leaves via that machine's own connection, through a public relay rather than a direct path." >&2
    return 0
  fi
  return 0
}
