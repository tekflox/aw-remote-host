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
  if [ "$(uname -s)" != "Linux" ]; then
    echo "vpn: advertising an exit node needs kernel IP forwarding, which this module only knows how to enable on Linux — $(uname -s) is untested and deliberately not claimed." >&2
    return 1
  fi
  if vpn_is_wsl; then
    echo "vpn: this is a WSL2 distro. It can join the mesh, but its network is NATed again by the Windows host it runs inside, so traffic forwarded through it as an exit gate has not been validated and is not offered." >&2
    return 1
  fi
  return 0
}
