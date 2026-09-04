# Bakes the aw-remote-host CLI into an image and runs `bootstrap-workspace`
# in the foreground, forever, restarting on any exit. Registers this container
# as the "aw" machine in aw-console — the token comes from
# AW_REMOTE_HOST_TOKEN at runtime, nothing is baked in.
#
# This file used to live in agentic-workspace at tools/aw-remote-host/, with a
# build context of that repo's root and `COPY repos/aw-remote-host/ .` reaching
# into this repo for the source. Only the packaging was over there; the code
# was always here. It was moved on 2026-09-04 so the thing that builds this
# binary lives in the repo that owns it, and the build context is now this
# repo — see docs/runbooks/aw-remote-host-image-rebuild.md §3.1.
FROM golang:1.23-alpine AS build

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/aw-remote-host ./cmd/aw-remote-host

# bootstrap-workspace's own install scripts (bootstrap/podman/install.sh
# etc.) are bash scripts that shell out to `sudo apt-get install podman` on
# Linux — they expect a real distro with apt + sudo + bash, not a minimal
# Alpine/busybox image. Debian slim gives them what they need.
FROM debian:bookworm-slim

# procps/psmisc/file are not needed to boot — they are needed to *diagnose*
# this host, and their absence has cost real time. bookworm-slim ships no ps,
# pkill or pgrep at all, so on 2026-08-20 a zombie-process investigation here
# had to find the aw-remote-host pid by walking /proc/*/exe by hand, and an
# earlier `ps -eo stat,comm | grep -c defunct` printed a reassuring "0" that
# was really grep counting the empty output of a `ps: not found`. That is the
# worst failure mode this stack has: a health check that cannot fail. `file`
# is here for the same reason — identifying which binary produced a core dump
# meant hand-parsing the ELF note headers in Python.
#   procps  ps, pkill, pgrep, top, free, vmstat
#   psmisc  pstree, killall, fuser  (pstree is how you see what reparented to PID 1)
#   file    identify a core dump / unknown binary
#
# iproute2/wireguard-tools/openvpn are what the external-VPN dialer needs to
# exist AT ALL on this host: internal/ops shells out to `ip`, `wg`,
# `wg-quick` and `openvpn` to bring a provider tunnel up inside this
# container's netns and to route the podman bridges through it. Without them
# ops_vpn_external reports "supported": false and the feature is inert — and
# installing them by hand into the running container is lost on the next
# recreate, which is the whole reason they are baked here instead. Measured
# 2026-09-03: 12 packages, 6.5 MB total, and none pulls systemd, dbus or
# python.
#   iproute2         ip (route/rule/link) — also what discover_bridge() reads
#   wireguard-tools  wg, wg-quick
#   openvpn          the other provider protocol
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates bash sudo curl procps psmisc file \
      iproute2 wireguard-tools openvpn && \
    rm -rf /var/lib/apt/lists/*

# tailscale, baked in rather than installed at runtime. This container is the
# `aw` workspace's host, and the exit-gate feature routes a host's CONTAINERS
# through a gate — which needs a mesh client HERE, on the machine that owns the
# podman bridges, not in the containers being routed. It cannot be installed by
# hand into the running container either: that is lost on the next deploy, and
# the whole point of this line is that it is not.
#
# The apt repository rather than tailscale.com/install.sh (which the vpn
# bootstrap module uses at runtime): install.sh ends in `systemctl enable`, and
# there is no systemd here — entrypoint.sh supervises tailscaled instead. apt
# also resolves the architecture itself, so this still builds on arm64.
#
# `tailscale` brings a systemd unit along with the binaries. Nothing starts it
# and nothing can; it is inert, and removing it would be a change to an
# upstream package for no gain.
RUN curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg \
      > /usr/share/keyrings/tailscale-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian bookworm main" \
      > /etc/apt/sources.list.d/tailscale.list && \
    apt-get update && apt-get install -y --no-install-recommends tailscale && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/aw-remote-host /usr/local/bin/aw-remote-host
COPY entrypoint.sh /entrypoint.sh
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

ENV HOME=/home/aw-remote-host
RUN mkdir -p "$HOME"

ENTRYPOINT ["/entrypoint.sh"]
