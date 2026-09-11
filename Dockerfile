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

# Stamp the version, exactly as release.yml's binary builds already do
# (-X main.version=...). Without this every image-born binary reports "dev",
# and "dev" is not cosmetic: internal/state/state.go short-circuits both
# RecordBootstrapVersion and CheckDowngrade on it, so an unstamped image can
# never record what it bootstrapped and the downgrade guard can never fire.
# It also makes the container the only one of the four host forms whose
# reported version is a lie. Defaults to "dev" so a local `docker build` with
# no --build-arg still works; release.yml passes the real vX.Y.Z.
ARG AW_REMOTE_HOST_VERSION=dev
RUN CGO_ENABLED=0 go build \
      -ldflags "-X main.version=${AW_REMOTE_HOST_VERSION}" \
      -o /out/aw-remote-host ./cmd/aw-remote-host

# bootstrap-workspace's own install scripts (bootstrap/podman/install.sh
# etc.) are bash scripts that shell out to `sudo apt-get install podman` on
# Linux — they expect a real distro with apt + sudo + bash, not a minimal
# Alpine/busybox image. Debian slim gives them what they need.
#
# WHY trixie AND NOT bookworm: podman IS baked into this image (below), from
# this suite, so the podman version this host runs is a property of THIS LINE.
# bookworm offers only 4.3.1; trixie offers 5.4.2,
# which is where `podman network update` arrives — the verb the external-VPN
# dialer needs to redirect a RUNNING container's resolver instead of having
# to recreate it. Measured 2026-09-08: bookworm-backports ships no podman
# package at all, Kubic's Debian_12 suite ships an OLDER 3.4.2, and pinning
# trixie's .deb into bookworm needs libc6 >= 2.38 against bookworm's 2.36 —
# a glibc bump plus the whole 64-bit-time_t transition, i.e. a distro upgrade
# in place. The base image is the only lever. See
# docs/runbooks/podman-5-upgrade-aw-remote-host.md.
FROM debian:trixie-slim

# procps/psmisc/file are not needed to boot — they are needed to *diagnose*
# this host, and their absence has cost real time. Debian slim ships no ps,
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
#   git              ops.go's guardHostNotAheadOfImage shells out to `git
#                    rev-parse`/`merge-base` against the host tree bind-mount
#                    to decide whether Update() would silently revert
#                    committed host work — without this binary that check
#                    can't read a host HEAD at all and silently no-ops,
#                    exactly on the containerised host form this ships to.
#   podman           the container runtime this host's whole job is to run
#   catatonit        podman's `--init` pid-1 reaper. Explicit because it is a
#                    RECOMMENDS of podman, not a depends, so
#                    --no-install-recommends above drops it — and the workspace
#                    module creates its container with --init, so without this
#                    every recreate ends in `lookup init binary: exec:
#                    "catatonit": executable file not found in $PATH` and the
#                    workspace never comes back. It arrived for free while
#                    podman was apt-installed at runtime (where recommends were
#                    on), which is exactly the kind of invisible dependency
#                    baking a package into an image has to make explicit.
#
# WHY podman IS BAKED IN (2026-09-11). It used to be installed at RUNTIME by
# bootstrap/podman/install.sh (`apt-get install -y podman`), which put the
# binary in this container's own writable layer — the one thing a recreate
# throws away. The nested containers' DATA survived (it lives under $HOME on a
# volume, see bootstrap/lib/podman_storage.sh) but the runtime that could read
# it did not, so recreating this container for a routine image bump left the
# `aw` workspace with `podman: not found`, ~50 nested containers unreachable,
# and no way to even DIAGNOSE it from inside. That is an outage caused purely
# by packaging. The entrypoint runs `bootstrap-workspace`, which does NOT run
# the podman module, so nothing put it back either. Same argument that already
# bakes tailscale and the VPN tools below: anything installed by hand into the
# running container is lost on the next recreate.
#
# This does NOT make bootstrap/podman/install.sh dead code — it still runs on
# every non-container host form (BYOD Mac, bare VM), and here its `ensure_cmd
# podman` no-ops the moment podman is on PATH.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates bash sudo curl procps psmisc file git \
      iproute2 wireguard-tools openvpn && \
    rm -rf /var/lib/apt/lists/*

# podman WITH its recommends, deliberately — the only apt line in this file
# that keeps them.
#
# bootstrap/podman/install.sh has always run plain `apt-get install -y podman`
# at runtime, recommends ON, and that is the package set this stack has been
# running on for months. Baking podman in under this file's blanket
# --no-install-recommends quietly installed a DIFFERENT set, and the two
# things it dropped both broke production on the first real recreate
# (2026-09-11):
#
#   catatonit     podman's --init pid-1 reaper. The workspace module creates
#                 its container with --init, so every recreate ended in
#                 `lookup init binary: exec: "catatonit": executable file not
#                 found in $PATH` and the workspace never came back.
#   aardvark-dns  the resolver netavark hands container DNS to, installed to
#                 /usr/lib/podman/ rather than onto PATH (podman looks it up
#                 there itself) — which is why a `command -v` check said it was
#                 fine. Without it
#                 podman warns "container dns will not be enabled" and every
#                 container-name lookup inside the podman network fails —
#                 which is every app in the workspace talking to every other.
#
# Curating a hand-written list of which recommends matter would be the same
# guess that produced this bug, one layer along: the next one nobody thought
# of fails the same silent way. Taking the set the runtime installer takes
# means the image and the BYOD host run the same podman, which is the whole
# contract between this file and that script.
RUN apt-get update && apt-get install -y podman && \
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
RUN curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg \
      > /usr/share/keyrings/tailscale-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian trixie main" \
      > /etc/apt/sources.list.d/tailscale.list && \
    apt-get update && apt-get install -y --no-install-recommends tailscale && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/aw-remote-host /usr/local/bin/aw-remote-host
COPY entrypoint.sh /entrypoint.sh
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

ENV HOME=/home/aw-remote-host
RUN mkdir -p "$HOME"

# Declares which HOST FORM this is, for internal/hostfacts.ContainerForm. It is
# what makes the control plane's "update" recreate this container from a new
# image instead of only replacing the binary inside it — the binary lives in
# this container's writable layer, so on its own it updates the host until the
# next recreate and no further. Set here rather than sniffed at runtime
# (/.dockerenv and friends) because the image is the only thing that knows for
# certain what it is; see that function's comment for what each kind of wrong
# guess costs.
ENV AW_REMOTE_HOST_FORM=container

# Baking the podman BINARY without its CONFIG would be worse than not baking
# it at all. /etc/containers/storage.conf lives in this container's writable
# layer too, so a recreate takes it with everything else — and a podman with
# no storage.conf silently falls back to the package default graphroot,
# /var/lib/containers/storage, which is IN that same disposable layer. That is
# the original 2026-09-02 data-loss incident (see podman_storage.sh's header),
# and baking only the binary would re-arm it for the window between a recreate
# and the next full bootstrap — a window the entrypoint's lean
# `bootstrap-workspace` never closes, because it does not run the podman
# module at all.
#
# Generated by SOURCING the very functions the podman module runs at runtime,
# never by hand-copying their output here. These two files are the contract
# between this image and bootstrap/podman/install.sh: if they ever disagree,
# the first bootstrap after a recreate rewrites the config and takes podman's
# whole view of its storage with it. Sourcing is what makes drift impossible —
# same "one definition, never re-derived inline" rule bootstrap/lib/container.sh
# states for resolve_data_dir.
#
# $HOME is already ENV above, so graphroot resolves to exactly the path the
# runtime call would produce; the guards in both functions then find their own
# output already in place and no-op on every bootstrap forever after.
# Every binary the bootstrap modules shell out to, asserted at BUILD time.
#
# A missing one is invisible until a host is recreated and then fails deep
# inside a module, hours or days later, with an error that names a package
# nobody remembers depending on. catatonit is why this exists: it is a
# RECOMMENDS of podman rather than a depends, so --no-install-recommends
# dropped it, and the first real image-update recreate died on `lookup init
# binary: exec: "catatonit": executable file not found in $PATH` with the
# workspace container unable to come back. It had always been there while
# podman was apt-installed at runtime with recommends on.
#
# Baking a package into an image means owning the dependencies the package
# manager used to infer. This line is that ownership, and it fails the BUILD
# rather than a production recreate.
RUN set -eu; \
    for bin in podman catatonit conmon crun git ip wg openvpn tailscaled ps bash sudo curl; do \
      command -v "$bin" >/dev/null || { echo "image is missing $bin — a bootstrap module shells out to it" >&2; exit 1; }; \
    done; \
    for helper in netavark aardvark-dns; do \
      [ -x "/usr/lib/podman/$helper" ] || { echo "image is missing $helper — podman networking/DNS cannot come up" >&2; exit 1; }; \
    done; \
    echo "image: all bootstrap-required binaries present"

COPY bootstrap/lib/podman_storage.sh /tmp/lib/podman_storage.sh
COPY bootstrap/lib/podman_firewall.sh /tmp/lib/podman_firewall.sh
RUN bash -c '. /tmp/lib/podman_storage.sh  && configure_podman_graphroot /etc/containers/storage.conf "$HOME" && \
             . /tmp/lib/podman_firewall.sh && configure_podman_firewall_driver /etc/containers/containers.conf' && \
    rm -rf /tmp/lib && \
    grep -q "graphroot = \"$HOME/.local/share/containers/storage\"" /etc/containers/storage.conf && \
    grep -q "runroot = \"/run/containers/storage\"" /etc/containers/storage.conf

ENTRYPOINT ["/entrypoint.sh"]
