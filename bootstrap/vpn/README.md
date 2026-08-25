# `vpn` — join this host to the tenant's mesh

Installs tailscale and enrols this machine in **the tenant's own headscale**,
optionally offering it as an exit gate.

This module is **opt-in** (`"optional": true` in `bootstrap/manifest.json`).
A plain `bootstrap-workspace --with-workspace` never runs it: joining a
network is a decision the machine's owner makes, not a side effect of
provisioning a workspace. It runs when something names it — the
`aw-remote-host vpn` command, or a control-plane bootstrap that asks for it.

## What it does, and the line it does not cross

It installs the client, starts the daemon, runs `tailscale up` against the
login server you give it, and — if asked — adds `--advertise-exit-node`.

It **never selects an exit node**, and nothing it does changes this
machine's default route. That is phase 2, and the boundary is not
bureaucratic:

> The `/link` tunnel is the only remote-management path a BYOD host has. If
> the default route moves onto a mesh that is misconfigured or whose exit
> gate is down, the machine loses internet, the tunnel drops, and the "turn
> the VPN off" button travels over that same tunnel. There is already a
> recorded accident of exactly this shape in this repo — see the long
> comment at `bootstrapWorkspaceSelfHeal`'s call site in
> `cmd/aw-remote-host/commands.go`, where a synchronous bootstrap failure
> left a workspace stranded with no way back except SSH.

`--advertise-exit-node` is inside the line because *advertising* provably
does not change the advertiser's own routing — confirmed on the production
bare-metal on 2026-08-25. Two further things follow from that, and both are
reported rather than assumed:

- Advertising is not the same as being usable. A headscale admin still has
  to approve the `0.0.0.0/0` route. Until then the node offers nothing;
  `aw-remote-host status` says so explicitly.
- `--accept-routes` and `--accept-dns` are both set to **false** explicitly,
  overriding tailscale's own defaults. Accepting routes would let another
  node change where this machine's traffic goes; accepting DNS would rewrite
  its resolver, which is the same lockout failure arriving through DNS
  instead of through routing. `AW_VPN_ACCEPT_DNS=1` opts into MagicDNS
  deliberately.

## Input

| Env var | Required | Meaning |
|---|---|---|
| `AW_VPN_LOGIN_SERVER` | yes | The tenant's headscale, e.g. `https://headscale.aw.tekflox.com`. Never defaulted, never hardcoded. |
| `AW_VPN_AUTHKEY` | first enrolment | A headscale pre-auth key. Not needed once the node is already up against the same server. Consumed by `tailscale up` and never written to disk. |
| `AW_VPN_HOSTNAME` | no | Node name in the mesh. Defaults to this machine's hostname. |
| `AW_VPN_ADVERTISE_EXIT` | no | `1`/`true`/`yes` to offer this node as an exit gate. Linux only. |
| `AW_VPN_ACCEPT_DNS` | no | `1`/`true`/`yes` to accept MagicDNS. Off by default — see above. |

`AW_VPN_LOGIN_SERVER` has no default on purpose. The architecture is **one
headscale per tenant**: two headscale instances do not federate, so nodes
registered against different control planes cannot see each other at all.
That makes tenant isolation a property of the topology rather than a matter
of getting an ACL right — and a hardcoded fallback control plane would quietly
undo it.

## What gets installed, and from where

| Platform | How |
|---|---|
| Linux (incl. WSL2) | `https://tailscale.com/install.sh`, which sets up tailscale's own signed apt/dnf repository for the distro; daemon via systemd. |
| macOS | `brew install tailscale` + `sudo tailscaled install-system-daemon`. |

The Linux path is the **one place in this repo that runs an upstream
installer** rather than naming a package in the distro's own repositories.
It is disclosed in `bootstrap/manifest.json`'s `source` field, so
`--plan` and an audit of the manifest both surface it, per the root README's
transparency contract. It is used because tailscale is not in any distro's
repositories: the alternative is this module hand-rolling the per-distro
repository and codename setup that `install.sh` already does, and getting it
wrong on a release tailscale has not published for yet.

## Eligibility — refuse with a reason, never install halfway

The real work of this module is `internal/vpn`'s probe, in the spirit of
`internal/hostpower.Resolve()`. Three cases, all measured on real hosts on
2026-08-25:

| Host | Verdict |
|---|---|
| Linux + root (`aw-baremetal`, uid 0, `/dev/net/tun`, systemd) | joins, and may advertise as exit node |
| WSL2 + root (`aw-surface-wsl`, uid 0, passwordless sudo, systemd on) | joins; **refused as an exit gate** — its network is NATed again by the Windows host, and forwarding through that has not been validated |
| macOS without sudo (`Mac.Home`, uid 503) | **refused entirely** — `sudo -n` fails so `tailscaled install-system-daemon` cannot run, and `/opt/homebrew` belongs to another account so `brew install` fails on permissions |

The macOS refusal is the one that matters most, because the failure it
prevents is silent. Without root, tailscaled can still start with
`--tun=userspace-networking` — which yields a SOCKS5/HTTP proxy and **not** a
network interface. A host installed that way looks enrolled and carries none
of its own traffic. On that same machine `tailscale set` answers `Access
denied: checkprefs access denied`.

## Verify

`verify.sh` exits 0 only when the node is `BackendState=Running` **against
the login server that was asked for**. It deliberately does not check whether
the exit route was approved — that is an admin action elsewhere, and failing
on it would put `install.sh` into a loop it cannot win.

## Status

`aw-remote-host status` reports the node name, the mesh IP, the tailnet, and
for every peer whether the path is **direct or relayed**. That last one is
not decoration. Measured 2026-08-25: `aw-mac` and `aw-surface-wsl` are on the
same home network behind the same public IP and still talk `via DERP(mad)`,
because the Surface is WSL2 and sits behind a second layer of NAT — `direct
connection not established`. A relay is not a rare fallback, it is a normal
outcome, and without this field "it works, but every packet goes to Madrid
and back" is invisible.
