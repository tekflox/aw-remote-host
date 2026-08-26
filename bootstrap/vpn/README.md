# `vpn` — join this host to the tenant's mesh

Installs tailscale and enrols this machine in **the tenant's own headscale**,
optionally offering it as an exit gate — and, since phase 2, selecting one.

| Command | Touches the default route? |
|---|---|
| `aw-remote-host vpn --login-server=…` | no — enrolment only (phase 1) |
| `aw-remote-host vpn --advertise-exit-node` | no — *offering* is not *using* |
| **`aw-remote-host vpn use-exit <node>`** | **REFUSED — see "Why selecting a gate is refused"** |
| `aw-remote-host vpn use-exit <node> --plan` | no — read-only preview, still works |
| `aw-remote-host vpn clear-exit` | yes, back to normal — never refused |

## Why selecting a gate is refused

`use-exit` moves **this machine's** default route — `ip rule … lookup 52`
applied `from all`, so the host and every container on it leave through the
gate. That was the wrong scope. What the feature is for is moving the
**containers'** egress; the host's own public IP is the thing that must *not*
change, and a host whose address moved is a failed apply however healthy the
container's egress looks.

The cost of the old shape is not theoretical. The first real apply took a Mac
off the internet, and the same verb is reachable against a bare metal running
production. So until the rules are keyed per container network, this refuses
rather than keep offering a destructive action — routing the whole machine is
not a degraded mode of this feature, it *is* the bug.

Refused in four places, because each one becomes reachable at a different
time: `vpn.UseExit` (`internal/vpn/usexit.go`, the innermost — every path goes
through it), the `vpn_use_exit` /link verb, this CLI, and aw-backend's
`/exit-gate` endpoint. The last one is what actually holds today: the host's
own refusal only reaches a machine once its binary is updated, and that is a
manual job.

**`clear-exit` is never refused**, deliberately — it is the way *off* a gate,
and the hosts that took a selection before this landed are exactly who needs
it. `--plan` also still works: it changes nothing by construction, and it is
where the exclusion set a host would really install can be read while that set
is being re-derived for the container-scoped model.

## Offering a node that is already on the mesh

`--advertise-exit-node` above is an ENROLMENT flag: it decides, once, at the
moment a machine joins. A node already on the mesh had no way to start
offering, and the consequence was concrete — on 2026-08-26 this tenant's mesh
had exactly one gate, the only node anyone had thought to ask for at join
time, and the Networking screen's picker was correct to list nothing else.

**`vpn_advertise_exit`** (`internal/ops/ops_vpn_advertise.go`, `{"advertise":
true|false}`) is that missing half. It enables kernel forwarding, proves it by
reading the sysctls back, then advertises — and measures this host's own route
to the internet either side, because *offering is not using* and an invariant
nobody measures is a comment.

It is **only half of a gate**. `offers_exit` in its reply is tailscale's
`ExitNodeOption` — advertised AND approved — and is normally `false` right
after a successful advertise. That is not a failure; it is the control plane's
turn. aw-backend's `POST /remote-hosts/{id}/exit-offer` does both halves and
**withdraws this one if its own fails**, because a node advertising a route
nobody approved looks armed and forwards nothing.

A **WSL2 distro may now serve as a gate**, where it used to be refused
outright (`internal/vpn.Resolve`, and `bootstrap/lib/vpn.sh` in the same
breath — the two must agree or the module never converges). "Never measured"
is not "does not work", and the refusal left the only machine that could be a
second gate permanently out. The cost travels with the permission instead, as
`exit_warning`: everything routed through it leaves via the Windows host's NAT
and, since it cannot hole-punch from behind that extra layer, through a public
relay.

Each of the two route-changing commands also has a `/link` verb, so the same
thing can be asked for from the Networking screen instead of over SSH:
`vpn_use_exit` and `vpn_clear_exit` (`internal/ops/ops_vpn_exit.go`), beside
the read-only `vpn_status`, the enrolment-only `vpn_bootstrap` and the
route-preserving `vpn_advertise_exit` above. They call
**the same `internal/vpn.UseExit`** the command does — the ordering below is
the safety mechanism, and a second copy of it reachable only from the control
plane would be the copy nobody exercises by hand.

That a verb can arrive over the very tunnel it is about to put at risk is the
obvious objection, and the answer is the ordering: the dead-man's switch is
armed *before* the route moves, so a caller who never hears back still gets
the host back.

This module is **opt-in** (`"optional": true` in `bootstrap/manifest.json`).
A plain `bootstrap-workspace --with-workspace` never runs it: joining a
network is a decision the machine's owner makes, not a side effect of
provisioning a workspace. It runs when something names it — the
`aw-remote-host vpn` command, or a control-plane bootstrap that asks for it.

## What the bootstrap module does, and the line it does not cross

The module — `install.sh`/`verify.sh`, the thing a control-plane bootstrap
runs — installs the client, starts the daemon, runs `tailscale up` against
the login server you give it, and, if asked, adds `--advertise-exit-node`.

It **never selects an exit node**, and nothing it does changes this
machine's default route. Selecting one is a separate, explicit command
(below), and that boundary is not bureaucratic:

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
| macOS without sudo (`Mac.Home`, uid 503) | **refused for ENROLMENT** — `sudo -n` fails so `tailscaled install-system-daemon` cannot run, and `/opt/homebrew` belongs to another account so `brew install` fails on permissions. It can still **select** a gate; that is a third verdict — see "A Mac as a client" |

The macOS refusal is the one that matters most, because the failure it
prevents is silent. Without root, tailscaled can still start with
`--tun=userspace-networking` — which yields a SOCKS5/HTTP proxy and **not** a
network interface. A host installed that way looks enrolled and carries none
of its own traffic. On that same machine `tailscale set` answers `Access
denied: checkprefs access denied`.

## Selecting an exit gate (phase 2)

```
aw-remote-host vpn use-exit <node> [--expect-egress <ip>] [--exclude a,b] \
                                   [--deadman 2m] [--confirm-timeout 45s] [--plan]
aw-remote-host vpn clear-exit
```

This moves the machine's default route — and, because every container NATs
out through it, every container's traffic with it — onto `<node>`. It is the
dangerous half of this module, so **the safety mechanism is the feature**.
The ordering below is the deliverable; the `tailscale set` in the middle is
the easy part.

1. **Measure egress before.** There is otherwise nothing to compare against.
2. **Arm a dead-man's switch, before touching anything.** A detached
   `sh -c 'sleep N; tailscale set --exit-node=; …'` in its own session
   (`SysProcAttr.Setsid` — it has to outlive the session that armed it, which
   is the session most likely to be killed by the route change it guards).
   Every later failure — a gate that does not forward, a confirmation that
   hangs, this process being `kill -9`ed — still ends with the route back.
   It is the **tool's** job, never the caller's.
3. **Pin the exclusions**, control plane first. (On macOS there are none to
   pin, and that is measured rather than skipped — see "A Mac as a client".)
4. **Move the route** — `tailscale set --exit-node=<ip>
   --exit-node-allow-lan-access=true --accept-dns=false`.
5. **Confirm through the new route**: fetch the real public IP, and check the
   control plane still answers.
6. **Revert anything unconfirmed** — and only *then* stand the switch down.

### The exclusions, and why they are shaped this way

| Prefix | Why |
|---|---|
| the control plane's address (`api.aw.tekflox.com`) | the only remote-management path. **Not optional** — if it cannot even be resolved, `use-exit` refuses rather than moving the route without it |
| every directly attached IPv4 network | that is the LAN prefix (`internal/lanfastpath` depends on it) *and* every podman/docker bridge, in one sweep that cannot drift as new bridges appear |
| whatever `--exclude` names | the things only the operator knows: a NAS on a routed subnet, a jump host |

On Linux they are installed as `ip rule add to <prefix> lookup main priority
5260`.
Two details carry the whole safety property:

- **5260 beats tailscale's catch-all at 5270.** Measured on `aw-baremetal`,
  2026-08-25: tailscale's rules live at 5210/5230/5250 (fwmark, its own
  packets only) and 5270 (`from all lookup 52`). 5260 is consulted first.
- **They point at the *main* table, never at a table the tunnel owns.** A
  leftover exclusion is therefore **inert** — "send this prefix to the main
  table" is what an unconfigured machine already does. Compare the recorded
  accident on this infrastructure: `ip rule from 172.18.0.5 lookup 51821`
  pointed into a table whose gateway had ceased to exist, and a container had
  no internet **for two days, silently**, surviving restarts because the rule
  lived on the host. Nobody was alerted; it surfaced when a deploy failed.
  The mechanism here is chosen so that failing to clean up cannot do that.

### Confirming, rather than assuming

"The interface is up" proves nothing. After the switch, `use-exit` fetches
this host's real public IP (fresh connections, keep-alives disabled — a
pooled connection would answer from the *old* path) and requires either:

- `--expect-egress <ip>`: an exact match with the gate's known public
  address; or
- no flag: that the address **changed**.

An unchanged address with no `--expect-egress` is treated as a failure and
reverted. There are legitimate topologies where a correct switch produces the
same address — a gate that NATs to the public IP the client already used —
and `--expect-egress` is how you say so up front. The control plane is
re-checked at the same time: internet without a management path is still a
lockout.

### The boot guard

An exit-node selection is a tailscale **preference** and survives a reboot.
The `ip rule` exclusions are runtime state and **do not**. A machine that
rebooted with the first and without the second would come back with its
default route on the mesh and nothing holding the control plane outside it —
the lockout, arriving on its own, after everyone stopped watching.

So `use-exit` installs `aw-vpn-exit-clear.service`, a oneshot that clears the
selection at boot. This deliberately makes the selection non-persistent, and
restores the escape hatch this repo already established in
`tools/host-firewall/aw-firewall-apply.sh`, which does not persist across a
reboot on purpose. `--persist-across-reboot` opts out and prints why you
probably should not.

### Known limits, stated rather than discovered

- **The control-plane exclusion is a DNS pin taken at selection time.** A
  control plane that moves behind a rotating address goes stale; re-run
  `use-exit` (or `clear-exit`) if it does. `status` prints what is actually
  pinned.
- **A container bridge created *after* `use-exit` is not excluded.** The
  sweep runs once. Re-run `use-exit` after adding a network.
- **IPv4 only.** The exclusions and the default-route move are both IPv4;
  IPv6 is not claimed rather than half-supported.
- **Linux and macOS.** Windows is refused towards its WSL2 distro: the
  workspace runs in there, so moving the Windows side's route would move the
  wrong operating system's.

### A Mac as a client

A Mac can **select** a gate. It still cannot **offer** one — forwarding needs
IP forwarding enabled with a sysctl nobody here has exercised on real
hardware, so it stays deliberately unclaimed.

"Can enrol" and "can select" are separate verdicts (`CanEnroll` /
`CanSelectExit` in `internal/vpn`), and on `Mac.Home` they disagree: it can
never enrol, because `/opt/homebrew` belongs to another account, and it can
select perfectly well, because tailscale is already installed there and
tailscaled runs as a root LaunchDaemon. Deciding the second with the first's
answer sent the machine's owner off to fix Homebrew, which would have changed
nothing.

**No route surgery, and that is the finding rather than a gap.** Measured on
`Mac.Home` (Darwin 25.5.0, arm64, tailscale 1.102.3) on 2026-08-26:

- tailscaled owns the utun and installs the split default itself. There is no
  `ip rule`, no table 52, and nothing for this module to route by hand.
- The LAN half of the exclusions is native —
  `--exit-node-allow-lan-access=true`, which the selection passes anyway, and
  which tailscaled tears down together with the selection that justified it.
  An exclusion that cannot outlive its justification.
- The only macOS mechanism for holding one address outside the tunnel is a
  static host route, `route -n add -host <ip> <gateway>`. It names a gateway,
  so it is the exact inverse of the inert `ip rule` above: a laptop that
  leaves that network comes back with a **black hole** for precisely the
  address the exclusion existed to protect, and a laptop is the one machine
  that changes networks every day. Not implemented, on purpose.

So on macOS the control plane's reachability is **confirmed rather than
pinned**: step 5 proves it still answers through the gate and reverts if it
does not. Its address is still resolved at plan time and an unresolvable one
is still a refusal — confirming a thing requires knowing where it is. What
this does not cover is the gate breaking *later*; then the Mac loses its
internet and its `/link` tunnel together, and the way back is `clear-exit`
from that keyboard or a restart. The result and the `vpn_use_exit` reply both
carry a `manageability` sentence saying so, so a screen cannot report the
Linux guarantee on a Mac. `--exclude` is **refused** there rather than
ignored: silently dropping it would tell an operator a prefix is outside the
tunnel when nothing is holding it there.

**The one privilege it does need, once.** tailscaled on macOS runs as a root
LaunchDaemon and gates every preference write on the calling user, so
`tailscale set` from an ordinary account answers `Access denied: checkprefs
access denied`. The fix is tailscale's own, and it is a one-time action by an
administrator of that Mac:

```
sudo tailscale set --operator=<user>
```

After that no further privilege is needed to select a gate from there.
Because the grant is invisible to `uid` and to `sudo -n`, the check is a
**live probe** and not a guess: `PlanUseExit` issues
`tailscale set --accept-dns=false` — a write that changes nothing, since that
flag is passed on every selection anyway and MagicDNS is forced off at
enrolment — and refuses with the command above if it is denied. It runs
*before* the dead-man's switch is armed, so a Mac without the grant is
refused rather than half-applied.

**The boot guard is a LaunchAgent there**,
`~/Library/LaunchAgents/com.tekflox.aw-vpn-exit-clear.plist`, user-scoped so
it needs no root either. Its premise differs from the systemd unit's — there
are no exclusions to lose across a reboot — but the other half of that unit's
value applies unchanged: a restart has to stay a way out of a gate that
stopped forwarding. The cost, said out loud: an agent fires at **login**, not
at boot, so the window between the two is not covered.

### What `status` reports

Everything above is read back **from the machine**, not from `state.json` —
the case that hurts is exactly the one where the two disagree:

```
vpn: route exclusions in force (outside the tunnel): 65.109.66.88, 10.88.0.0/16, 172.17.0.0/16
vpn: EXIT NODE IN FORCE — this machine's default route goes through aw-baremetal (100.64.0.1)
vpn: default route for 1.1.1.1 leaves via tailscale0
vpn: REAL public egress IP: 65.109.66.88 (measured via https://api.ipify.org)
```

and it speaks up about the leftover states rather than only the good ones —
exclusions with no selection behind them, a selection with no exclusions, a
dead-man's switch that already fired, a boot guard that is missing.

### Measured end to end (disposable node, 2026-08-25)

A throwaway systemd container enrolled as `aw-vpn-lab` (100.64.0.5) against
the live `headscale.aw.tekflox.com`, using `aw-baremetal` as the gate:

| Proof | Result |
|---|---|
| default route moves | `ip route get 1.1.1.1` went `via 172.17.0.1 dev eth0` → `dev tailscale0 table 52` |
| a **container** on that host follows | forwarded lookup `from 10.88.0.4 iif podman0` went `dev eth0` → `dev tailscale0`; its bytes crossed `tailscale0` |
| `/link` survives | `ip route get 65.109.66.88` stayed on `eth0`; 3×`HTTP 200` from `/api/health`, and `wss://…/link` answered (a token rejection, not a connect failure) with the gate in force |
| unconfirmed switch reverts | with no `--expect-egress` the IP could not change, so the tool reverted itself and exited non-zero |
| **the dead-man's switch fires** | the tool was `SIGKILL`ed mid-confirmation; ~20s later (`--deadman=25s`) the exclusions were gone, the selection cleared, the route back on `eth0` and the internet working — with a log line saying so |

The node, the container, the image and the ephemeral pre-auth key were all
removed afterwards. Same standard as phase 1.

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
