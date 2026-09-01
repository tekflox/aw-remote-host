# `vpn` — join this host to the tenant's mesh

Installs tailscale and enrols this machine in **the tenant's own headscale**,
optionally offering it as an exit gate — and, since phase 2, selecting one.

| Command | Whose egress moves? |
|---|---|
| `aw-remote-host vpn --login-server=…` | nobody's — enrolment only (phase 1) |
| `aw-remote-host vpn --advertise-exit-node` | nobody's — *offering* is not *using* |
| **`aw-remote-host vpn use-exit <node>`** | **the CONTAINERS'. Never the host's — see below** |
| `aw-remote-host vpn use-exit <node> --plan` | nobody's — read-only preview |
| `aw-remote-host vpn clear-exit` | back to normal — never refused |

## The invariant: route the containers, never the host

This is the correction of 2026-08-26, and it inverts what the feature used to
do. `use-exit` once moved **this machine's** default route — `ip rule … lookup
52` applied `from all`, so the host and every container on it left through the
gate. That was the wrong scope, and the cost was not theoretical: the first
real apply took a Mac off the internet, and the same verb was reachable against
a bare metal running production.

What holds now:

- the **containers'** public IP **must change**. That is the feature.
- the **host's** public IP **must not change**. That is a hard assertion, not a
  hope.
- a host whose address moved is a **failed apply** and reverts, however healthy
  the container's egress looks.
- the confirmation checks **both**, because either alone is a half-measure:
  container-changed-only hides a host that moved too; host-unchanged-only
  proves nothing happened at all.

### What is still refused, and why that is not a leftover

Routing the whole machine is not a degraded mode of this feature — it *is* the
bug. So any host where the only thing that *could* move is the machine itself
is **refused**, with the reason, rather than served:

| Host | Answer |
|---|---|
| Linux with a container runtime and at least one network | **allowed** — container-scoped |
| **a Linux container that itself runs containers** | **allowed**, container-scoped, exactly like any other Linux host — see below |
| Linux with no `docker`/`podman` that answers | **refused**: nothing to route but the machine |
| a runtime that answers but defines no IPv4 network | **refused**: same, one step later |
| **macOS** | **refused** — see "A Mac as a client" |
| Windows | refused towards its WSL2 distro, as before |

**Being a container is not a disqualification; having nothing to scope is.**
That row is not an exception carved out of the invariant above — it is the
invariant applied literally, and it is written down here because the obvious
reading of "never the host" is that a container must be a special case, and
somebody acting on that reading in three months would revert it as a
regression.

The machine that forced the question is `b614f41828c8`, the container the `aw`
workspace's whole stack runs inside. Measured in there on 2026-09-01: uid 0,
`CapEff=000001ffffffffff`, its own netns, `/dev/net/tun`, `ip rule add/del`
working, and `/usr/bin/podman` answering `network ls` with two bridges — 75
running containers on `aw-remote-host`/`10.89.0.0/24`. It has containers to
scope, so the exclusion CIDR exists, so routing it moves those containers and
nothing else. That is the whole of the test.

The discriminant stays **"are there containers to scope?"** rather than
becoming "is this a physical machine or a container?", and the reason is not
convenience:

- the first is a **measurement** — `DetectContainerRuntime` requires the
  runtime to actually answer `network ls`, the same call the next step makes.
  The second is an **inference** with no signal that does not lie:
  `/.dockerenv` is docker-only, `container=` is podman-only, and unified
  cgroup v2 reports `0::/` either way.
- applied to this host the second gives the **wrong** answer. It would class
  `b614f41828c8` as "container, therefore route it whole", moving the entire
  netns and losing both the per-network granularity and the host bypass — in
  order to route the 75 containers the existing path already routes safely.
- the invariant was never about containers versus hosts. It is about blast
  radius: *nothing beyond the workload someone asked to route may move*.
  "Are there containers to scope?" is the measurable form of that sentence.
  This container is not "the host of these containers" in the sense that took
  a Mac off the internet on 2026-08-26; it is their host in the sense the
  feature is for.

`NoContainerRuntimeRefusal` is therefore unchanged and must stay that way — it
is what still protects the bare metal and the Mac. What was wrong in the
original report about this host was the measurement (`command -v docker podman`
returns non-zero when *any* argument is missing, which read as "no runtime"),
not the rule.

`vpn.ScopeRefusal` is that verdict, in two halves: the static one from the OS
(no probe can change a Mac's answer) and the live one from the machine (is
there a runtime, does it define a network). The CLI and the `vpn_use_exit`
verb both ask it before building a spec, so a caller gets the reason instead of
a failure from deep in the sequence; `UseExit` asks again as the innermost
layer, because a refusal that lives only in the callers is one a future caller
walks around.

**`clear-exit` is never refused**, deliberately — it is the way *off* a gate,
and the hosts that took a selection before this landed are exactly who needs
it. `--plan` also still works on a refused host: it changes nothing by
construction, and it is where the reason can be read next to what that host
actually resolves to.

> **aw-backend still refuses `POST /exit-gate` with a 409** as of this commit.
> That flag was added while the whole verb was refused, and lifting it for the
> container-scoped path is a change in *that* repo, not this one. Until it is
> lifted the UI path stays closed and the CLI / `/link` verb are the ways in.

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

### systemd, or a supervisor that says so (2026-09-01)

`/run/systemd/system` used to be a hard requirement on Linux. It is not any
more, and the reason is that it was never the requirement — it was a proxy for
one: **something has to keep `tailscaled` running**, or the node leaves the
mesh at the first crash and nothing says so.

A container can satisfy that and can never satisfy the proxy. `b614f41828c8`'s
PID 1 *is* its supervisor (`tools/aw-remote-host/entrypoint.sh` in
`agentic-workspace`), so demanding systemd there was demanding something the
machine cannot have in exchange for something it already does.

So a supervisor may declare itself, in `/run/aw-remote-host/tailscaled-supervisor`:

```
name=aw-remote-host-entrypoint
pid=1234
```

Both halves of this module read it — `internal/vpn`'s `probeSupervisor` and
`bootstrap/lib/vpn.sh`'s `vpn_has_supervisor`, which must keep agreeing for
the reason that file's header gives. Two things make the claim hard to lie
with, and both are needed:

- **the declared pid must still be alive** (signal 0). `/run` is *not* a tmpfs
  in every container — measured on this one, where it is part of the image's
  overlay — so a marker can outlive the boot that wrote it. The writer also
  removes any stale file before writing its own; the liveness check is the
  half that does not depend on the writer having remembered to.
- **the pid must not be `aw-remote-host` itself.** A process supervising
  itself supervises nothing, and its own pid is the one trivially alive at the
  moment of asking.

A host with neither systemd nor a live declaration is still refused, and the
refusal names both ways out — telling the reader of a container to enable
systemd sends them to fix something a container cannot have.

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

This moves the egress of every **container network** on this host onto
`<node>`, and leaves the machine's own where it is. It is the dangerous half
of this module, so **the safety mechanism is the feature**. The ordering below
is the deliverable; the `tailscale set` in the middle is the easy part.

1. **Measure BOTH egresses before** — the host's, which must hold, and the
   containers', which must move. The same function measures the "after", or
   the pair proves nothing.
2. **Arm a dead-man's switch, before touching anything.** A detached
   `sh -c 'sleep N; tailscale set --exit-node=; …'` in its own session
   (`SysProcAttr.Setsid` — it has to outlive the session that armed it, which
   is the session most likely to be killed by the route change it guards).
   Every later failure — a gate that does not forward, a confirmation that
   hangs, this process being `kill -9`ed — still ends with the rules gone.
3. **Install the rules**, host bypass *first* (below).
4. **Select the gate** — `tailscale set --exit-node=<ip>
   --exit-node-allow-lan-access=true --accept-dns=false`.
5. **Confirm both halves**: the containers' address changed, the host's did
   not, and the control plane still answers.
6. **Revert anything unconfirmed** — and only *then* stand the switch down.

### The rules, and why they are shaped this way

Four priorities, all inside tailscale's own reserved 5210–5270 block — which
is what makes deleting blindly at them safe, since nothing else allocates
there. In the order the kernel evaluates them:

| Priority | Rule | Why |
|---|---|---|
| 5259 | `to 100.64.0.0/10 lookup 52` | the mesh stays reachable for host and containers alike |
| 5260 | `to <prefix> lookup main` | the exclusions — control plane, every attached network, `--exclude` |
| 5261 | `from <container CIDR> lookup 52` | **the feature.** One per container network |
| 5265 | `from all lookup main` | **the host's route, held still** |

- **5265 is what makes the invariant hold.** Everything that is not a container
  reaches it before tailscale's catch-all at 5270 ever gets a chance, so the
  host's default stays in the main table for the whole life of the selection.
  Its public IP cannot move, because nothing consults table 52 on its behalf.
  It is also installed **first**, before any container rule and long before
  `tailscale set` creates 5270 — so the window in which the host could take
  the gate is zero, not small.
- **5259 is not optional, and was nearly missed.** Measured on the Surface,
  2026-08-26: `ip route show 100.64.0.0/10` in the **main** table is *empty* —
  the peer routes live only in table 52. Without 5259 the bypass would send
  mesh traffic to a table with no route for it and the machine would lose the
  mesh, including the peer it is being routed through, while looking healthy.
- **The container rules are keyed on the network's CIDR, never on a container's
  own address.** Container IPs are ephemeral *and* recycled, so a rule pinned
  to `172.18.0.5` silently starts applying to whatever different container next
  gets that address. That is the recorded accident on this infrastructure:
  `ip rule from 172.18.0.5 lookup 51821` left a container with no internet
  **for two days, silently**, surviving restarts because the rule lived on the
  host.
- **The CIDRs come from the runtime, never from the interface table.**
  `docker`/`podman network inspect`, parsed across all three shapes in play
  (podman 4/netavark, docker, podman 3/CNI). A defined network with no running
  container has no host-side bridge address at all: on the Surface, podman
  knows `10.88.0.0/16` and `10.89.0.0/24` while `ip -4 addr` shows only the
  second. An interface sweep would have missed half the containers on the box,
  in the direction that reads as success.

**The one rule that points into the tunnel's table**, said plainly rather than
glossed: `from <CIDR> lookup 52` is the shape exit.go's header warns about, and
routing containers through a tunnel cannot be expressed any other way. What
makes it survivable is a property table 51821 did not have — tailscaled puts a
**default route** in table 52 only while a selection is in force, and removes
it when the selection clears (measured on the Surface: with nothing selected,
table 52 holds peer routes and no default). A leftover container rule therefore
finds no default and the kernel falls through to the next rule. The 51821 rule
pointed at a wireguard table that kept its dead default forever.

**The exclusions were re-derived, not inherited.** Under the old model they
protected the *host*, whose route was moving. It no longer moves, so each had
to earn its place again as a rule about *container* traffic — and both kinds
did:

| Prefix | Why, under the new model |
|---|---|
| the control plane's address | a container's traffic to it would otherwise leave through the gate. **Still not optional**: an unresolvable control plane is still a refusal |
| every directly attached IPv4 network | where container-to-LAN and container-to-container traffic goes. Without them a container talking to the NAS, the host, or a container on another bridge would have it sent into the tunnel and dropped. `internal/lanfastpath` depends on the LAN one |
| whatever `--exclude` names | the things only the operator knows: a NAS on a routed subnet, a jump host |

They are `to <prefix> lookup main` rules, which is what lets them sit above the
container rules and win: destination decides, so only traffic genuinely
*leaving* is left for the gate.

### Confirming, rather than assuming

"The interface is up" proves nothing, and neither does one address. After the
selection, `use-exit` re-measures both — fresh connections, keep-alives
disabled, and the first endpoint is an **IP literal**
(`https://1.1.1.1/cdn-cgi/trace`) so the answer does not depend on DNS, which
matters most on the container side where `dns_enabled=false` is normal.

The container half is measured by running a **throwaway container** on the
host's own runtime, which makes the connection fresh by construction — there is
no pool that could answer over the path that existed before the change. This is
the same `vpn.MeasureContainerEgress` the read side uses; two implementations
would drift, and a divergence produced by two different methods would prove
nothing.

Four checks, in the order of the damage:

1. **the host held.** Failed first, and not retried — a host whose address
   moved is already in the state the sequence exists to prevent. The result
   carries `host_moved` so a caller can tell that apart from a gate that
   merely did not work.
2. **the control plane still answers.**
3. **the containers moved** — `--expect-egress <ip>` for an exact match, or
   without it, that the address **changed**. An unchanged address with no
   `--expect-egress` is a failure and reverts; there are legitimate topologies
   where a correct switch produces the same address, and the flag is how you
   say so up front.
4. **the two addresses differ.** With the host proven to have held, a container
   egress equal to the host's can only mean the rules matched nothing. That is
   the failure that used to be indistinguishable from success.

### The boot guard

An exit-node selection is a tailscale **preference** and survives a reboot.
The `ip rule` set is runtime state and **does not**. A machine that rebooted
with the first and without the second would come back with tailscale's
`from all lookup 52` unopposed and **no host bypass** — which is the whole
machine routed through the gate, the exact scope this feature exists to
prevent, arriving on its own after everyone stopped watching.

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
- **A container network created *after* `use-exit` is not routed**, and not
  excluded either. Discovery runs once, at selection time. Re-run `use-exit`
  after adding a network — and note the failure is the safe direction: a new
  network keeps the host's own egress rather than silently getting the gate's.
- **The gate must not also be advertised by the client.** tailscale refuses to
  advertise an exit node and use one at the same time, so a host offering
  itself as a gate cannot select one until it stops. The refusal surfaces as a
  failed `tailscale set`, and the sequence rolls every rule back.
- **The probe pulls an image the first time.** `docker.io/curlimages/curl` is
  ~10MB; on a host that does not have it, the first measurement waits for the
  pull. `vpn.ContainerProbeImage` points it elsewhere.
- **IPv4 only.** The exclusions and the default-route move are both IPv4;
  IPv6 is not claimed rather than half-supported.
- **Linux and macOS.** Windows is refused towards its WSL2 distro: the
  workspace runs in there, so moving the Windows side's route would move the
  wrong operating system's.

### A Mac as a client — the darwin question, answered

**A Mac is refused, with a reason, and there is no fallback.** The card asked
whether container-scoped routing is reachable from *outside* the Docker Desktop
/ `podman machine` VM. It is not, and two independent things make it so —
either alone would be enough:

1. **The packets are already disguised.** There is no host-level container
   network on macOS. Both runtimes run every container inside a Linux VM with
   its own network stack, and that VM NATs container traffic to its own address
   before macOS sees it (Docker Desktop goes further and terminates it in a
   userspace proxy). By the time a packet reaches the Mac's routing, its source
   is the VM's or the host's — there is no container CIDR left to key on.
2. **There is nothing to key it with.** macOS has no policy routing by source
   prefix; `route` keys on destination only. Measured on `Mac.Home`,
   2026-08-26: `command -v ip` finds nothing — there is no `ip(8)` on the
   platform at all.

So the only scope available from out there is the **whole machine**, and under
the corrected invariant that is not a degraded mode of this feature: it is the
bug, and it is what took this Mac off the internet on the first real apply. A
fallback would be the failure wearing the feature's name.

**What would work**, so the refusal is not a dead end: enrol the VM itself. A
`podman machine` / Docker Desktop VM is an ordinary Linux host, and an
`aw-remote-host` inside it takes the Linux path with real container networks
and a real `ip rule` — the same answer this module already gives Windows,
whose workspace lives in WSL2.

Everything below still describes what a Mac *can* do, and remains true: it can
select a gate for **itself**, which is a capability this verb no longer
exposes. It still cannot **offer** one — forwarding needs a sysctl nobody here
has exercised on real hardware, so it stays deliberately unclaimed.

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
vpn: routing rules in force: from all to 100.64.0.0/10 lookup 52; from all to 65.109.66.88 lookup main; from 10.89.0.0/24 lookup 52; from all lookup main
vpn: EXIT NODE IN FORCE — this host's CONTAINER networks go through aw-baremetal (100.64.0.1)
vpn: this HOST's route for 1.1.1.1 leaves via eth0 (a tailscale interface here would mean the host is routed, which it must not be)
vpn: HOST public egress IP: 188.250.165.236 (measured via https://1.1.1.1/cdn-cgi/trace) — with a gate in force this must be the SAME address as before it
vpn: CONTAINER egress IP: 65.109.66.88 (measured via https://1.1.1.1/cdn-cgi/trace, from a throwaway container on podman network podman)
```

Rules are printed **verbatim**, not summarised into bare prefixes: under
container-scoped routing a rule's direction is its whole meaning, and `from
10.89.0.0/24 lookup 52` (into the tunnel) and `to 10.89.0.0/24 lookup main`
(out of it) would collapse into the same string.

It speaks up about the leftover states rather than only the good ones — rules
with no selection behind them, a selection with **no** rules (which now means
tailscale's own catch-all is unopposed and the *machine* is routed), a
dead-man's switch that already fired, a boot guard that is missing.

### The two addresses, and how to read them

`vpn_public_ip` reports both, and their divergence is the diagnostic:

| State | Reading |
|---|---|
| no gate, the two are **equal** | healthy |
| no gate, the two **differ** | something is already routing container traffic somewhere unexpected — the `51821` shape, which went unnoticed for two days |
| gate applied, the two **differ** | it worked, **and** the host was left alone. Both facts from one comparison |
| gate applied, still **equal** | either the gate did nothing, or the host moved too and both are now the gate's address — indistinguishable from the container's number alone, which is why both are reported |

A measurement that fails returns an empty address **with the reason** and never
a remembered one; a host with no container runtime says exactly that. It never
copies the host's address into the container's field — under this model the two
numbers differing *is* the evidence, so that would fabricate the proof somebody
is about to rely on.

### Measured end to end, container-scoped (Surface WSL, 2026-08-26)

A full cycle on `aw-surface-wsl` (`caf475b7032ee441`, podman 4.9.3, root),
gate `aw-baremetal`, relayed via DERP(hel). Never on `bare-metal-privileged`,
never on `Mac.Home`.

| Proof | Result |
|---|---|
| baseline, no gate | host `188.250.165.236`, container `188.250.165.236` — **equal**, as the model predicts |
| discovery beats an interface sweep | routed `10.88.0.0/16` **and** `10.89.0.0/24`; only the second has a host interface |
| **containers move** | container egress `188.250.165.236` → **`65.109.66.88`** |
| **the host holds** | host egress `188.250.165.236` → `188.250.165.236`, and `ip route get 1.1.1.1` stayed `via 172.31.64.1 dev eth0` — never a tailscale interface |
| independently re-measured with the gate in force | a shell outside the tool read host `188.250.165.236`, container `65.109.66.88` |
| the rule table is what was designed | 5259/5260×3/5261×2/5265 present, tailscale's 5270 unreachable |
| rollback on failure | an earlier attempt failed at `tailscale set` (the Surface was advertising a gate, which tailscale will not combine with using one); all **7 rules removed**, table back to pristine |
| `clear-exit` restores both | 7 rules removed, host and container both back to `188.250.165.236` |

The `--advertise-exit-node` turned off for the test was restored afterwards,
and headscale still lists `aw-surface-wsl` with `0.0.0.0/0, ::/0` approved.

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
