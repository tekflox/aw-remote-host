// Routing ONE container on this host out through an EXTERNAL WireGuard tunnel
// that this host already terminates — as opposed to a mesh exit gate, which is
// usexit.go's job and is not touched by anything in this file.
//
// WHY THIS EXISTS AS A SECOND PATH AT ALL. It routes ONE named container
// rather than every container network the way usexit.go does, and it does so
// over a tunnel this host terminates itself rather than a mesh gate. Those are
// different mechanisms with different failure modes, and they can be in force
// at the same time.
//
// A CORRECTION, 2026-09-05. This header used to say that the `aw-remote-host`
// container (`e91aacf5a3a3`, where the `aw` workspace's 130 sibling containers
// live) had no `ip`, no `wg` and no container runtime of its own, and that
// this was why the apply had to run on the bare metal hosting it. That was
// measured on 2026-09-02 and it was true then. It is NOT true any more:
// the image was rebuilt from this repo's own Dockerfile and the container was
// recreated, and inside the running container today are /usr/sbin/ip
// (iproute2-6.1.0), /usr/bin/wg and /usr/bin/wg-quick (wireguard-tools
// 1.0.20210914), /usr/sbin/openvpn (2.6.14), /usr/bin/podman and
// /usr/bin/tailscale.
//
// So the SAME-NETNS case is now the simple case and the normal one: the
// runtime, the local bridges and the tunnel device are all in one namespace,
// ExternalRouteSpec.Container resolves "as the local runtime knows it"
// (below), and the apply runs where the Runner runs. Nothing about this file
// had to be inverted for that — it was always written against a Runner rather
// than against a location.
//
// The cross-host case (an apply for host A executing on host B, where B is the
// only machine that can write the rule) still WORKS and is still supported —
// the container id A reports for itself is the id B knows it by — but it is
// the difficult case, not the premise. Reading it as the premise sends the
// next person looking for a hosting relationship that no longer has to exist.
//
// The tunnel this points a source at can now be brought up by this tool too:
// externalup.go's ExternalUp/ExternalDown are the dialler, and they are
// SIBLINGS of this file rather than callers of it. Before them the tunnel had
// to already exist — typically aw-vpn-hub's, whose table 200 carries
// `default via 10.8.0.2 dev wg0` plus a direct route per local bridge so
// container-to-container traffic never enters the tunnel
// (repos/aw-stack/scripts/vpn-hub-entrypoint.sh). ExternalUp builds a table of
// exactly that shape, for the same reason.
//
// THE INVARIANT IS UNCHANGED, and this path does not need an exception to it:
//
//   - the routed CONTAINER's public IP MUST change. That is the feature.
//   - the HOST's public IP MUST NOT change. Asserted after every apply, and a
//     host whose address moved is a failed apply that reverts.
//   - the rule is anchored on a /32 belonging to the workload, never on a
//     network CIDR. Measured on the production bare metal 2026-09-02:
//     172.18.0.0/16 also carries aw-backend, aw-caddy, aw-headscale, aw-derper,
//     aw-sandbox and agents-platform-multitenant. A /16 rule would put the
//     entire production stack on a residential line. mustBeSingleHost turns
//     that into a refusal rather than a warning.
//
// The discriminant that keeps a physical machine from ever being routed by
// this path is structural rather than heuristic: the rule's source is an
// address enumerated FROM THE CONTAINER RUNTIME. A machine that is not running
// the named container produces no such address and is refused. There is no
// input to this file that widens into `from all`.
//
// THE RULE DOES NOT SURVIVE ON ITS OWN, and that is measured, not feared. On
// this bare metal `systemd-networkd` is restarted by the daily unattended apt
// upgrade (apt-daily-upgrade.service ran 2026-09-02 06:48:11; networkd
// restarted 06:48:54, 06:49:10 and 06:49:45) and it flushes every routing
// policy rule it does not own — tailscaled logs `somebody (likely
// systemd-networkd) deleted ip rules; restoring Tailscale's` and puts its own
// back. The hub's own client rules at priority 100-107 were NOT put back,
// because the hub installs them once at boot and then sleeps, which is why
// they are missing from a container that has been up 15 hours with
// RestartCount 0. Anything installed once here has a life expectancy shorter
// than a day. Reassert (below) is therefore part of the feature and not a
// nicety, and it is what the link daemon calls on a timer.
package vpn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// ExternalRouteTable is the routing table an external tunnel's default route
// is expected to live in. 200 is aw-vpn-hub's, and it is a default rather than
// a constant because a second external provider needs a second table — tables
// scale by replication here, not by multiplexing (vpn-concentrator.md §6).
const ExternalRouteTable = 200

// ExternalRoutePriority is where this path's `ip rule` sits.
//
// The neighbourhood is crowded and picking blind would silently shadow
// something. Measured on the production bare metal: tailscale owns 5210-5270
// (5210 main, 5230 default, 5250 unreachable, 5270 lookup 52) and usexit.go
// uses 5259-5265 inside that band. aw-vpn-hub uses 100-107 for its own wg
// clients. 5399 is below tailscale's whole range and far above the hub's, so
// it is evaluated after tailscale's fwmark rules have had their say — which is
// what keeps a tailscale-marked packet out of this table — and before the
// 32766 main lookup that would otherwise send the container out the host's
// own uplink.
const ExternalRoutePriority = 5399

// ExternalRouteSpec is one request to move a single container's egress onto an
// external tunnel this host terminates.
type ExternalRouteSpec struct {
	// Container names the container whose egress moves, by name or id, as the
	// local runtime knows it. Required: it is also the discriminant, because
	// resolving it is what produces an address that cannot be this machine.
	Container string
	// Table is the routing table carrying the tunnel's default route.
	// Defaults to ExternalRouteTable.
	Table int
	// Priority is the ip rule priority. Defaults to ExternalRoutePriority.
	Priority int
	// ExpectEgress, when set, makes confirmation an exact match instead of
	// merely "the address changed".
	ExpectEgress string
	// Deadman is how long an unconfirmed apply has before it reverts itself.
	Deadman time.Duration
	// ConfirmTimeout is how long to keep trying to confirm. Must stay inside
	// Deadman, and withDefaults enforces that rather than trusting a caller.
	ConfirmTimeout time.Duration
	// ControlPlane is the base URL whose addresses are held outside the
	// tunnel. Defaults to the daemon's own control plane.
	ControlPlane string

	// TunnelDNS asks for the local container resolver's OWN upstream to be
	// moved onto DNS below, closing the leak this file's
	// planExternalExclusions header documents as a known gap.
	//
	// It is OFF by default and the caller has to ask, because the change is
	// NETWORK-WIDE by construction: aardvark's upstream is scoped to a podman
	// network, `--dns-add` is the only knob, and every container on that
	// network resolves through the new upstream while the tunnel is up. See
	// §5 of the design. Defaulting it on would move 30 containers' resolvers
	// on behalf of a caller that asked to route one.
	//
	// The kill switch lives on this flag rather than in the binary: rolling
	// back is "stop passing --tunnel-dns", a core deploy, which is far faster
	// than rebuilding and reinstalling this binary on the host.
	TunnelDNS bool
	// DNS is the profile's own resolver list, already IP-validated by
	// ExternalProfile.validate. It arrives here from --profile-json rather
	// than a --dns flag on purpose: the address then never appears in an exec
	// command string, so aw-backend's job log stays exactly as clean as it is
	// today. Empty means there is nothing to move the upstream TO, which is
	// the first of §4's refusals.
	DNS []string

	// Runner is how every shellout is made. Required and never defaulted:
	// this package cannot build one (the base shellout lives in internal/ops,
	// which imports this package) and PrivilegedRunner's zero value has a nil
	// Inner that panics on first use. Same field, same reason, as UseExitSpec.
	Runner Runner
	// Runtime lets a caller that has already detected the container engine
	// avoid paying for the probe again. Zero value means "detect it".
	Runtime ContainerRuntime
}

func (s ExternalRouteSpec) withDefaults() ExternalRouteSpec {
	if s.Table == 0 {
		s.Table = ExternalRouteTable
	}
	if s.Priority == 0 {
		s.Priority = ExternalRoutePriority
	}
	if s.Deadman <= 0 {
		s.Deadman = 120 * time.Second
	}
	if s.ConfirmTimeout <= 0 {
		s.ConfirmTimeout = 45 * time.Second
	}
	// A confirmation window that outlives the switch it is racing would let a
	// selection revert while this run still believes it is confirming, and the
	// run would then report a success that no longer exists.
	if s.ConfirmTimeout >= s.Deadman {
		s.ConfirmTimeout = s.Deadman - 15*time.Second
		if s.ConfirmTimeout < 5*time.Second {
			s.ConfirmTimeout = 5 * time.Second
		}
	}
	return s
}

// ExternalRoutePlan is everything resolved before anything is changed.
// Producing one is read-only, which is what makes the plan mode an honest
// preview rather than a second code path that might disagree.
type ExternalRoutePlan struct {
	Container   string   `json:"container"`
	ContainerID string   `json:"container_id"`
	SourceIP    string   `json:"source_ip"`
	Table       int      `json:"table"`
	Priority    int      `json:"priority"`
	Runtime     string   `json:"runtime"`
	TunnelVia   string   `json:"tunnel_via"`
	TunnelDev   string   `json:"tunnel_dev"`
	Exclusions  []string `json:"exclusions"`
	MainGateway string   `json:"main_gateway"`
	MainDev     string   `json:"main_dev"`
	Refusal     string   `json:"refusal,omitempty"`
	// ExpectEgress is spec.ExpectEgress, carried onto the plan so it can be
	// persisted alongside everything else this apply recorded — see
	// ExternalStatusReport, the reader that turns a later mismatch into a
	// warning instead of a bare, unverified address.
	ExpectEgress string `json:"expect_egress,omitempty"`

	// --- the DNS half. All four are empty unless every PLAN-time
	// precondition in §4 held; the APPLY-time ones are proven in
	// applyTunnelDNS, which is the only thing that may set DNSTunneled. ---

	// DNSServers are the profile's resolvers, to become the network's
	// aardvark upstream. Empty means the DNS half is not being attempted at
	// all, and every function below treats that as "there is nothing to do"
	// rather than as a failure.
	DNSServers []string `json:"dns_servers,omitempty"`
	// DNSNetwork is the podman network carrying the routed container,
	// RESOLVED from `podman inspect` rather than assumed to be a constant.
	// Today it is the only network on this host; §9 of the design records
	// that writing it as a constant is a door that closes the moment a
	// second one appears.
	DNSNetwork string `json:"dns_network,omitempty"`
	// DNSPodmanPath is podman's ABSOLUTE path, resolved before anything is
	// touched — the same rule ArmSpec.TailscalePath enforces, and here it is
	// load-bearing rather than tidy: the dead-man's revert names this path,
	// so a podman that cannot be resolved is a DNS change that cannot be
	// undone, and one that must therefore not be made. That un-revertability
	// is exactly what got the previous approach to this rejected.
	DNSPodmanPath string `json:"dns_podman_path,omitempty"`
	// DNSPrior is the network's upstream list BEFORE this apply, so a revert
	// restores what was there instead of assuming it was empty. Today it is
	// empty on this host; recording it is what keeps that from being an
	// assumption baked into the undo.
	DNSPrior []string `json:"dns_prior,omitempty"`

	// Guarantees is what this apply can honestly promise — whether the kill
	// switch is really there, whether DNS is really tunnelled, and the
	// sentences to show when either is false. Embedded so `dns_tunneled`,
	// `kill_switch` and `warnings` appear at the top level of the JSON, which
	// is the shape core and the UI were given.
	ExternalGuarantees
}

// Rule is the exact `ip rule` this plan installs, as a printable string. Used
// in the narration and in the dead-man's revert script, so that the thing
// removed is spelled the same way as the thing added.
func (p ExternalRoutePlan) ruleArgs(verb string) []string {
	return []string{"rule", verb, "from", p.SourceIP + "/32", "lookup", strconv.Itoa(p.Table), "priority", strconv.Itoa(p.Priority)}
}

// excludeArgs is one DNS/control-plane exclusion, expressed inside the tunnel
// table so it wins over that table's own default.
//
// `onlink` is not optional here and it is not cargo cult. The production bare
// metal carries 65.109.66.88/32 on enp41s0 with `default via 65.109.66.65
// proto static onlink` — a Hetzner-style layout where the gateway is not
// inside any interface subnet. Without onlink the kernel answers `Error:
// Nexthop has invalid gateway.` and the exclusion silently never installs,
// which was measured on the first attempt at exactly this.
func (p ExternalRoutePlan) excludeArgs(verb, prefix string) []string {
	args := []string{"route", verb, prefix, "via", p.MainGateway, "dev", p.MainDev}
	if verb == "add" {
		args = append(args, "onlink")
	}
	return append(args, "table", strconv.Itoa(p.Table))
}

// dnsRouteArgs is the MAIN-table /32 that makes the resolver reachable at all,
// and it is the non-obvious half of this whole feature.
//
// aardvark forwards from the HOST netns with the host's own source address, so
// its queries are resolved against the MAIN table — which has no route into the
// tunnel. Pointing `--dns-add` at an address the main table cannot reach does
// not degrade DNS for the routed container, it BLACK-HOLES IT FOR EVERY
// CONTAINER ON THE NETWORK — 30 of them here, including postgres, redis and the
// MCP gateway. That is a far worse outcome than the leak being closed, and it is
// the single most likely way a naive implementation breaks this host (§10).
//
// The prefix is a /32 to the resolver and nothing wider, so it moves the
// resolver's traffic and not the machine's: `ExternalRoute`'s "host egress must
// NOT change" confirmation still runs afterwards and would revert this whole
// apply if it ever did.
//
// `onlink` for the same measured reason excludeArgs carries it: a WireGuard
// device whose address is a /32 has no connected subnet containing the tunnel
// gateway, and without onlink the kernel answers `Error: Nexthop has invalid
// gateway.` and the route silently never installs.
func (p ExternalRoutePlan) dnsRouteArgs(verb, dns string) []string {
	args := []string{"route", verb, dns + "/32", "via", p.TunnelVia, "dev", p.TunnelDev}
	if verb == "add" {
		args = append(args, "onlink")
	}
	return args
}

// dnsUpdateArgs is the `podman network update` that moves the upstream.
//
// verb is "--dns-add" or "--dns-drop". Measured on the host 2026-09-08: both
// take repeated flags, both exit 0, and a `--dns-drop` of an address that is
// not there still exits 0 — which is what makes the dead-man's line safe to
// run unconditionally.
func (p ExternalRoutePlan) dnsUpdateArgs(verb string) []string {
	args := []string{"network", "update", p.DNSNetwork}
	for _, d := range p.DNSServers {
		args = append(args, verb, d)
	}
	return args
}

// aardvarkConfigDir is where netavark writes the per-network aardvark config.
// The UPSTREAM LIST IS THE FIRST LINE, alongside the bind address, and it is
// comma-separated when there is more than one:
//
//	10.89.0.1 9.9.9.9,149.112.112.112
//
// so an assertion has to read line 1 and split on both — a `grep` over the
// whole file would match a container's own A record further down and report
// success for a change that never landed (§10).
const aardvarkConfigDir = "/run/containers/networks/aardvark-dns"

// aardvarkUpstreams reads the upstreams a network's aardvark is forwarding to
// right now, as the kernel-visible truth rather than as podman's record of it.
//
// Absent file, unreadable file and empty list are all "no upstreams", never an
// error: this is called on the reassert timer and from the status verb, and a
// host that has never dialled must not produce a log full of failures.
func aardvarkUpstreams(ctx context.Context, r Runner, network string) []string {
	if network == "" {
		return nil
	}
	out, err := r.Run(ctx, "cat", aardvarkConfigDir+"/"+network)
	if err != nil {
		return nil
	}
	line := firstLine(out)
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		// Field 0 is the bind address; a bare line means no upstream at all,
		// which is this host's measured state today.
		return nil
	}
	var out2 []string
	for _, f := range fields[1:] {
		for _, part := range strings.Split(f, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out2 = append(out2, part)
			}
		}
	}
	return out2
}

// aardvarkBindAddress is field 0 of that same first line — the address the
// routed container actually sends its queries to. Used to prove §4.5 end to
// end without hardcoding a gateway.
func aardvarkBindAddress(ctx context.Context, r Runner, network string) string {
	if network == "" {
		return ""
	}
	out, err := r.Run(ctx, "cat", aardvarkConfigDir+"/"+network)
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(firstLine(out)))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// ExternalRouteResult is what one apply measured, whether it worked or not.
// The before/after pairs are populated on the failure paths too: "it did not
// work" is worth much more next to the four addresses that prove it.
type ExternalRouteResult struct {
	Plan ExternalRoutePlan `json:"plan"`

	HostBefore string `json:"host_before"`
	HostAfter  string `json:"host_after,omitempty"`
	HostHeld   bool   `json:"host_held"`
	HostMoved  bool   `json:"host_moved"`

	ContainerBefore string `json:"container_before,omitempty"`
	ContainerAfter  string `json:"container_after,omitempty"`

	Confirmed bool   `json:"confirmed"`
	Reverted  bool   `json:"reverted"`
	Reason    string `json:"reason,omitempty"`

	DeadmanExpiresAt  string `json:"deadman_expires_at,omitempty"`
	DeadmanStillArmed bool   `json:"deadman_still_armed"`
}

// PlanExternalRoute resolves the container, the table and the exclusions, and
// refuses anything this host cannot safely be asked to do — changing nothing.
//
// The refusals are ordered by how early they can be known, so a host that was
// never a candidate never gets as far as running a probe container.
func PlanExternalRoute(ctx context.Context, spec ExternalRouteSpec) (*ExternalRoutePlan, error) {
	spec = spec.withDefaults()
	plan := &ExternalRoutePlan{
		Container:    spec.Container,
		Table:        spec.Table,
		Priority:     spec.Priority,
		ExpectEgress: spec.ExpectEgress,
		// Non-nil from the very first line, so every early return below —
		// every refusal — still marshals `"warnings": []` rather than null.
		ExternalGuarantees: ExternalGuarantees{Warnings: []string{}},
	}
	if strings.TrimSpace(spec.Container) == "" {
		return nil, fmt.Errorf("container is required: it names the workload whose egress moves, and resolving it is also what proves the rule cannot match this machine")
	}
	runner := spec.Runner
	if runner == nil {
		// Deliberately an error and not a default. This package cannot
		// construct a working runner on its own — the base shellout lives in
		// internal/ops, which imports this package — and PrivilegedRunner's
		// zero value has a nil Inner that panics on first use. A caller that
		// forgot to supply one has to be told, not handed something that dies
		// halfway through a route change.
		return nil, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	// `ip` first, because without it nothing below can be written and the
	// honest failure is "this host cannot do this at all".
	if _, err := runner.Run(ctx, "ip", "-V"); err != nil {
		plan.Refusal = "this host has no usable `ip` command, so it cannot write a routing policy rule for anything"
		return plan, nil
	}

	rt := spec.Runtime
	if !rt.Present() {
		detected, err := DetectContainerRuntime(ctx, runner)
		if err != nil || !detected.Present() {
			plan.Refusal = NoContainerRuntimeRefusal
			return plan, nil
		}
		rt = detected
	}
	plan.Runtime = rt.Name

	id, ip, err := resolveContainerSource(ctx, runner, rt, spec.Container)
	if err != nil {
		// A container that cannot be resolved is a REFUSAL and never a guess.
		// The IP this rule keys on is Docker IPAM and moves whenever the
		// container is recreated; substituting a remembered or assumed address
		// would eventually point the rule at whatever moved into that slot.
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.ContainerID, plan.SourceIP = id, ip

	if err := mustBeSingleHost(ip); err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	if err := mustNotBeThisHost(ctx, runner, ip); err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}

	via, dev, err := tableDefault(ctx, runner, spec.Table)
	if err != nil {
		// Pointing a rule at an empty table does not fall through to main —
		// it black-holes the container. Refusing is the difference between
		// "the tunnel is not up" and "the workspace lost the internet".
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.TunnelVia, plan.TunnelDev = via, dev

	gw, mdev, err := mainDefault(ctx, runner)
	if err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.MainGateway, plan.MainDev = gw, mdev

	exclusions, killSwitch := planExternalExclusions(ctx, spec.ControlPlane)
	plan.Exclusions = exclusions

	// The DNS half's PLAN-time preconditions (§4.1 and §4.2). Failing any of
	// them leaves the four fields empty, which every function below reads as
	// "not attempted" — the route itself is unaffected, because a route that
	// failed because DNS could not be tunnelled would regress behaviour that
	// has shipped.
	planTunnelDNS(ctx, runner, rt, spec, plan)

	// A route that is about to be applied IS in force for the purposes of the
	// warning: this plan is what the apply will do, and the warning has to
	// reach the screen with the result rather than after somebody notices.
	//
	// dnsTunneled is FALSE here even when the DNS half is fully planned, and
	// that is not a rounding-down. §4 says the flag may only be set once the
	// APPLY-time proofs have passed, and a plan has by definition applied
	// nothing — `--plan` changes no state, so on a plan the resolver has
	// genuinely not moved. applyTunnelDNS is the only place it can become true.
	plan.ExternalGuarantees = newExternalGuarantees(true, killSwitch, false)
	return plan, nil
}

// planTunnelDNS resolves the DNS half, or leaves it unresolved.
//
// It NEVER sets plan.Refusal and never returns an error. That is the whole
// posture of §4: any failure here means "route exactly as this host does
// today, and keep saying DNS is not tunnelled" — the honest, already-shipped
// behaviour — rather than "refuse to connect". The DNS leak is the thing
// being fixed; failing to fix it must not become a worse bug than having it.
func planTunnelDNS(ctx context.Context, r Runner, rt ContainerRuntime, spec ExternalRouteSpec, plan *ExternalRoutePlan) {
	if !spec.TunnelDNS {
		return
	}
	// §4.1 — a profile with no `DNS =` line has nothing to point aardvark at.
	var servers []string
	for _, d := range spec.DNS {
		d = strings.TrimSpace(d)
		// Re-validated here even though externalup.go:236 already did it. This
		// value ends up inside a dead-man's shell script, and "somebody else
		// checked" is not the standard for a string that reaches a script that
		// runs unattended on a machine whose network has just gone.
		if ip := net.ParseIP(d); ip != nil && ip.To4() != nil {
			servers = append(servers, d)
		}
	}
	if len(servers) == 0 {
		return
	}
	// `podman network update` is podman-only — docker has no equivalent verb,
	// so on a docker host the honest outcome is the warning, not an attempt.
	if rt.Name != "podman" {
		return
	}
	// §4.2 — the ABSOLUTE path, resolved BEFORE anything is touched. If it
	// does not resolve, the change cannot be reverted by the dead-man, so it
	// must not be made.
	podmanPath, err := lookupExternalBinary(rt.Name)
	if err != nil || podmanPath == "" {
		return
	}
	network, err := resolveContainerNetwork(ctx, r, rt, plan.ContainerID)
	if err != nil || network == "" {
		return
	}
	plan.DNSServers = servers
	plan.DNSNetwork = network
	plan.DNSPodmanPath = podmanPath
	plan.DNSPrior = aardvarkUpstreams(ctx, r, network)
}

// resolveContainerNetwork names the podman network whose aardvark upstream
// this apply would move.
//
// It asks `inspect` rather than assuming `aw-remote-host`, because §9 records
// that as the door this feature closes if it is written as a constant: today
// there is exactly one network on this host, and the first day there are two,
// a constant would point the change at the wrong one silently.
//
// More than one attachment is refused for the same reason resolveContainerSource
// refuses it — this path moves ONE network's resolver, and picking one of
// several would move the DNS of containers that have nothing to do with the
// tunnel while leaving the routed container's own other network alone.
func resolveContainerNetwork(ctx context.Context, r Runner, rt ContainerRuntime, containerID string) (string, error) {
	const format = "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"
	out, err := r.Run(ctx, rt.Name, "inspect", "-f", format, containerID)
	if err != nil {
		return "", fmt.Errorf("could not resolve the podman network carrying %s (%s inspect: %v)", containerID, rt.Name, err)
	}
	names := strings.Fields(strings.TrimSpace(out))
	switch len(names) {
	case 0:
		return "", fmt.Errorf("container %s reports no podman network, so there is no aardvark upstream to move", containerID)
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("container %s is attached to %d networks (%s) and this path moves exactly one network's resolver — refusing rather than picking one", containerID, len(names), strings.Join(names, ", "))
	}
}


// ExternalRoute moves one container's egress onto the external tunnel, and
// reverts if it cannot prove that worked.
//
// The sequence is deliberately the same shape as UseExit's, for the same
// reasons, in the same order: measure both addresses, arm the dead-man's
// switch, pin the exclusions, install the rule, confirm BOTH halves, revert
// anything unconfirmed. The result is returned alongside any error rather than
// instead of it — a failed apply that has already reverted is a normal, safe
// outcome and the caller still wants the evidence.
func ExternalRoute(ctx context.Context, spec ExternalRouteSpec, progress Progress) (ExternalRouteResult, error) {
	spec = spec.withDefaults()
	runner := spec.Runner
	if runner == nil {
		// Deliberately an error and not a default. This package cannot
		// construct a working runner on its own — the base shellout lives in
		// internal/ops, which imports this package — and PrivilegedRunner's
		// zero value has a nil Inner that panics on first use. A caller that
		// forgot to supply one has to be told, not handed something that dies
		// halfway through a route change.
		return ExternalRouteResult{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	plan, err := PlanExternalRoute(ctx, spec)
	if err != nil {
		return ExternalRouteResult{}, err
	}
	res := ExternalRouteResult{Plan: *plan}
	if plan.Refusal != "" {
		progress.emit("error", plan.Refusal)
		res.Reason = plan.Refusal
		return res, fmt.Errorf("%w: %s", ErrScopeRefused, plan.Refusal)
	}

	progress.emit("info", "routing container %s (%s) out through %s via %s, table %d",
		plan.Container, plan.SourceIP, plan.TunnelDev, plan.TunnelVia, plan.Table)
	progress.emit("info", "the rule is anchored on %s/32 — a single host address that belongs to that container and cannot be this machine.", plan.SourceIP)
	for _, ex := range plan.Exclusions {
		progress.emit("info", "  %s stays OUTSIDE the tunnel", ex)
	}
	// Loudly, and in the same stream as everything else that just happened.
	// The kill switch going missing used to be completely silent.
	//
	// The DNS warning is held back when the DNS half is about to be ATTEMPTED:
	// at plan time the verdict is genuinely not known yet (§4's proofs are all
	// apply-time), and emitting "DNS IS NOT FULLY TUNNELLED" here and then
	// reporting dns_tunneled:true in the same object would make the narration
	// contradict the result. It is re-emitted below, after the apply, from
	// what was actually proven.
	dnsPending := len(plan.DNSServers) > 0
	for _, w := range plan.Warnings {
		if dnsPending && w == DNSNotTunnelledWarning {
			continue
		}
		progress.emit("warning", "%s", w)
	}
	if dnsPending {
		progress.emit("info", "DNS: will move network %s's resolver upstream to %s — this affects EVERY container on that network, not only %s, because aardvark's upstream is scoped to the network and there is no per-container form of it",
			plan.DNSNetwork, strings.Join(plan.DNSServers, ", "), plan.Container)
	}

	// TWO baselines, and the host's is the one that is not optional: it is
	// what the confirmation asserts held, and without it there is no way to
	// prove afterwards that the machine was left alone.
	host, err := PublicIP(ctx)
	if err != nil {
		return res, fmt.Errorf("could not measure this host's own public IP before the change, so there would be no way to prove afterwards that the machine's egress did not move — refusing to touch anything: %w", err)
	}
	res.HostBefore = host.IP
	progress.emit("info", "host egress before (must NOT change): %s", host.IP)

	before := measureNetnsEgress(ctx, runner, plan.Runtime, plan.ContainerID)
	res.ContainerBefore = before.IP
	if before.IP == "" && spec.ExpectEgress == "" {
		return res, fmt.Errorf("could not measure the container's egress before the change (%s), and no expected egress was given, so the result could not be confirmed either way", before.Error)
	}
	progress.emit("info", "container egress before (MUST change): %s", before.IP)

	// ARM FIRST. Everything below this line can fail, hang or be killed, and
	// the container still comes back.
	armed, err := Arm(ArmSpec{
		After:           spec.Deadman,
		ExitNode:        fmt.Sprintf("external tunnel %s for container %s", plan.TunnelDev, plan.Container),
		ExclusionRevert: externalRevertScript(runner, *plan),
	})
	if err != nil {
		return res, fmt.Errorf("refusing to install the rule because the dead-man's switch could not be armed: %w", err)
	}
	res.DeadmanExpiresAt = armed.ExpiresAt
	progress.emit("info", "dead-man's switch ARMED (pid %d) — this route reverts itself at %s unless this run confirms it", armed.PID, armed.ExpiresAt)

	// Exclusions BEFORE the rule, so there is no window in which the container
	// is on the tunnel with its resolvers inside it.
	dnsTunneled, err := applyExternalRoute(ctx, runner, *plan, progress)
	if err != nil {
		res.Reverted, res.DeadmanStillArmed = revertExternalAfterFailure(ctx, runner, *plan, progress)
		return res, err
	}

	// Rebuilt from what the apply PROVED rather than from what it planned.
	// This is the one place DNSTunneled can become true, and it is downstream
	// of every §4 check — a plan that intended to tunnel DNS and an apply that
	// managed to are different facts, and only the second one may be reported.
	plan.ExternalGuarantees = newExternalGuarantees(true, plan.KillSwitch, dnsTunneled)
	res.Plan = *plan
	if dnsPending {
		if dnsTunneled {
			progress.emit("info", "DNS: aardvark's upstream for network %s is now %s, reached through %s — the leak documented in planExternalExclusions is closed for every container on that network while this tunnel is up",
				plan.DNSNetwork, strings.Join(plan.DNSServers, ", "), plan.TunnelDev)
		} else {
			progress.emit("warning", "%s", DNSNotTunnelledWarning)
		}
	}

	progress.emit("info", "rule installed — confirming BOTH halves (up to %s): that the container's egress moved, and that this machine's did not...", spec.ConfirmTimeout)
	confirm := confirmExternal(ctx, runner, *plan, externalConfirmSpec{
		hostBefore:      res.HostBefore,
		containerBefore: res.ContainerBefore,
		expected:        spec.ExpectEgress,
	}, spec.ConfirmTimeout, progress)

	res.HostAfter, res.HostHeld, res.HostMoved = confirm.hostAfter, confirm.hostHeld, confirm.hostMoved
	res.ContainerAfter = confirm.containerAfter
	res.Confirmed, res.Reason = confirm.ok, confirm.reason

	if !confirm.ok {
		if confirm.hostMoved {
			// Named separately because it is not the same event. A tunnel that
			// does not forward is a feature failing; a host whose address moved
			// is this machine having been changed in the one way it must never
			// be, and whoever is watching needs to read that sentence rather
			// than infer it from two addresses.
			progress.emit("error", "REVERTING — THIS MACHINE'S OWN EGRESS MOVED. That is a failed apply regardless of what the container is doing, and it is the exact failure this path was built to make impossible.")
		}
		progress.emit("warning", "REVERTING — a route that cannot be confirmed is the failure this sequence exists to prevent, not a partial success.")
		if err := revertExternalRoute(ctx, runner, *plan, progress); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("error", "the revert itself FAILED (%v). The dead-man's switch is still armed and fires at %s; leaving it armed on purpose.", err, armed.ExpiresAt)
			return res, fmt.Errorf("the external route could not be confirmed and the revert failed: %s", confirm.reason)
		}
		res.Reverted = true
		if _, err := Disarm(); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("warning", "the route was reverted but the dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
		}
		return res, fmt.Errorf("the external route was NOT confirmed and has been reverted: %s", confirm.reason)
	}

	if _, err := Disarm(); err != nil {
		res.DeadmanStillArmed = true
		return res, fmt.Errorf("egress was confirmed, but the dead-man's switch could not be stood down (%w) — it will revert this route at %s", err, armed.ExpiresAt)
	}
	progress.emit("info", "container egress confirmed as %s with the host held at %s; dead-man's switch stood down.", res.ContainerAfter, res.HostAfter)

	// Persisted LAST and only on success, because this record is what Reassert
	// re-applies on a timer. A record written for an apply that did not
	// confirm would be re-asserted forever.
	return res, saveExternalRouteState(*plan)
}

// ExternalUnroute removes the rule and the exclusions and reports where the
// container's traffic goes now.
//
// Deliberately NOT gated by any of the refusals above, for the same reason
// ClearExit is not: it is the way OFF the tunnel, and an undo that refuses is
// one that fails exactly when it is most needed.
func ExternalUnroute(ctx context.Context, spec ExternalRouteSpec, progress Progress) (ExternalRouteResult, error) {
	spec = spec.withDefaults()
	runner := spec.Runner
	if runner == nil {
		// Deliberately an error and not a default. This package cannot
		// construct a working runner on its own — the base shellout lives in
		// internal/ops, which imports this package — and PrivilegedRunner's
		// zero value has a nil Inner that panics on first use. A caller that
		// forgot to supply one has to be told, not handed something that dies
		// halfway through a route change.
		return ExternalRouteResult{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	// Undo what was RECORDED, not what a fresh plan would produce. The
	// container's IP moves whenever it is recreated, so re-planning here would
	// compute a rule that was never installed and leave the real one behind.
	plan, err := loadExternalRouteState()
	if err != nil || plan == nil {
		progress.emit("info", "no external route is recorded on this host; nothing to undo")
		return ExternalRouteResult{Reverted: true}, nil
	}
	res := ExternalRouteResult{Plan: *plan}

	if err := revertExternalRoute(ctx, runner, *plan, progress); err != nil {
		return res, err
	}
	res.Reverted = true
	if _, err := Disarm(); err != nil {
		progress.emit("warning", "the route was removed but a dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
	}
	if err := clearExternalRouteState(); err != nil {
		return res, err
	}

	after := measureNetnsEgress(ctx, runner, plan.Runtime, plan.ContainerID)
	res.ContainerAfter = after.IP
	if host, err := PublicIP(ctx); err == nil {
		res.HostAfter = host.IP
	}
	progress.emit("info", "external route removed — container egress is now %s", after.IP)
	return res, nil
}

// Reassert puts back whatever a rule flush took away, and is a no-op when
// nothing is recorded or nothing is missing.
//
// This is not defensive programming for a hypothetical. On the production bare
// metal `systemd-networkd` is restarted by the daily unattended apt upgrade and
// flushes every routing policy rule it does not own; the hub's own rules at
// priority 100-107 are missing right now for exactly that reason, on a
// container that has been up 15 hours without restarting. Routes inside table
// 200 survived that flush and the rules did not, so this checks both but
// expects to be replacing the rule.
//
// It returns what it had to put back, so a caller can log a flush having
// happened rather than silently papering over it.
func Reassert(ctx context.Context, r Runner) ([]string, error) {
	plan, err := loadExternalRouteState()
	if err != nil || plan == nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("no command runner was supplied to re-assert the external route for %s", plan.Container)
	}
	restored, updated, gone, err := reassertPlan(ctx, r, *plan)
	if err != nil {
		return restored, err
	}
	switch {
	case gone:
		// The container this record was built for no longer exists. reassertPlan
		// already took the rule and its exclusions out; clearing the record is
		// what keeps the NEXT pass from doing this same work forever, and — the
		// part that actually matters — keeps a stale record from ever being
		// re-read as if it still described something real.
		if cerr := clearExternalRouteState(); cerr != nil {
			return restored, fmt.Errorf("container %s no longer resolves, and the stale external-route record could not be cleared: %w", plan.Container, cerr)
		}
	case updated != nil:
		// Same container, a new address. Persisted via state.Update
		// (load-modify-save) so this write cannot clobber whatever else the
		// daemon recorded between the read above and now — see state.Update's
		// own comment for the race this replaced.
		if serr := saveExternalRouteState(*updated); serr != nil {
			return restored, fmt.Errorf("resolved a new address (%s) for %s but could not persist it: %w", updated.SourceIP, plan.Container, serr)
		}
	}
	return restored, nil
}

// reassertPlan is Reassert with the state read (and the state write) already
// factored out, which is what makes the behaviour testable without a state
// file on the machine running `go test`: it only ever talks to Runner.
//
// It re-resolves the container by its recorded ContainerID through the
// runtime on EVERY pass, not only when the rule is missing — the same lookup
// PlanExternalRoute used to build this record in the first place. That is the
// actual fix here, not a defensive extra: a rule that matches the RECORDED
// SourceIP can be sitting untouched in the kernel while that address now
// belongs to a different container than the one this record was built for,
// because Docker handed the old address to whatever it started next.
// ruleInstalled alone cannot see that — it only proves a rule for the old
// address still exists, never that the old address still means what the
// record says it does. One inspect per ReassertInterval pass is the cost of closing that,
// and ReassertInterval's own comment already treats a cheap check on a short
// interval as the entire point of this loop.
//
// It returns, instead of writing anything itself: what it had to restore,
// the updated plan when the address moved (nil when it didn't), and whether
// the container is gone. Reassert turns that into exactly one state write.
func reassertPlan(ctx context.Context, r Runner, plan ExternalRoutePlan) (restored []string, updated *ExternalRoutePlan, gone bool, err error) {
	rt := ContainerRuntime{Name: plan.Runtime}
	_, ip, resolveErr := resolveContainerSource(ctx, r, rt, plan.ContainerID)
	if resolveErr != nil {
		// The container this rule was built for no longer resolves under the
		// id that was recorded — recreated, or removed outright. Putting the
		// rule back, or leaving it in place, would keep a /32 pointed at an
		// address any other container on this Docker network is free to
		// receive next, silently handing it this tunnel. Take the rule and its
		// exclusions out; there is nothing left here to reassert.
		if ok, rerr := ruleInstalled(ctx, r, plan); rerr == nil && ok {
			if _, err := r.Run(ctx, "ip", plan.ruleArgs("del")...); err != nil {
				return restored, nil, false, fmt.Errorf("container %s (%s) no longer resolves (%v), and the orphaned rule for %s could not be removed: %w", plan.Container, plan.ContainerID, resolveErr, plan.SourceIP, err)
			}
			restored = append(restored, "removed orphaned rule from "+plan.SourceIP+"/32 ("+plan.Container+" no longer exists)")
		}
		for _, prefix := range plan.Exclusions {
			ok, rerr := routeInstalled(ctx, r, plan, prefix)
			if rerr != nil || !ok {
				continue
			}
			if _, err := r.Run(ctx, "ip", plan.excludeArgs("del", prefix)...); err != nil {
				return restored, nil, false, fmt.Errorf("container %s no longer resolves, and the orphaned exclusion %s could not be removed: %w", plan.Container, prefix, err)
			}
			restored = append(restored, "removed orphaned exclusion "+prefix)
		}
		// The resolver moved for this container's sake, so it comes back when
		// the container does not exist any more. Leaving 30 containers pointed
		// at a VPN resolver on behalf of a workload that is gone is the same
		// orphan the rule above is, with a much wider blast radius.
		if len(plan.DNSServers) > 0 {
			if err := revertTunnelDNS(ctx, r, plan); err != nil {
				return restored, nil, false, fmt.Errorf("container %s no longer resolves, and the orphaned DNS upstream on %s could not be dropped: %w", plan.Container, plan.DNSNetwork, err)
			}
			restored = append(restored, "dropped orphaned DNS upstream on "+plan.DNSNetwork+" ("+plan.Container+" no longer exists)")
		}
		return restored, nil, true, nil
	}

	if ip != plan.SourceIP {
		// Same container id, a new IPAM address — a network reconnect, or a
		// recreate that happened to keep the id. PlanExternalRoute proves this
		// invariant on the initial apply; a reassert re-resolving to a new
		// address has to prove it again before installing anything, or a
		// container that migrated to host networking would route the host
		// itself — exactly the failure this invariant exists to prevent.
		if err := mustNotBeThisHost(ctx, r, ip); err != nil {
			return restored, nil, false, fmt.Errorf("refusing to re-assert %s at its new address: %w", plan.Container, err)
		}
		// The old rule, if it is still there, now matches whoever inherited
		// that address, not this container, so it has to come out before the
		// new one goes in; there must be no window with both installed.
		if ok, rerr := ruleInstalled(ctx, r, plan); rerr == nil && ok {
			if _, err := r.Run(ctx, "ip", plan.ruleArgs("del")...); err != nil {
				return restored, nil, false, fmt.Errorf("could not remove the stale rule for %s before re-asserting the new address %s: %w", plan.SourceIP, ip, err)
			}
		}
		next := plan
		next.SourceIP = ip
		restored = append(restored, "container "+plan.Container+" moved to "+ip+" — record updated")
		plan = next
		updated = &next
	}

	present, perr := ruleInstalled(ctx, r, plan)
	if perr != nil {
		return restored, updated, false, perr
	}
	if !present {
		if _, err := r.Run(ctx, "ip", plan.ruleArgs("add")...); err != nil {
			return restored, updated, false, fmt.Errorf("could not re-assert the external route rule for %s: %w", plan.Container, err)
		}
		restored = append(restored, "ip rule from "+plan.SourceIP+"/32")
	}
	for _, prefix := range plan.Exclusions {
		ok, err := routeInstalled(ctx, r, plan, prefix)
		if err != nil || ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.excludeArgs("add", prefix)...); err != nil {
			return restored, updated, false, fmt.Errorf("could not re-assert the exclusion %s: %w", prefix, err)
		}
		restored = append(restored, "exclusion "+prefix)
	}

	// THE DNS HALF, re-checked on the same timer and for the same measured
	// reason the rule is. Two things take it away without telling anyone: the
	// daily unattended-apt flush that systemd-networkd does to the main-table
	// /32, and anything that rewrites the network's config (a podman restart,
	// a `network reload`) to the aardvark upstream. Neither breaks loudly —
	// the first black-holes the resolver, the second silently reopens the leak
	// this feature exists to close — so both are checked here rather than
	// discovered later.
	//
	// Asserted on LINE 1 of the aardvark config, never on a grep over the
	// file: the upstream list shares that line with the bind address, and the
	// records below it can contain an address that would match a naive grep
	// and report success for a change that never landed (§10).
	if len(plan.DNSServers) > 0 {
		for _, dns := range plan.DNSServers {
			if ok, err := dnsRouteInstalled(ctx, r, dns); err != nil || ok {
				continue
			}
			if _, err := r.Run(ctx, "ip", plan.dnsRouteArgs("add", dns)...); err != nil {
				return restored, updated, false, fmt.Errorf("could not re-assert the main-table route to the tunnel resolver %s, without which every container on %s loses external DNS: %w", dns, plan.DNSNetwork, err)
			}
			restored = append(restored, "main-table route to resolver "+dns)
		}
		upstreams := aardvarkUpstreams(ctx, r, plan.DNSNetwork)
		var missing []string
		for _, dns := range plan.DNSServers {
			if !containsAddress(upstreams, dns) {
				missing = append(missing, dns)
			}
		}
		if len(missing) > 0 {
			if _, err := r.Run(ctx, plan.DNSPodmanPath, plan.dnsUpdateArgs("--dns-add")...); err != nil {
				return restored, updated, false, fmt.Errorf("could not re-assert %s's aardvark upstream (%s): %w", plan.DNSNetwork, strings.Join(missing, ", "), err)
			}
			restored = append(restored, "aardvark upstream on "+plan.DNSNetwork+" ("+strings.Join(missing, ", ")+")")
		}
	}
	return restored, updated, false, nil
}

// ReassertInterval is how often the daemon re-checks the rule.
//
// The flush this defends against is rare — daily, when the unattended apt
// upgrade restarts systemd-networkd — but the check is two `ip show` reads and
// the failure it catches is silent: a flushed rule does not break the
// container, it quietly puts it back on the host's own egress, so nothing
// anywhere reports an error and the feature is simply not in force any more.
// A cheap check on a short interval is the only thing that turns that back
// into something observable.
const ReassertInterval = 30 * time.Second

// ReassertLoop re-asserts the recorded external route until ctx is cancelled,
// reporting each time it actually had to put something back.
//
// It runs one pass immediately: a host coming back from a reboot has an empty
// rule table and a state file that still records a route, and waiting a full
// interval to notice would be a gap for no reason. Errors are reported and
// never fatal — the same bargain firewall.SelfHeal makes at the same point in
// startup, and for the same reason: a self-heal that could not run must not
// stop this process from linking at all.
func ReassertLoop(ctx context.Context, r Runner, report func(restored []string, err error)) {
	pass := func() {
		restored, err := Reassert(ctx, r)
		if report != nil && (len(restored) > 0 || err != nil) {
			report(restored, err)
		}
	}
	pass()
	ticker := time.NewTicker(ReassertInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass()
		}
	}
}

// --- resolution -------------------------------------------------------------

// resolveContainerSource turns a container name into (id, single IPv4).
//
// It asks the RUNTIME rather than accepting an address from a caller, and that
// is the load-bearing part of this whole file: an address that came out of
// `inspect` belongs to a container that exists on this host right now. The
// correlation that makes this usable from a control plane was measured on
// 2026-09-02 — the hostname host A reports for itself (`e91aacf5a3a3`) IS the
// container id host B knows it by — so a caller can name the host it means and
// never has to send an IP that might have been recycled.
func resolveContainerSource(ctx context.Context, r Runner, rt ContainerRuntime, name string) (string, string, error) {
	const format = "{{.Id}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"
	out, err := r.Run(ctx, rt.Name, "inspect", "-f", format, name)
	if err != nil {
		return "", "", fmt.Errorf("container %q could not be resolved on this host (%s inspect: %v) — refusing to guess an address, because this rule keys on runtime IPAM that moves whenever a container is recreated", name, rt.Name, err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 {
		return "", "", fmt.Errorf("container %q exists but reports no IPv4 address, so there is nothing to anchor a rule on", name)
	}
	id := fields[0]
	var ips []string
	for _, f := range fields[1:] {
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			ips = append(ips, f)
		}
	}
	switch len(ips) {
	case 0:
		return "", "", fmt.Errorf("container %q exists but reports no IPv4 address, so there is nothing to anchor a rule on", name)
	case 1:
		return id, ips[0], nil
	default:
		// Routing one of several attachments would move some of that
		// container's traffic and not the rest, which is worse than not doing
		// it: the egress would depend on which network a given connection
		// happened to use.
		return "", "", fmt.Errorf("container %q is attached to %d networks (%s) and this path routes exactly one source address — refusing rather than picking one and moving only part of its traffic", name, len(ips), strings.Join(ips, ", "))
	}
}

// mustBeSingleHost is the /16 guard, as an assertion rather than a comment.
//
// Measured on the production bare metal 2026-09-02: 172.18.0.0/16 carries
// aw-backend, aw-caddy, aw-headscale, aw-derper, aw-sandbox and
// agents-platform-multitenant alongside the workspace's own container. A rule
// written `from 172.18.0.0/16` would put all of production on a residential
// line in one command, so the only address shape this file accepts is a single
// host.
func mustBeSingleHost(ip string) error {
	if strings.Contains(ip, "/") {
		return fmt.Errorf("refusing the source %q: this path installs a /32 rule and nothing wider, because the container networks on this host are shared with production services that must not be routed", ip)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("refusing the source %q: it is not a single IPv4 address", ip)
	}
	return nil
}

// mustNotBeThisHost proves the rule excludes the machine, rather than assuming
// it. A container address that is also one of this host's own addresses would
// route the host, which is the failure the invariant exists to prevent.
func mustNotBeThisHost(ctx context.Context, r Runner, ip string) error {
	out, err := r.Run(ctx, "ip", "-4", "-o", "addr", "show")
	if err != nil {
		return fmt.Errorf("could not enumerate this host's own addresses, so it could not be proven that %s is not one of them — refusing: %w", ip, err)
	}
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, ip+"/") || f == ip {
				return fmt.Errorf("refusing to route %s: it is one of THIS MACHINE's own addresses, and moving it would move the host's egress — the exact failure this feature was rewritten to make impossible", ip)
			}
		}
	}
	return nil
}

// tableDefault reads the default route out of the tunnel's table, and refuses
// an empty one. An `ip rule` pointing at a table with no default does not fall
// through to main; it black-holes every packet that matches.
func tableDefault(ctx context.Context, r Runner, table int) (via, dev string, err error) {
	out, err := r.Run(ctx, "ip", "route", "show", "table", strconv.Itoa(table))
	if err != nil {
		return "", "", fmt.Errorf("routing table %d could not be read, so it cannot be proven to carry a working default route: %w", table, err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "via":
				via = f[i+1]
			case "dev":
				dev = f[i+1]
			}
		}
		if dev != "" {
			return via, dev, nil
		}
	}
	return "", "", fmt.Errorf("routing table %d carries no default route, so a rule pointing at it would black-hole the container instead of tunnelling it — refusing. On this host that table belongs to aw-vpn-hub; check that the hub is up", table)
}

// mainDefault is where the exclusions are sent instead of into the tunnel.
func mainDefault(ctx context.Context, r Runner) (gw, dev string, err error) {
	out, err := r.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return "", "", fmt.Errorf("could not read this host's own default route, which is where the exclusions have to point: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "via":
				gw = f[i+1]
			case "dev":
				dev = f[i+1]
			}
		}
		if gw != "" && dev != "" {
			return gw, dev, nil
		}
	}
	return "", "", fmt.Errorf("this host has no default route with both a gateway and a device, so there is nowhere to send the exclusions")
}

// planExternalExclusions holds the CONTROL PLANE outside the tunnel, and
// nothing else.
//
// DNS GOES THROUGH THE VPN — decided by Frederico, 2026-09-05, and this
// function used to do the opposite. It pinned every nameserver it could find
// outside the tunnel, which meant a user who turned the VPN on still resolved
// through their ISP: the single most recognisable way a VPN leaks, and it was
// on by default. Those exclusions are gone.
//
// The reasoning that ORIGINALLY put them here was real but narrower than it
// looked. With the rule in place ICMP passed, TCP passed and UDP/53 did not,
// so "the workspace leaves via the hub" became "the workspace has no DNS".
// What was actually missing was the local fabric, not the resolvers: the
// tunnel's table had a default and no route to the networks the container
// talks to. That is now fixed properly and at the right layer — externalup.go
// builds the table with every CONNECTED route before the default (its
// invariant 1) — so the container reaches its own resolver the same way it
// reaches Postgres and Redis, over the bridge route, with no /32 exclusion
// involved. Measured on this deployment: the resolver a container asks is
// 10.89.0.1 (aardvark, in this netns), which is inside 10.89.0.0/24 dev
// podman1 — a connected route, already in the table. Dropping the nameserver
// exclusions therefore does not break internal name resolution.
//
// THE CONTROL PLANE EXCLUSION STAYS, and it is not a nicety — it is the kill
// switch. The core has to reach aw-backend to issue `external-down`, so
// without this pin a half-broken tunnel would block its own Disconnect: the
// recovery surface would go down with the thing being recovered, which is the
// exact failure this whole module is built around. Frederico's instruction
// carved it out explicitly ("e o que mais for imprescindível pro controle").
// It rides the same reasoning, and the same mechanism, as usexit.go's: a /32
// inside the tunnel's own table pointing back at the main gateway, which beats
// that table's default.
//
// KNOWN AND DELIBERATE GAP: this makes the routed container's DNS leave
// through the tunnel only for the resolvers it addresses DIRECTLY. On this
// deployment glibc sends essentially everything to 10.89.0.1 first, and from
// aardvark onward the query no longer carries the container's source address,
// so no source-anchored rule can reach it — those queries still leave via the
// host. Closing that needs aardvark's own upstream to move, which podman 4.3.1
// cannot express and a POSIX-sh dead-man cannot revert; see the card. Until
// then ExternalStatusReport.DNSTunneled reports this honestly rather than
// letting a screen imply otherwise.
//
// Loopback and link-local are dropped: a /32 exclusion for 127.0.0.11 would be
// meaningless and a route for it on the main gateway would be wrong.
// It returns the list AND whether the kill switch is actually there, because
// after Layer 1 those two are no longer the same question. The exclusion list
// used to be kept non-empty by the nameserver pins, so "empty" could only mean
// "nothing to pin". Now an apply whose control plane failed to resolve
// produces zero exclusions and is byte-for-byte identical to a healthy one —
// the kill switch silently absent, on the one path whose whole job is to
// survive the tunnel going bad. A bool is the difference between "computed
// successfully, nothing to add" and "could not pin the thing that lets you
// switch this off".
func planExternalExclusions(ctx context.Context, controlPlane string) (exclusions []string, killSwitch bool) {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
			return
		}
		prefix := ip + "/32"
		if seen[prefix] {
			return
		}
		seen[prefix] = true
		out = append(out, prefix)
	}

	for _, ip := range resolveControlPlaneIPs(ctx, controlPlane) {
		add(ip)
	}
	// The kill switch is the ROUTES, not the intent: a control plane that was
	// configured but resolved to nothing usable (no A record, only IPv6, a
	// resolver that timed out) pins nothing, and saying otherwise would be the
	// exact false reassurance this return value exists to remove.
	return out, len(out) > 0
}

// resolveControlPlaneIPs is best-effort by design: a control plane that cannot
// be resolved right now is a reason to say so, not a reason to refuse to route
// — the dead-man's switch is what covers the case where the pin was wrong.
func resolveControlPlaneIPs(ctx context.Context, base string) []string {
	host := strings.TrimSpace(base)
	if host == "" {
		return nil
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

// --- apply / revert ---------------------------------------------------------

// applyExternalRoute installs the exclusions, then the rule, then — only if
// both of those worked — attempts the DNS half.
//
// It returns whether DNS ended up tunnelled ALONGSIDE the error rather than
// folding one into the other, because they are different kinds of outcome: an
// error here means the ROUTE failed and everything reverts, while a false
// dnsTunneled means the route is fine and DNS is exactly as leaky as it was
// before this feature existed. Conflating them would make a failed DNS proof
// tear down a working tunnel (§4).
func applyExternalRoute(ctx context.Context, r Runner, plan ExternalRoutePlan, progress Progress) (dnsTunneled bool, err error) {
	for _, prefix := range plan.Exclusions {
		if ok, err := routeInstalled(ctx, r, plan, prefix); err == nil && ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.excludeArgs("add", prefix)...); err != nil {
			return false, fmt.Errorf("could not hold %s outside the tunnel, and routing the container without that would leave it without DNS: %w", prefix, err)
		}
	}
	// Idempotent on purpose: `ip rule add` happily installs a duplicate, and a
	// second identical rule is invisible in every symptom but impossible to
	// remove with one `del`.
	if ok, rerr := ruleInstalled(ctx, r, plan); rerr != nil || !ok {
		if _, err := r.Run(ctx, "ip", plan.ruleArgs("add")...); err != nil {
			return false, fmt.Errorf("could not install the routing policy rule for %s: %w", plan.SourceIP, err)
		}
	}
	// ROUTE IN BEFORE RESOLVER (§10). The container has to be on the tunnel
	// before its resolver is pointed down it, or there is a window where
	// queries are aimed at an address the container's own route cannot reach.
	return applyTunnelDNS(ctx, r, plan, progress), nil
}

// applyTunnelDNS proves §4.3, §4.4 and §4.5 in that order and moves the
// network's aardvark upstream, or undoes its own half and reports false.
//
// Every failure path calls revertTunnelDNS and KEEPS THE ROUTE. That asymmetry
// is the design's, and it is deliberate: the route was independently confirmed
// and is the feature the user asked for, while tunnelled DNS is the gap being
// closed. Killing a working tunnel because the gap could not be closed would
// regress shipped behaviour to fix a leak.
func applyTunnelDNS(ctx context.Context, r Runner, plan ExternalRoutePlan, progress Progress) bool {
	if len(plan.DNSServers) == 0 {
		return false
	}
	abandon := func(format string, args ...any) bool {
		progress.emit("warning", "DNS was NOT tunnelled and has been left exactly as it was: "+format, args...)
		if err := revertTunnelDNS(ctx, r, plan); err != nil {
			// Loud, because this is the one DNS failure that can outlive the
			// run: a half-applied upstream is what black-holes 30 containers.
			// The dead-man is still armed at this point and its script carries
			// the same drop, so the recovery exists — it just is not silent.
			progress.emit("error", "backing the DNS change out did not fully complete (%v). The dead-man's switch still carries the same `--dns-drop`, and `%s network update %s --dns-drop %s` undoes it by hand.",
				err, plan.DNSPodmanPath, plan.DNSNetwork, strings.Join(plan.DNSServers, " --dns-drop "))
		}
		return false
	}

	// §4.3 — the MAIN-table /32 first, and PROVEN, not assumed. Without it
	// aardvark forwards from the host netns into a table with no route to the
	// resolver and every container on the network loses external DNS.
	for _, dns := range plan.DNSServers {
		if ok, err := dnsRouteInstalled(ctx, r, dns); err != nil || !ok {
			if _, err := r.Run(ctx, "ip", plan.dnsRouteArgs("add", dns)...); err != nil {
				return abandon("the main-table route %s/32 via %s dev %s could not be installed (%v), and pointing the resolver at an address this host cannot reach would black-hole DNS for every container on network %s", dns, plan.TunnelVia, plan.TunnelDev, err, plan.DNSNetwork)
			}
		}
		// `ip route get` is what proves the /32 actually won, rather than that
		// the add command exited 0. A profile whose resolver is a PUBLIC one
		// reachable over the main default is the case this catches: without
		// the /32 taking effect its queries still resolve — so §4.5's
		// end-to-end check would pass — while leaving the machine in the
		// clear. That is the false reassurance externalguarantees.go exists to
		// prevent, so the route is proven separately from the path.
		dev, err := routeGetDevice(ctx, r, dns)
		if err != nil {
			return abandon("it could not be proven which device queries to %s would leave by (%v)", dns, err)
		}
		if dev != plan.TunnelDev {
			return abandon("queries to %s would leave by %s, not the tunnel %s — sending them to a resolver in the clear is not tunnelled DNS, and reporting it as such would be worse than reporting the leak", dns, dev, plan.TunnelDev)
		}
	}

	// §4.4 — move the upstream, and read back the file rather than trusting
	// the exit code.
	if _, err := r.Run(ctx, plan.DNSPodmanPath, plan.dnsUpdateArgs("--dns-add")...); err != nil {
		return abandon("`podman network update %s --dns-add` failed (%v)", plan.DNSNetwork, err)
	}
	got := aardvarkUpstreams(ctx, r, plan.DNSNetwork)
	for _, want := range plan.DNSServers {
		if !containsAddress(got, want) {
			return abandon("`podman network update` exited 0 but %s's aardvark upstream is %q, which does not carry %s", plan.DNSNetwork, strings.Join(got, ","), want)
		}
	}

	// §4.5 — and finally the only check that proves the PATH rather than the
	// configuration. CryptokeyRoutingHint's measured lesson is why this is not
	// redundant with the route check above: a peer whose AllowedIPs does not
	// cover our address gives a route that looks perfect and traffic that
	// silently dies, and DNS would fail exactly that way.
	if err := resolvesThroughTunnel(ctx, r, plan); err != nil {
		return abandon("a name could not be resolved from inside %s after the change (%v).%s", plan.Container, err, CryptokeyRoutingHint)
	}
	return true
}

// revertTunnelDNS undoes the DNS half, RESOLVER OUT BEFORE ROUTE (§10).
//
// The drop goes first so there is never a moment where aardvark is still
// pointed at an address whose route has already been withdrawn — that ordering
// is the difference between a clean undo and the black hole this feature's
// main risk is. Both halves are idempotent (a `--dns-drop` of an address that
// is not configured exits 0; a missing route is checked before deleting), so
// this is safe to call on a partial apply, on a full one, and twice.
func revertTunnelDNS(ctx context.Context, r Runner, plan ExternalRoutePlan) error {
	if len(plan.DNSServers) == 0 {
		return nil
	}
	var firstErr error
	if plan.DNSPodmanPath != "" && plan.DNSNetwork != "" {
		if _, err := r.Run(ctx, plan.DNSPodmanPath, plan.dnsUpdateArgs("--dns-drop")...); err != nil {
			firstErr = fmt.Errorf("could not drop %s's aardvark upstream: %w", plan.DNSNetwork, err)
		}
		// Anything that was there BEFORE this apply goes back. Today this is
		// empty on the production host, and recording it is precisely what
		// keeps "it was empty" from being an assumption compiled into the undo.
		for _, prior := range plan.DNSPrior {
			if containsAddress(plan.DNSServers, prior) {
				continue
			}
			if _, err := r.Run(ctx, plan.DNSPodmanPath, "network", "update", plan.DNSNetwork, "--dns-add", prior); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("could not restore %s's prior upstream %s: %w", plan.DNSNetwork, prior, err)
			}
		}
	}
	for _, dns := range plan.DNSServers {
		if ok, err := dnsRouteInstalled(ctx, r, dns); err == nil && !ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.dnsRouteArgs("del", dns)...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("could not remove the main-table route for %s: %w", dns, err)
		}
	}
	return firstErr
}

// dnsRouteInstalled asks whether the main-table /32 is there. `ip route show
// <prefix>` prints the matching route or nothing at all, so emptiness is the
// answer rather than an error.
func dnsRouteInstalled(ctx context.Context, r Runner, dns string) (bool, error) {
	out, err := r.Run(ctx, "ip", "route", "show", dns+"/32")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// routeGetDevice is the kernel's own answer to "which device would this
// packet leave by", which is a different question from "is there a route" and
// the only one worth asking here.
func routeGetDevice(ctx context.Context, r Runner, dst string) (string, error) {
	out, err := r.Run(ctx, "ip", "route", "get", dst)
	if err != nil {
		return "", err
	}
	f := strings.Fields(firstLine(out))
	for i := 0; i < len(f)-1; i++ {
		if f[i] == "dev" {
			return f[i+1], nil
		}
	}
	return "", fmt.Errorf("`ip route get %s` named no device: %q", dst, strings.TrimSpace(firstLine(out)))
}

// resolvesThroughTunnel proves a name actually resolves for the routed
// container, by running a probe INSIDE that container's network namespace.
//
// `--network container:<id>` is the same mechanism measureNetnsEgress uses and
// it works here for one measured reason: podman gives the probe the TARGET's
// resolv.conf, so it asks the same aardvark on the same address the routed
// container does. Verified on the host 2026-09-08 — the probe's
// /etc/resolv.conf came back as the target's `nameserver 10.89.1.1`.
//
// The routed container itself is never required to contain a resolver tool,
// which matters: on this deployment it is the workspace, and a check that
// depended on what happens to be installed there would silently stop working
// the day that image changes.
func resolvesThroughTunnel(ctx context.Context, r Runner, plan ExternalRoutePlan) error {
	args := []string{"run", "--rm", "--network", "container:" + plan.ContainerID,
		"--entrypoint", "sh", ContainerProbeImage, "-c", dnsProbeScript()}
	out, err := r.Run(ctx, plan.DNSPodmanPath, args...)
	if err != nil {
		return fmt.Errorf("the probe in %s's namespace failed: %v: %s", plan.Container, err, strings.TrimSpace(lastLine(out)))
	}
	if !strings.Contains(out, dnsProbeMarker) {
		return fmt.Errorf("the probe ran but resolved nothing: %q", strings.TrimSpace(lastLine(out)))
	}
	return nil
}

// dnsProbeMarker is looked for instead of an exit code for the same reason
// containerEgressScript emits its own: a probe that printed a resolver's
// error page, or a busybox whose exit status disagrees with its output, would
// otherwise be read as success.
const dnsProbeMarker = "AW_DNS_OK"

// dnsProbeScript tries two names rather than one so a single domain being
// briefly unresolvable is not read as "the tunnel's resolver is broken".
func dnsProbeScript() string {
	return "for n in example.com cloudflare.com; do\n" +
		"  if nslookup \"$n\" >/dev/null 2>&1; then echo \"" + dnsProbeMarker + " $n\"; exit 0; fi\n" +
		"done\n" +
		"echo AW_DNS_FAIL; exit 1\n"
}

func containsAddress(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// revertExternalRoute removes the rule FIRST. Order matters for the same
// reason it does in usexit.go's revert: if removing the exclusions then fails,
// the container is already off the tunnel rather than on it with half its pins
// gone.
func revertExternalRoute(ctx context.Context, r Runner, plan ExternalRoutePlan, progress Progress) error {
	var firstErr error
	// RESOLVER OUT BEFORE ROUTE (§10), which is why this is above the rule
	// removal and not below it. Taking the tunnel away from under an aardvark
	// still forwarding into it is the black hole; taking the resolver back
	// first leaves the network resolving exactly as it did before the apply,
	// whatever happens to the rest of this function.
	if err := revertTunnelDNS(ctx, r, plan); err != nil {
		firstErr = err
	}
	// Loop rather than a single del: a flush-and-reassert race can leave two
	// identical rules, and one `del` would remove only one of them.
	for i := 0; i < 8; i++ {
		ok, err := ruleInstalled(ctx, r, plan)
		if err != nil || !ok {
			break
		}
		if _, err := r.Run(ctx, "ip", plan.ruleArgs("del")...); err != nil {
			firstErr = fmt.Errorf("could not remove the routing policy rule for %s: %w", plan.SourceIP, err)
			break
		}
	}
	for _, prefix := range plan.Exclusions {
		if ok, err := routeInstalled(ctx, r, plan, prefix); err == nil && !ok {
			continue
		}
		if _, err := r.Run(ctx, "ip", plan.excludeArgs("del", prefix)...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("could not remove the exclusion %s: %w", prefix, err)
		}
	}
	if firstErr == nil {
		progress.emit("info", "rule and exclusions removed; %s is back on this host's own egress", plan.Container)
	}
	return firstErr
}

func revertExternalAfterFailure(ctx context.Context, r Runner, plan ExternalRoutePlan, progress Progress) (reverted, stillArmed bool) {
	if err := revertExternalRoute(ctx, r, plan, progress); err != nil {
		progress.emit("error", "cleanup after a failed apply did not complete (%v) — leaving the dead-man's switch armed on purpose", err)
		return false, true
	}
	if _, err := Disarm(); err != nil {
		return true, true
	}
	return true, false
}

// externalRevertScript is the shell the dead-man's switch runs. Same contract
// as the tailscale one it sits beside: POSIX sh, every path already absolute,
// every privilege prefix already applied, and no reference to this binary —
// a self-referential revert dies with any update or partial write of the very
// tool that armed it.
func externalRevertScript(r Runner, plan ExternalRoutePlan) string {
	prefix := ""
	if p, ok := r.(PrivilegedRunner); ok {
		prefix = strings.TrimSuffix(p.CommandPrefix("ip"), "ip")
	}
	var b strings.Builder
	// THE DNS LINES GO FIRST, and this ordering is the whole reason the DNS
	// change was allowed to be made at all.
	//
	// An un-revertable DNS change is precisely what got the aardvark-config
	// approach rejected on the predecessor card; what podman 5 changed is that
	// the undo is now a CLI verb a POSIX-sh script can call by absolute path,
	// exactly the shape as deadman.go's own `tailscale set --exit-node=` line.
	// So the fire path leaves 30 containers resolving the way they did before
	// this run, and it does that before it touches the route — resolver out
	// before route, the same order revertTunnelDNS uses, for the same reason.
	//
	// `--dns-drop` of an address that is not configured exits 0 (measured
	// 2026-09-08), so this line is safe on a run that never got as far as
	// adding it. The absolute path is plan.DNSPodmanPath, resolved at plan
	// time — a bare `podman` here would depend on the PATH of a machine whose
	// network has just gone.
	if len(plan.DNSServers) > 0 && plan.DNSPodmanPath != "" && plan.DNSNetwork != "" {
		fmt.Fprintf(&b, "%s%s %s || true\n", prefix, plan.DNSPodmanPath, strings.Join(plan.dnsUpdateArgs("--dns-drop"), " "))
		for _, dns := range plan.DNSServers {
			fmt.Fprintf(&b, "%sip %s || true\n", prefix, strings.Join(plan.dnsRouteArgs("del", dns), " "))
		}
	}
	fmt.Fprintf(&b, "%sip %s || true\n", prefix, strings.Join(plan.ruleArgs("del"), " "))
	for _, ex := range plan.Exclusions {
		fmt.Fprintf(&b, "%sip %s || true\n", prefix, strings.Join(plan.excludeArgs("del", ex), " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func ruleInstalled(ctx context.Context, r Runner, plan ExternalRoutePlan) (bool, error) {
	out, err := r.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return false, fmt.Errorf("could not read this host's routing policy rules: %w", err)
	}
	want := plan.SourceIP
	table := strconv.Itoa(plan.Table)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// `ip rule show` prints "5399:\tfrom 172.18.0.4 lookup 200" — the /32
		// is dropped from a single-host source, so match the bare address.
		if strings.TrimSuffix(f[0], ":") == strconv.Itoa(plan.Priority) &&
			f[1] == "from" && strings.TrimSuffix(f[2], "/32") == want &&
			f[len(f)-1] == table {
			return true, nil
		}
	}
	return false, nil
}

func routeInstalled(ctx context.Context, r Runner, plan ExternalRoutePlan, prefix string) (bool, error) {
	out, err := r.Run(ctx, "ip", "route", "show", "table", strconv.Itoa(plan.Table))
	if err != nil {
		return false, err
	}
	bare := strings.TrimSuffix(prefix, "/32")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == prefix || f[0] == bare) {
			return true, nil
		}
	}
	return false, nil
}

// CryptokeyRoutingHint is appended to the two confirmation failures that share
// one measured cause, so an operator is told it instead of rediscovering it.
//
// MEASURED 2026-09-05 against the live hub, both directions:
//
//   - peer AllowedIPs 10.8.0.12/32 (matching our tunnel address): the routed
//     container's public IP changed 65.109.66.88 -> 24.90.8.255 with policy
//     routing ALONE. No SNAT rule of ours was needed or added — the container
//     network's own masquerade already rewrites the source to the tunnel
//     address on the way out, which is what makes a single-/32 peer work.
//   - peer AllowedIPs 10.8.0.99/32 (NOT matching): identical routing,
//     `ip route get` still picks the tunnel, and the container's egress goes
//     dead — the tunnel carrying 92/180 bytes, handshake only.
//
// The second is indistinguishable from a routing fault by looking at routes,
// which is exactly why it costs hours: everything on this side is correct and
// the far end is silently discarding the packets. WireGuard's cryptokey
// routing drops any inbound packet whose SOURCE is outside the AllowedIPs of
// the peer it decrypted from, and a commercial provider (NordLynx included)
// hands out a single /32 just as this deployment's hub does.
const CryptokeyRoutingHint = " The routing on this side is correct, so the likeliest cause is the FAR END: WireGuard drops any packet whose source address is outside the AllowedIPs the peer has registered for this client. Check that the provider's peer entry for this profile covers the address in the profile's `address` field."

// --- confirmation -----------------------------------------------------------

type externalConfirmSpec struct {
	hostBefore      string
	containerBefore string
	expected        string
}

type externalConfirmation struct {
	hostAfter      string
	hostHeld       bool
	hostMoved      bool
	containerAfter string
	ok             bool
	reason         string
}

// confirmExternal asserts BOTH halves, and keeps trying until the window runs
// out because a fresh tunnel takes a few seconds to carry its first flow.
func confirmExternal(ctx context.Context, r Runner, plan ExternalRoutePlan, spec externalConfirmSpec, window time.Duration, progress Progress) externalConfirmation {
	deadline := time.Now().Add(window)
	var last externalConfirmation
	for attempt := 1; ; attempt++ {
		last = externalConfirmOnce(ctx, r, plan, spec)
		if last.ok || last.hostMoved || time.Now().After(deadline) {
			return last
		}
		progress.emit("info", "  attempt %d: %s — retrying", attempt, last.reason)
		select {
		case <-ctx.Done():
			return last
		case <-time.After(3 * time.Second):
		}
	}
}

func externalConfirmOnce(ctx context.Context, r Runner, plan ExternalRoutePlan, spec externalConfirmSpec) externalConfirmation {
	var c externalConfirmation

	// The host's address is checked FIRST and a move short-circuits the rest:
	// a container egress that looks right is meaningless if the machine came
	// with it.
	// hostPublicIP rather than PublicIP directly, for the reason its own
	// comment gives: it is a live HTTPS round trip, and the confirmation logic
	// has to be testable without one.
	host, err := hostPublicIP(ctx)
	if err != nil {
		c.reason = fmt.Sprintf("this host's own public IP could not be re-measured (%v), so it cannot be proven the machine stayed put", err)
		return c
	}
	c.hostAfter = host.IP
	c.hostHeld = host.IP == spec.hostBefore
	c.hostMoved = !c.hostHeld
	if c.hostMoved {
		c.reason = fmt.Sprintf("THIS MACHINE's egress moved from %s to %s", spec.hostBefore, host.IP)
		return c
	}

	got := measureNetnsEgress(ctx, r, plan.Runtime, plan.ContainerID)
	c.containerAfter = got.IP
	if got.IP == "" {
		c.reason = fmt.Sprintf("the container's egress could not be measured through the new route (%s).%s", got.Error, CryptokeyRoutingHint)
		return c
	}
	if spec.expected != "" {
		if got.IP != spec.expected {
			c.reason = fmt.Sprintf("the container is leaving via %s, not the expected %s", got.IP, spec.expected)
			return c
		}
		c.ok = true
		return c
	}
	if spec.containerBefore != "" && got.IP == spec.containerBefore {
		c.reason = fmt.Sprintf("the container is still leaving via %s — the rule is installed but nothing moved.%s", got.IP, CryptokeyRoutingHint)
		return c
	}
	c.ok = true
	return c
}

// measureNetnsEgress asks what the routed container's own egress is, by
// running the probe INSIDE that container's network namespace.
//
// This is the part that makes the confirmation exact rather than
// approximate. MeasureContainerEgress (containers.go) probes a NETWORK, so its
// probe gets a fresh address that this /32 rule does not match — it would
// faithfully report the host's egress no matter how well the rule worked.
// `--network container:<id>` shares the target's namespace and therefore its
// source address, so the probe is matched by the very rule being confirmed.
// Verified on the production bare metal 2026-09-02 against aw-remote-host.
//
// The container itself is never required to contain curl, wget or anything
// else, which matters here: the container this exists for has no `ip` and an
// empty dpkg database.
func measureNetnsEgress(ctx context.Context, r Runner, runtime, containerID string) ContainerEgressResult {
	res := ContainerEgressResult{Runtime: runtime, Network: "container:" + containerID}
	if runtime == "" || containerID == "" {
		res.Error = NoContainerRuntimeRefusal
		return res
	}
	args := []string{"run", "--rm", "--network", "container:" + containerID,
		"--entrypoint", "sh", ContainerProbeImage, "-c", containerEgressScript()}
	out, err := r.Run(ctx, runtime, args...)
	if err != nil {
		res.Error = fmt.Sprintf("probe container in the target's network namespace failed: %v: %s", err, strings.TrimSpace(out))
		return res
	}
	// Parsed by containers.go's own parser, not by a second one written here.
	// containerEgressScript emits a MARKED line ("AW_EGRESS <url> <ip>") so that
	// a page body which happens to contain an address cannot be mistaken for
	// the answer; a hand-rolled "first line that parses as an IP" reader
	// silently disagrees with that format, which is exactly what it did on the
	// first real run against this bare metal.
	via, ip := parseContainerEgress(out)
	if ip == "" {
		res.Error = "the probe ran but printed no address: " + strings.TrimSpace(out)
		return res
	}
	res.IP, res.Via = ip, via
	return res
}

// --- state ------------------------------------------------------------------

func saveExternalRouteState(plan ExternalRoutePlan) error {
	return mutateExternalRouteState(func(v *state.VPNState) {
		v.ExternalRoute = &state.ExternalRouteState{
			Container:    plan.Container,
			ContainerID:  plan.ContainerID,
			SourceIP:     plan.SourceIP,
			Table:        plan.Table,
			Priority:     plan.Priority,
			Runtime:      plan.Runtime,
			TunnelDev:    plan.TunnelDev,
			MainGateway:  plan.MainGateway,
			MainDev:      plan.MainDev,
			Exclusions:   plan.Exclusions,
			RoutedAt:     time.Now().UTC().Format(time.RFC3339),
			ExpectEgress: plan.ExpectEgress,

			DNSServers:    plan.DNSServers,
			DNSNetwork:    plan.DNSNetwork,
			DNSPodmanPath: plan.DNSPodmanPath,
			DNSPrior:      plan.DNSPrior,
		}
	})
}

func clearExternalRouteState() error {
	return mutateExternalRouteState(func(v *state.VPNState) { v.ExternalRoute = nil })
}

// mutateExternalRouteState goes through state.Update so the read and the write
// are one operation against the file. A load-modify-save spelled out here
// would be the same race the daemon already lost once — see state.Update's
// comment for the measurement.
func mutateExternalRouteState(apply func(*state.VPNState)) error {
	path, err := state.DefaultPath()
	if err != nil {
		return err
	}
	return state.Update(path, func(st *state.State) {
		if st.VPN == nil {
			st.VPN = &state.VPNState{}
		}
		apply(st.VPN)
	})
}

// loadExternalRouteState returns the recorded route, or nil when there is
// none. A missing or unreadable state file is "nothing recorded" rather than
// an error: Reassert runs on a timer and must not turn a fresh host into a log
// full of failures.
func loadExternalRouteState() (*ExternalRoutePlan, error) {
	path, err := state.DefaultPath()
	if err != nil {
		return nil, nil
	}
	st, err := state.Load(path)
	if err != nil || st.VPN == nil || st.VPN.ExternalRoute == nil {
		return nil, nil
	}
	e := st.VPN.ExternalRoute
	return &ExternalRoutePlan{
		Container:    e.Container,
		ContainerID:  e.ContainerID,
		SourceIP:     e.SourceIP,
		Table:        e.Table,
		Priority:     e.Priority,
		Runtime:      e.Runtime,
		TunnelDev:    e.TunnelDev,
		MainGateway:  e.MainGateway,
		MainDev:      e.MainDev,
		Exclusions:   e.Exclusions,
		ExpectEgress: e.ExpectEgress,

		DNSServers:    e.DNSServers,
		DNSNetwork:    e.DNSNetwork,
		DNSPodmanPath: e.DNSPodmanPath,
		DNSPrior:      e.DNSPrior,
	}, nil
}
