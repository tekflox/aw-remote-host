package vpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Phase 2: selecting an exit gate, which moves this machine's default route
// onto the mesh. Everything in this file exists because of one failure mode.
//
// The /link tunnel is the only remote-management path a BYOD host has. Move
// the default route onto a tunnel whose gate is unreachable and the machine
// loses the internet, the tunnel drops, and the command that would undo it
// travels over that same tunnel. This is not a thought experiment: in the
// week before this was written, on this project's own bare-metal, a leftover
// `ip rule from 172.18.0.5 lookup 51821` sent a container's egress into a
// gateway whose tunnel no longer existed. That container had no internet for
// TWO DAYS, silently; it survived restarts because the rule lived on the
// host; nobody was alerted, and it only surfaced when a deploy failed.
//
// Two design consequences follow, and they are the whole point of this file:
//
//  1. Exclusions are expressed as `ip rule ... lookup main`, never as a rule
//     pointing INTO a table the tunnel owns. A leftover exclusion is inert —
//     "send this prefix to the main table" is what an unconfigured machine
//     already does. A leftover rule of the 51821 shape is a black hole. The
//     mechanism is chosen so that failing to clean up cannot strand anything.
//  2. Nothing here trusts an interface being up. Egress is CONFIRMED by
//     fetching the real public IP through the new route, and a switch that
//     cannot be confirmed is reverted rather than reported.

// The `ip rule` priorities this module installs, and the whole of the routing
// model in one place. Every one of them lives inside tailscale's own reserved
// 5210-5270 block, which is what makes them safe to delete blindly on the way
// out: nothing else in the system allocates there.
//
// Measured on aw-baremetal 2026-08-25 and re-measured on the Surface
// 2026-08-26 — tailscale's own rules, with an exit node in force, are:
//
//	5210: from all fwmark 0x80000/0xff0000 lookup main
//	5230: from all fwmark 0x80000/0xff0000 lookup default
//	5250: from all fwmark 0x80000/0xff0000 unreachable
//	5270: from all lookup 52
//
// 5270 is the catch-all that puts EVERY packet into tailscale's table, and it
// is the reason the old shape of this feature moved the whole machine. The
// three fwmark rules above only ever match tailscaled's OWN packets, so
// sitting below them shadows nothing.
//
// What this module installs, in the order the kernel evaluates it:
//
//	5259: to 100.64.0.0/10 lookup 52     the mesh stays reachable — see below
//	5260: to <prefix> lookup main        the exclusions (control plane, LANs)
//	5261: from <container CIDR> lookup 52  THE FEATURE: containers only
//	5265: from all lookup main           THE HOST'S ROUTE, HELD STILL
//
// 5265 is what makes the invariant hold. It is reached by everything that is
// not a container, before tailscale's 5270 ever gets a chance, so the host's
// default route stays in the main table for the entire life of the selection.
// The host's public IP cannot move because nothing ever consults table 52 on
// its behalf.
//
// 5259 is not optional and was nearly missed. On the Surface, `ip route show
// 100.64.0.0/10` in the MAIN table is EMPTY — the peer routes
// (100.64.0.1/100.64.0.3/100.100.100.100 dev tailscale0) live only in table
// 52. Without 5259 the host bypass at 5265 would send mesh traffic to a table
// that has no route for it, and the machine would lose the mesh — including
// the peers it is being routed through — while looking perfectly healthy.
const (
	// meshPreservePriority keeps the mesh itself reachable for host and
	// containers alike, above the host bypass.
	meshPreservePriority = 5259
	// exclusionPriority is where the `to <prefix> lookup main` exclusions go.
	exclusionPriority = 5260
	// containerRoutePriority is where each container network's `from <CIDR>
	// lookup 52` rule goes — keyed on the NETWORK, never on a container's own
	// address. See containers.go's header for the outage that rule shape cost.
	containerRoutePriority = 5261
	// hostBypassPriority is the single `from all lookup main` that holds the
	// host's own egress still.
	hostBypassPriority = 5265

	// meshPrefix is tailscale's CGNAT range, fixed by the protocol rather than
	// by configuration.
	meshPrefix = "100.64.0.0/10"

	// exitConfirmEndpointTimeout bounds a single public-IP lookup. Short on
	// purpose — when an exit gate is broken these hang, and every second
	// spent hanging is a second the machine is off the internet.
	exitConfirmEndpointTimeout = 8 * time.Second
)

// routePriorities is every priority this module owns, cleared as one set.
// Listed once so a rule shape added later cannot be installed and then left
// behind by a cleanup that never heard about it.
var routePriorities = []int{meshPreservePriority, exclusionPriority, containerRoutePriority, hostBypassPriority}

// egressEndpoints are the "what is my public IP" services tried in order, from
// different operators, because the confirmation step is what stands between a
// broken exit node and a stranded host: one provider having a bad day must not
// read as "the route is broken", and must not read as "the route is fine"
// either.
//
// The FIRST is an IP literal, and that is the point of the ordering. A gate
// that forwards packets but breaks name resolution would otherwise be reported
// as no internet at all; worse, on the container side a network with
// dns_enabled=false is completely normal. Measured answering over TLS to the
// bare address from both a host and a podman container on the Surface,
// 2026-08-26.
var egressEndpoints = []egressEndpoint{
	{URL: "https://1.1.1.1/cdn-cgi/trace", Keyed: true, ByIP: true},
	{URL: "https://api.ipify.org"},
	{URL: "https://ifconfig.me/ip"},
	{URL: "https://icanhazip.com"},
}

// egressEndpoint is one such service and how to read it.
type egressEndpoint struct {
	URL string
	// Keyed marks a `key=value` body (Cloudflare's cdn-cgi/trace) rather than
	// a bare address.
	Keyed bool
	// ByIP records that this URL needs no DNS. Carried so the honesty of a
	// measurement is a property of the result and not folklore about the list.
	ByIP bool
}

// Exclusion is one prefix deliberately kept OUT of the tunnel.
//
// Reason is not decoration. It is printed by `status` and by --plan, because
// the operator question this feature raises is always "what is still reachable
// if the mesh dies", and a bare list of CIDRs does not answer it.
type Exclusion struct {
	Prefix string
	Reason string
}

// ExclusionPlan is the full set of exclusions for one use-exit, plus what had
// to be resolved to build it.
type ExclusionPlan struct {
	Exclusions []Exclusion
	// ControlPlaneHost is the hostname whose addresses were pinned, and
	// ControlPlaneIPs what it resolved to at planning time. Both are reported:
	// a control plane behind a rotating CDN address is a real way for this
	// exclusion to go stale, and the honest thing is to show the pin rather
	// than imply the hostname itself is excluded.
	ControlPlaneHost string
	ControlPlaneIPs  []string
}

// LocalPrefix is one directly attached IPv4 network on this machine.
type LocalPrefix struct {
	Iface  string
	Prefix string
}

// LocalPrefixes enumerates every directly attached IPv4 network — the LAN,
// every podman/docker bridge, everything.
//
// Sweeping the interface table rather than naming `podman*`/`docker0`/`cni-*`
// is deliberate. The required exclusions are "the podman subnets and the LAN
// prefix", and both are, by definition, networks this machine is already
// attached to. A name-based list has to be kept in step with every container
// runtime that ever creates a bridge here; an attachment-based one cannot
// drift. It also degrades in the safe direction: the worst case is excluding
// a private network that did not need excluding, which leaves it reachable
// exactly as it was before the tunnel existed.
//
// tailscale0's own /32 is skipped — routing the mesh address outside the mesh
// is nonsense — and so is anything not IPv4, since only the IPv4 default
// route is moved here.
func LocalPrefixes() []LocalPrefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []LocalPrefix
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "tailscale") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones == 32 {
				// A /32 is a host address, not a network — the bare-metal's
				// own public address is configured that way (65.109.66.88/32,
				// measured 2026-08-25) and excluding it would say nothing
				// useful about what stays reachable.
				continue
			}
			prefix := (&net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			out = append(out, LocalPrefix{Iface: iface.Name, Prefix: prefix})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// Resolver looks a hostname up. Split out so PlanExclusions is testable
// without DNS, and so a failure to resolve the control plane is a value this
// package can reason about rather than a network call buried mid-function.
type Resolver func(host string) ([]string, error)

// DefaultResolver resolves through the system resolver.
func DefaultResolver(host string) ([]string, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			out = append(out, parsed.To4().String())
		}
	}
	return out, nil
}

// PlanExclusions builds the set of prefixes that stay outside the tunnel.
//
// The control plane is FIRST and is not optional. If it cannot be resolved
// this returns an error and the caller must not proceed: pinning the
// management path is the one exclusion whose absence turns a bad exit node
// into a machine that needs a physical visit, so "I could not work out where
// the control plane lives, but I moved your default route anyway" is not an
// outcome this is allowed to produce.
//
// extra is the operator's own --exclude list, for the things only they know
// about — a NAS on a routed subnet, a jump host, a second management plane.
func PlanExclusions(controlPlane string, locals []LocalPrefix, extra []string, resolve Resolver) (ExclusionPlan, error) {
	host, ips, err := resolveControlPlane(controlPlane, resolve)
	if err != nil {
		return ExclusionPlan{}, err
	}
	plan := ExclusionPlan{ControlPlaneHost: host, ControlPlaneIPs: ips}

	add := func(prefix, reason string) {
		for _, existing := range plan.Exclusions {
			if existing.Prefix == prefix {
				return
			}
		}
		plan.Exclusions = append(plan.Exclusions, Exclusion{Prefix: prefix, Reason: reason})
	}

	// RE-DERIVED for container-scoped routing, 2026-08-26, rather than kept
	// because it was there. Under the old model these protected the HOST,
	// whose route was moving. The host's route no longer moves — the bypass at
	// priority 5265 holds it — so every one of them had to earn its place
	// again as a rule about CONTAINER traffic, and both kinds did:
	//
	//   - the control plane, because a container's traffic to it would
	//     otherwise leave through the gate. The anti-lockout argument is gone
	//     (the /link tunnel is the host's, and the host is untouched), but the
	//     card's requirement that container->control-plane traffic keep
	//     working is not, and this is what keeps it on the same path it used
	//     yesterday instead of one that depends on a gate staying up;
	//   - the attached networks, because they are where container-to-LAN and
	//     container-to-container traffic goes. Without them a container
	//     talking to the NAS, to the host, or to a container on another
	//     bridge would have that traffic sent into the tunnel and dropped.
	//     internal/lanfastpath depends on the LAN one.
	//
	// They are `to <prefix> lookup main` rules, which is what lets them sit
	// above the container rules and win: destination decides, so only traffic
	// that is genuinely LEAVING is left for the gate.
	for _, ip := range plan.ControlPlaneIPs {
		add(ip+"/32", "the control plane / /link tunnel endpoint ("+host+") — containers reach it on this host's own path rather than through the gate")
	}
	for _, l := range locals {
		add(l.Prefix, "directly attached network on "+l.Iface+" (LAN prefix / container bridge) — container-to-LAN and container-to-container traffic must not enter the tunnel")
	}
	for _, raw := range extra {
		prefix := strings.TrimSpace(raw)
		if prefix == "" {
			continue
		}
		normalised, err := normalisePrefix(prefix)
		if err != nil {
			return ExclusionPlan{}, err
		}
		add(normalised, "requested with --exclude")
	}
	return plan, nil
}

// resolveControlPlane works out where the management path lives, and refuses
// when it cannot.
//
// Split out of PlanExclusions because it is the one part of that function
// every platform needs, including the ones that pin nothing: on darwin the
// control plane's reachability is CONFIRMED rather than pinned, and
// confirming it still requires knowing where it is. The refusal wording talks
// about the default route rather than about exclusions for the same reason —
// it is true on a host that installs none.
func resolveControlPlane(controlPlane string, resolve Resolver) (host string, ips []string, err error) {
	host = hostOf(controlPlane)
	if host == "" {
		return "", nil, fmt.Errorf("cannot work out the control-plane host from %q, and the management path is not an optional exclusion", controlPlane)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return host, []string{ip.To4().String()}, nil
	}
	ips, err = resolve(host)
	if err != nil {
		return "", nil, fmt.Errorf("resolve control plane %q: %w — refusing to move the default route without knowing where the management path is", host, err)
	}
	if len(ips) == 0 {
		return "", nil, fmt.Errorf("control plane %q resolved to no IPv4 address — refusing to move the default route without knowing where the management path is", host)
	}
	return host, ips, nil
}

func normalisePrefix(raw string) (string, error) {
	if !strings.Contains(raw, "/") {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("--exclude %q is neither an IPv4 address nor an IPv4 CIDR", raw)
		}
		return ip.To4().String() + "/32", nil
	}
	_, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", fmt.Errorf("--exclude %q: %w", raw, err)
	}
	if ipnet.IP.To4() == nil {
		return "", fmt.Errorf("--exclude %q is not IPv4; only the IPv4 default route is moved by this command", raw)
	}
	return ipnet.String(), nil
}

// hostOf strips a scheme and a port off a control-plane URL. Tolerant on
// purpose: --control-plane is given as https://api.aw.tekflox.com, but the
// value reaching here may equally be a bare hostname from state.
func hostOf(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return s
}

// ContainerRoute is one container network's routing rule: the prefix that
// moves, and which networks it belongs to.
//
// Networks is for the narration only. It is what turns "10.89.0.0/24 now
// leaves through the gate" into a sentence naming the containers an operator
// recognises, and it is deliberately a list — two networks can share a subnet
// when one was recreated under a new name, and one rule serves both.
type ContainerRoute struct {
	Prefix   string
	Networks []string
}

// RoutePlan is the complete set of `ip rule` entries one selection installs.
// Both halves together, because they are only correct together: the container
// rules without the host bypass would route the machine, and the bypass
// without the container rules would route nothing at all.
type RoutePlan struct {
	Containers []ContainerRoute
	Exclusions []Exclusion
}

// ApplyRoutes installs the plan.
//
// THE ORDER IS THE SAFETY PROPERTY, and it is not the order the kernel
// evaluates in — priorities decide that. It is the order in which a partial
// failure leaves the machine:
//
//  1. everything at this module's priorities is cleared, so a second
//     use-exit cannot stack a second generation of rules on the first;
//  2. the HOST BYPASS goes in FIRST. From this instant the host's default
//     route is pinned to the main table, and it is in place before any
//     container rule and long before `tailscale set` installs its own
//     `from all lookup 52` at 5270. There is no window, not even a
//     millisecond, in which this machine's own egress could take the tunnel;
//  3. the mesh-preserve rule, so the bypass cannot cost the host its peers;
//  4. the exclusions;
//  5. the container rules last — the only step whose failure means "the
//     feature did not happen", which is the harmless direction to fail in.
//
// Any failure rolls the whole set back rather than leaving it half applied. A
// half-applied set reads like the host is pinned when the pin may be the rule
// that failed, and that misreading is what this sequence exists to prevent.
func ApplyRoutes(ctx context.Context, r Runner, plan RoutePlan) error {
	if _, err := clearRouteRules(ctx, r); err != nil {
		return err
	}
	rollback := func(format string, args ...any) error {
		_, _ = clearRouteRules(ctx, r)
		return fmt.Errorf(format, args...)
	}

	if out, err := r.Run(ctx, "ip", "rule", "add", "from", "all", "lookup", "main", "priority", fmt.Sprint(hostBypassPriority)); err != nil {
		return rollback("install the host bypass (`from all lookup main` at priority %d): %w: %s — without it this machine's own route would move, which is the one thing this must never do", hostBypassPriority, err, strings.TrimSpace(out))
	}
	if out, err := r.Run(ctx, "ip", "rule", "add", "to", meshPrefix, "lookup", "52", "priority", fmt.Sprint(meshPreservePriority)); err != nil {
		return rollback("install the mesh-preserve rule (`to %s lookup 52` at priority %d): %w: %s — the host bypass alone would take this machine off the mesh", meshPrefix, meshPreservePriority, err, strings.TrimSpace(out))
	}
	for _, e := range plan.Exclusions {
		if out, err := r.Run(ctx, "ip", "rule", "add", "to", e.Prefix, "lookup", "main", "priority", fmt.Sprint(exclusionPriority)); err != nil {
			return rollback("install route exclusion for %s: %w: %s", e.Prefix, err, strings.TrimSpace(out))
		}
	}
	for _, c := range plan.Containers {
		if out, err := r.Run(ctx, "ip", "rule", "add", "from", c.Prefix, "lookup", "52", "priority", fmt.Sprint(containerRoutePriority)); err != nil {
			return rollback("install the container route for %s: %w: %s", c.Prefix, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// ClearRoutes removes whatever this host's platform installed. On a Mac that
// is nothing, and it answers (0, nil) rather than reaching for `ip`.
func ClearRoutes(ctx context.Context, r Runner) (int, error) {
	return currentPlatform().clearExclusions(ctx, r)
}

// clearRouteRules removes every rule this package installed, by deleting at
// each of its own priorities until the kernel says there are none left.
//
// Deleting by priority rather than by exact spec is what makes cleanup total.
// A rule whose spec drifted (a prefix rewritten by something else, a run that
// died between two adds) would survive a spec-matched delete and become the
// leftover this whole design is built to avoid.
//
// WHAT A LEFTOVER COSTS UNDER THIS MODEL, said plainly, because one of these
// rules is the shape that caused the aw-console outage. `from <CIDR> lookup
// 52` does point INTO a table the tunnel owns — the very thing exit.go's
// header says to avoid — and routing containers through a tunnel cannot be
// expressed any other way. What makes it survivable here is a property of
// table 52 that table 51821 did not have: tailscaled populates 52 with a
// DEFAULT ROUTE only while an exit node is selected, and removes it when the
// selection clears (measured on the Surface, 2026-08-26: with no selection,
// table 52 holds peer routes only and no default). A leftover container rule
// therefore finds no default, and `ip rule` falls through to the next rule
// rather than dropping the packet. The 51821 rule pointed at a wireguard table
// that kept its dead default forever, which is why it was a black hole and
// this is not. The dead-man's switch, the boot guard and `status`'s
// leftover-rule warning are the other three layers.
func clearRouteRules(ctx context.Context, r Runner) (int, error) {
	total := 0
	for _, priority := range routePriorities {
		removed, err := clearRulesAtPriority(ctx, r, priority)
		total += removed
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func clearRulesAtPriority(ctx context.Context, r Runner, priority int) (int, error) {
	removed := 0
	for i := 0; i < 64; i++ {
		out, err := r.Run(ctx, "ip", "rule", "del", "priority", fmt.Sprint(priority))
		if err != nil {
			// The kernel answers "RTNETLINK answers: No such file or
			// directory" once the last one is gone. That is the loop's exit
			// condition, not a failure.
			if isNoSuchRule(out) {
				return removed, nil
			}
			return removed, fmt.Errorf("remove route rules at priority %d: %w: %s", priority, err, strings.TrimSpace(out))
		}
		removed++
	}
	return removed, fmt.Errorf("removed %d route rules and there are still more at priority %d — refusing to loop", removed, priority)
}

func isNoSuchRule(out string) bool {
	lowered := strings.ToLower(out)
	return strings.Contains(lowered, "no such file") || strings.Contains(lowered, "cannot find")
}

// ListRouteRules reads back the rules actually in force. `status` shows this
// rather than what state.json remembers being asked for — the whole hazard is
// a rule outliving the intent that created it.
func ListRouteRules(ctx context.Context, r Runner) ([]string, error) {
	return currentPlatform().listExclusions(ctx, r)
}

func listIPRuleExclusions(ctx context.Context, r Runner) ([]string, error) {
	out, err := r.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return nil, fmt.Errorf("read ip rules: %w: %s", err, strings.TrimSpace(out))
	}
	return parseRouteRules(out), nil
}

// parseRouteRules picks this module's lines out of `ip rule show`, at every
// priority it owns, and returns the rule bodies verbatim:
//
//	5259:	from all to 100.64.0.0/10 lookup 52
//	5260:	from all to 1.2.3.4 lookup main
//	5261:	from 10.89.0.0/24 lookup 52
//	5265:	from all lookup main
//
// Verbatim rather than summarised into "excluded prefixes", which is what this
// used to do. Under container-scoped routing the direction of a rule is the
// whole meaning — `from <CIDR> lookup 52` moves traffic INTO the tunnel and
// `to <prefix> lookup main` keeps it OUT — and a list of bare prefixes cannot
// tell an operator which of the two they are looking at.
func parseRouteRules(out string) []string {
	prefixes := make(map[string]bool, len(routePriorities))
	for _, p := range routePriorities {
		prefixes[fmt.Sprint(p)+":"] = true
	}
	var found []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		head, rest, ok := strings.Cut(line, ":")
		if !ok || !prefixes[head+":"] {
			continue
		}
		found = append(found, strings.Join(strings.Fields(rest), " "))
	}
	return found
}

// RouteDevice reports which interface the kernel would send a packet for dst
// out of. This is the cheap, local half of the confirmation: after a switch
// the default should leave via tailscale0, and every excluded prefix should
// not. It is evidence, never proof — an interface being chosen says nothing
// about whether anything is listening at the other end, which is why the
// public-IP check below exists as well.
// It asks whichever tool this OS answers with — `ip route get` on Linux,
// `route -n get` on macOS.
func RouteDevice(ctx context.Context, r Runner, dst string) (string, error) {
	return currentPlatform().routeDevice(ctx, r, dst)
}

func parseRouteDevice(out string) string {
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// Egress is a measured public-IP observation.
type Egress struct {
	IP string
	// Via is the endpoint that answered, so a surprising address can be
	// attributed to a provider rather than argued about.
	Via string
}

// PublicIP fetches this machine's real public IP address.
//
// Every request is made on a fresh connection with keep-alives disabled: a
// pooled connection established BEFORE the route moved would answer from the
// old path and report a change that never happened. That is the specific way
// a confirmation step lies.
func PublicIP(ctx context.Context) (Egress, error) {
	var errs []string
	for _, endpoint := range egressEndpoints {
		ip, err := fetchIP(ctx, endpoint)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint.URL, err))
			continue
		}
		return Egress{IP: ip, Via: endpoint.URL}, nil
	}
	return Egress{}, fmt.Errorf("could not determine this host's public IP from any endpoint: %s", strings.Join(errs, "; "))
}

func fetchIP(ctx context.Context, endpoint egressEndpoint) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, exitConfirmEndpointTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.URL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// The keyed body is a few hundred bytes and the address is not in the
	// first line, so the cap has to clear it — but it stays a cap, because a
	// misrouted request can land on anything at all.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ip := parseEgressBody(string(body), endpoint.Keyed)
	if ip == "" {
		return "", fmt.Errorf("answered %q, which is not an IP address", strings.TrimSpace(firstLine(string(body))))
	}
	return ip, nil
}

// parseEgressBody reads an address out of either answer shape: a bare address,
// or Cloudflare's `ip=<addr>` line inside a key=value blob. net.ParseIP is the
// only thing that promotes a string to a measurement — a captive portal's
// login page and a proxy's error text both return HTTP 200 with a body, and
// neither is an egress address.
func parseEgressBody(body string, keyed bool) string {
	if keyed {
		for _, line := range strings.Split(body, "\n") {
			value, ok := strings.CutPrefix(strings.TrimSpace(line), "ip=")
			if !ok {
				continue
			}
			if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil && ip.To4() != nil {
				return ip.To4().String()
			}
		}
		return ""
	}
	if ip := net.ParseIP(strings.TrimSpace(body)); ip != nil {
		return ip.String()
	}
	return ""
}

// Reachable reports whether an HTTP GET to url completes at all. Used against
// the control plane after the route moves: the exclusion is meant to keep the
// management path outside the tunnel, and the only way to know it worked is
// to use it.
func Reachable(ctx context.Context, url string) error {
	reqCtx, cancel := context.WithTimeout(ctx, exitConfirmEndpointTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	// Any HTTP answer at all proves the path: a 404 from the control plane
	// still means packets reached it and came back, which is the whole
	// question. Only a transport failure counts as unreachable.
	return nil
}

// ResolveExitPeer finds the peer to use as an exit gate, by node name, mesh
// IP, or DNS name.
//
// It refuses a peer that does not offer an exit route, and the refusal says
// which of the two reasons applies, because they need different people to fix
// them: "not advertising" is the gate host's operator, "advertised but not
// approved" is a headscale admin. A peer that is offline is refused too —
// selecting a dead gate is the exact move that strands a host.
func ResolveExitPeer(s Status, name string) (Peer, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return Peer{}, fmt.Errorf("no exit node given")
	}
	var match *Peer
	for i := range s.Peers {
		p := &s.Peers[i]
		if strings.ToLower(p.Name) == want || strings.EqualFold(strings.TrimSuffix(p.DNSName, "."), want) {
			match = p
			break
		}
		for _, ip := range p.IPs {
			if ip == want {
				match = p
				break
			}
		}
		if match != nil {
			break
		}
	}
	if match == nil {
		return Peer{}, fmt.Errorf("no peer named %q in this mesh — known peers: %s", name, peerNames(s))
	}
	if !match.OffersExit {
		return Peer{}, fmt.Errorf("peer %q does not offer an exit route. Either it was never started with --advertise-exit-node, or it advertises 0.0.0.0/0 and a headscale admin has not approved that route yet — until one of those is fixed, selecting it would move this machine's default route onto a gate that will not forward anything", match.Name)
	}
	if !match.Online {
		return Peer{}, fmt.Errorf("peer %q offers an exit route but is OFFLINE right now. Selecting an unreachable gate is exactly how a host ends up with no internet and no way back", match.Name)
	}
	if firstV4(match.IPs) == "" {
		return Peer{}, fmt.Errorf("peer %q has no IPv4 mesh address to select", match.Name)
	}
	return *match, nil
}

func peerNames(s Status) string {
	if len(s.Peers) == 0 {
		return "(none)"
	}
	var names []string
	for _, p := range s.Peers {
		suffix := ""
		if p.OffersExit {
			suffix = " [offers exit]"
		}
		names = append(names, p.Name+suffix)
	}
	return strings.Join(names, ", ")
}

// firstV4 returns a peer's first IPv4 mesh address. `tailscale set
// --exit-node` is given the address rather than the name: a name has to be
// re-resolved by tailscale against MagicDNS, and MagicDNS is off here.
func firstV4(ips []string) string {
	for _, raw := range ips {
		if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return ""
}

// SetExitNode points this machine's default route at ip (or clears it when ip
// is empty).
//
// --accept-dns=false is passed on every call, including the clearing one, and
// it is not incidental. Accepting MagicDNS rewrites this host's resolver, so a
// headscale that misbehaves stops the machine resolving its own control plane
// — the same lockout arriving through DNS instead of through routing. Phase 1
// forces it off at enrolment; a `tailscale set` that omitted it here would
// leave the door open for anything else to turn it back on.
func SetExitNode(ctx context.Context, r Runner, ip string) error {
	args := []string{"set", "--exit-node=" + ip, "--accept-dns=false"}
	if ip != "" {
		// LAN access is what keeps the machine reachable from the network it
		// is physically on while its default route is elsewhere. Off, the
		// route exclusions would be the only thing holding that open.
		args = append(args, "--exit-node-allow-lan-access=true")
	} else {
		args = append(args, "--exit-node-allow-lan-access=false")
	}
	out, err := r.Run(ctx, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("tailscale %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

// ConfirmResult is everything the confirmation step measured, kept whole so a
// failure can be reported with its evidence instead of as a verdict.
//
// It carries FOUR addresses, not two, and that is the shape of the corrected
// invariant: the host's before and after, which must be the same address, and
// the containers' before and after, which must not be.
type ConfirmResult struct {
	// The host half. HostHeld is the assertion that used to be a hope.
	HostBefore   string
	HostAfter    string
	HostAfterVia string
	HostHeld     bool
	// HostMoved is the FAILED APPLY. It is separate from a plain !OK because
	// it is the only failure that means the machine was damaged rather than
	// the feature not working, and a caller has to be able to tell those
	// apart without parsing Reason.
	HostMoved bool

	// The container half.
	ContainerBefore ContainerEgressResult
	ContainerAfter  ContainerEgressResult
	Expected        string // "" when the caller did not state one

	DefaultDevice   string
	ControlPlaneOK  bool
	ControlPlaneErr error
	OK              bool
	Reason          string
}

// confirmSpec is what the confirmation needs to reach a verdict. A struct
// rather than nine positional arguments, because the two baselines are both
// strings and swapping them would invert the entire test.
type confirmSpec struct {
	platform     exitPlatform
	runtime      ContainerRuntime
	network      string
	hostBefore   string
	container    ContainerEgressResult
	expected     string
	controlPlane string
}

// confirmContainerScoped decides whether the switch actually worked, and it
// checks BOTH halves because either one alone is a half-measure:
//
//   - container-changed-only can hide the host having moved too, which is a
//     production machine losing its address while the screen says success;
//   - host-unchanged-only proves nothing happened at all.
//
// The order of the checks is the order of the damage:
//
//  1. THE HOST HELD. Measured first and failed first. A host whose public IP
//     moved is a failed apply and must revert even if the container's egress
//     looks perfect — the caller gets HostMoved so it can say so.
//  2. The control plane is still reachable, the anti-lockout check.
//  3. The containers really moved. With an expected address that is an exact
//     match; without one, the evidence available is that the address CHANGED.
//  4. The two addresses actually differ. A container egress equal to the
//     host's, with the host proven to have held, means the rules matched
//     nothing and the gate silently did nothing — the failure that used to be
//     indistinguishable from success.
func confirmContainerScoped(ctx context.Context, r Runner, spec confirmSpec) ConfirmResult {
	res := ConfirmResult{
		HostBefore:      spec.hostBefore,
		ContainerBefore: spec.container,
		Expected:        spec.expected,
	}

	if dev, err := spec.platform.routeDevice(ctx, r, "1.1.1.1"); err == nil {
		res.DefaultDevice = dev
	}

	host, err := PublicIP(ctx)
	if err != nil {
		// Not knowing is not the same as unchanged, and it must never be
		// reported as such: with the host bypass in force this host having no
		// internet is itself a failure worth reverting.
		res.Reason = "this host's own public IP could not be measured after the change, so it is not possible to assert that the machine's egress held — which is the one thing that must be proven: " + err.Error()
		return res
	}
	res.HostAfter, res.HostAfterVia = host.IP, host.Via

	if spec.hostBefore == "" {
		res.Reason = "this host's public IP was never measured before the change, so there is nothing to assert the host's egress against. Refusing to call a selection confirmed on the container's evidence alone"
		return res
	}
	if host.IP != spec.hostBefore {
		res.HostMoved = true
		res.Reason = fmt.Sprintf("THE HOST'S OWN EGRESS MOVED, from %s to %s (via %s). That is a failed apply whatever the containers are doing: this verb routes containers and the machine's own public IP is the thing that must not change", spec.hostBefore, host.IP, host.Via)
		return res
	}
	res.HostHeld = true

	if err := Reachable(ctx, spec.controlPlane); err != nil {
		res.ControlPlaneErr = err
		res.Reason = fmt.Sprintf("the control plane (%s) is NOT reachable with the exit node in force: %v — the exclusion that is supposed to keep the management path outside the tunnel is not working", spec.controlPlane, err)
		return res
	}
	res.ControlPlaneOK = true

	res.ContainerAfter = MeasureContainerEgress(ctx, r, spec.runtime, spec.network)
	res.OK, res.Reason = containerEgressVerdict(spec.container, res.ContainerAfter, spec.expected, host.IP)
	return res
}

// containerEgressVerdict is the container half of the decision, split out from
// the I/O so it can be tested against every combination rather than only
// against whatever the machine running `go test` happens to be behind.
func containerEgressVerdict(before, after ContainerEgressResult, expected, hostIP string) (bool, string) {
	if after.IP == "" {
		return false, fmt.Sprintf("the containers could not reach the internet at all through the new route: %s", after.Error)
	}
	switch {
	case expected != "":
		if after.IP != expected {
			return false, fmt.Sprintf("container egress is %s (via %s) but the exit gate was expected to present %s — the containers are not leaving through the gate that was selected", after.IP, after.Via, expected)
		}
	case before.IP == "":
		return false, fmt.Sprintf("container egress was not measured before the change (%s), so there is no baseline to compare against — re-run with --expect-egress <ip> to state what the gate should present", before.Error)
	case after.IP == before.IP:
		return false, fmt.Sprintf("container egress is still %s (via %s), the same address as before the switch — nothing measurable changed, so this cannot be reported as working. If this gate legitimately presents the same public IP the containers already used, re-run with --expect-egress %s to state that up front", after.IP, after.Via, after.IP)
	}
	// The host has already been proven to have held by the time this runs, so
	// an equal pair can only mean one thing — and it is the thing that reads
	// as success from the container's number alone.
	if after.IP == hostIP {
		return false, fmt.Sprintf("container egress (%s) is the SAME address the host leaves from, and the host is proven not to have moved — so the containers are not going through the gate at all. The rules matched no traffic; check that the networks discovered from %s are the ones the containers actually run on", after.IP, after.Network)
	}
	return true, ""
}

// Describe renders a confirmation for a human, success or failure alike. Both
// pairs, always, in the order the invariant reads: the host is supposed to be
// boring and the containers are supposed to have moved.
func (c ConfirmResult) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "host egress before: %s\n", orNone(c.HostBefore))
	fmt.Fprintf(&b, "host egress now:    %s", orNone(c.HostAfter))
	if c.HostAfterVia != "" {
		fmt.Fprintf(&b, " (measured via %s)", c.HostAfterVia)
	}
	switch {
	case c.HostMoved:
		b.WriteString("  <-- MOVED. This is a failed apply.")
	case c.HostHeld:
		b.WriteString("  <-- held, as required")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "container egress before: %s\n", orNone(c.ContainerBefore.IP))
	fmt.Fprintf(&b, "container egress now:    %s", orNone(c.ContainerAfter.IP))
	if c.ContainerAfter.Via != "" {
		fmt.Fprintf(&b, " (measured via %s, on network %s)", c.ContainerAfter.Via, c.ContainerAfter.Network)
	}
	b.WriteString("\n")
	if c.Expected != "" {
		fmt.Fprintf(&b, "container egress expected: %s\n", c.Expected)
	}
	if c.DefaultDevice != "" {
		fmt.Fprintf(&b, "the HOST's route for 1.1.1.1 leaves via: %s (must not be a tailscale interface)\n", c.DefaultDevice)
	}
	if c.ControlPlaneOK {
		b.WriteString("control plane: reachable\n")
	} else if c.ControlPlaneErr != nil {
		fmt.Fprintf(&b, "control plane: UNREACHABLE (%v)\n", c.ControlPlaneErr)
	}
	if !c.OK {
		fmt.Fprintf(&b, "NOT CONFIRMED: %s", c.Reason)
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "(not measured)"
	}
	return s
}
