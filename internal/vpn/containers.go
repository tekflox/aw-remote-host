// The container half of the exit gate: which container networks this host
// runs, and what address a container on one of them really leaves from.
//
// This file exists because of the scope correction of 2026-08-26. The feature
// is not "route this machine through a gate" — it is "route this machine's
// CONTAINERS through a gate, and leave the machine itself exactly where it
// is". Everything a rule can be keyed on therefore has to come from the
// container runtime, and two properties of how it is read are load-bearing:
//
//  1. NETWORK CIDRs, NEVER CONTAINER IPs. A container address is ephemeral AND
//     recycled: a rule pinned to 172.18.0.5 silently starts applying to
//     whatever different container next gets that address. That is not a
//     hypothesis — the aw-console outage of 2026-08-25 was exactly
//     `ip rule from 172.18.0.5 lookup 51821`, a per-IP rule that outlived its
//     tunnel and took one container off the internet for two days, invisibly.
//     A network's subnet is a property of the network, changes only when
//     somebody recreates it, and covers every container that will ever live
//     on it.
//
//  2. ASK THE RUNTIME, NEVER THE INTERFACE TABLE. exit.go's LocalPrefixes()
//     sweeps attached interfaces, which is right for "what is this host
//     already on" and wrong for this: a defined network with no running
//     container has no host-side bridge address at all. Measured on the
//     Surface (2026-08-26): podman knows two networks, `podman`
//     (10.88.0.0/16) and `aw-remote-host` (10.89.0.0/24), and `ip -4 addr`
//     shows only podman1/10.89.0.1. Routing from the interface table would
//     have silently missed half the containers on the box — and missed them
//     in the direction that reads as success.
package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ContainerProbeImage is the throwaway container the egress measurement runs.
//
// curlimages/curl rather than alpine/busybox for one reason that matters here:
// its curl speaks TLS to an IP literal, which is what makes the by-IP probe
// below possible. It is ~10MB, it is alpine underneath so it has /bin/sh, and
// it was already present on the Surface when this was written. A var so a
// host with a mirror, or a test, can point it elsewhere.
var ContainerProbeImage = "docker.io/curlimages/curl:latest"

// containerEgressEndpoints are tried in order INSIDE the container. The first
// is an IP literal on purpose: a container that inherits a broken resolver, or
// one on a network with dns_enabled=false, would otherwise report "no
// internet" for a gate that is forwarding perfectly. Measured working from a
// podman container on the Surface, 2026-08-26.
var containerEgressEndpoints = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
}

// ContainerRuntime is the container engine this host actually answers with.
type ContainerRuntime struct {
	// Name is "docker" or "podman" — the command as it is invoked.
	Name string
	// Version is whatever `<name> --version` printed, kept for the report so
	// a surprising network shape can be attributed rather than argued about.
	Version string
}

// Present reports whether a runtime was found at all.
func (rt ContainerRuntime) Present() bool { return rt.Name != "" }

// DefaultNetwork is the network a container joins when nobody says otherwise.
// Used only to PREFER one for the egress probe; a host that has deleted it
// falls back to whatever else is defined.
func (rt ContainerRuntime) DefaultNetwork() string {
	if rt.Name == "podman" {
		return "podman"
	}
	return "bridge"
}

// NoContainerRuntimeRefusal is what a host with no container engine is told,
// and it is a refusal rather than a fallback on purpose. There is nothing on
// such a machine whose egress this feature could move; the only thing left to
// route would be the host, which under the corrected invariant is the bug.
const NoContainerRuntimeRefusal = "no container runtime answers on this host (neither `docker` nor `podman`), so there are no container networks whose egress could be moved. The only thing left to route would be the machine itself, and moving a host's own route is exactly what this verb must never do — so this is a refusal, not a reason to fall back."

// NoContainerNetworkRefusal is the same refusal one step further in: a runtime
// that answers but has no network with an IPv4 subnet. Kept separate because
// it sends the operator somewhere different — "install a runtime" versus
// "create a network, or start the containers that would define one".
const NoContainerNetworkRefusal = "Create a network (or start the containers whose network was removed) and re-run; routing the host instead is not an option this verb offers."

// DetectContainerRuntime finds the engine on this host.
//
// It requires the runtime to ANSWER, not merely to be on PATH. A `docker`
// shim with no daemon behind it, or a podman whose socket is not up, is the
// house's own silent-degradation shape: present, green, and serving nothing.
// `network ls` is the probe because it is the exact call the next step makes,
// so a runtime that passes here cannot fail the one after it for a reason
// this could have found.
//
// docker is tried first. On a host that has both, docker is normally the one
// running the workloads, and podman frequently installs a `docker` alias that
// answers identically — so trying docker first either finds the real engine
// or finds podman wearing docker's name, and both are correct.
func DetectContainerRuntime(ctx context.Context, r Runner) (ContainerRuntime, error) {
	var tried []string
	for _, name := range []string{"docker", "podman"} {
		if out, err := r.Run(ctx, name, "network", "ls", "--format", "{{.Name}}"); err != nil {
			tried = append(tried, fmt.Sprintf("%s: %v: %s", name, err, strings.TrimSpace(firstLine(out))))
			continue
		}
		rt := ContainerRuntime{Name: name}
		if v, err := r.Run(ctx, name, "--version"); err == nil {
			rt.Version = strings.TrimSpace(firstLine(v))
		}
		return rt, nil
	}
	return ContainerRuntime{}, fmt.Errorf("%s (%s)", NoContainerRuntimeRefusal, strings.Join(tried, "; "))
}

// ContainerNetwork is one network the runtime owns, and the IPv4 prefixes
// containers on it are given addresses from.
type ContainerNetwork struct {
	Name    string
	Subnets []string
	// Attached is how many containers this network currently has attached,
	// measured by `<runtime> ps --filter network=<name>` rather than read off
	// `network inspect` — whose JSON carries no container list on either
	// runtime (podman's own inspect output has no "containers" key at all;
	// verified on the aw-remote-host workspace container, 2026-09-01).
	// PickProbeNetwork exists to key off this instead of the network's name.
	Attached int
}

// ContainerNetworks lists every network with at least one IPv4 subnet.
//
// Networks with no IPv4 subnet are dropped rather than reported empty: docker's
// `host` and `none` are not networks in this sense, an IPv6-only network has
// nothing an IPv4 rule could match, and a rule cannot be built from either.
// An `internal: true` network IS kept — its traffic never leaves the host, so
// a rule for it matches nothing and costs nothing, and dropping it would mean
// this list and the rules installed from it disagree about what exists.
func ContainerNetworks(ctx context.Context, r Runner, rt ContainerRuntime) ([]ContainerNetwork, error) {
	if !rt.Present() {
		return nil, fmt.Errorf("%s", NoContainerRuntimeRefusal)
	}
	out, err := r.Run(ctx, rt.Name, "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		return nil, fmt.Errorf("%s network ls: %w: %s", rt.Name, err, strings.TrimSpace(out))
	}
	var nets []ContainerNetwork
	for _, name := range strings.Fields(out) {
		if name == "host" || name == "none" {
			continue
		}
		raw, err := r.Run(ctx, rt.Name, "network", "inspect", name)
		if err != nil {
			// One unreadable network must not hide the others. A network that
			// cannot be inspected simply carries no rule, and saying which one
			// is what lets an operator tell "no containers are routed" apart
			// from "one network was skipped".
			continue
		}
		subnets := parseNetworkSubnets(raw)
		if len(subnets) == 0 {
			continue
		}
		nets = append(nets, ContainerNetwork{
			Name:     name,
			Subnets:  subnets,
			Attached: countAttachedContainers(ctx, r, rt, name),
		})
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].Name < nets[j].Name })
	return nets, nil
}

// countAttachedContainers measures how many containers a network actually
// has attached. Best-effort and fails CLOSED: a network whose attachment
// could not be measured counts as unpopulated rather than as populated,
// because the cost of the two mistakes is not symmetric here — probing a
// network nothing lives on produces a confident wrong answer (the bug this
// whole file exists to fix), while refusing a network that was in fact
// populated only costs a clearer error message.
func countAttachedContainers(ctx context.Context, r Runner, rt ContainerRuntime, network string) int {
	out, err := r.Run(ctx, rt.Name, "ps", "--filter", "network="+network, "--format", "{{.ID}}")
	if err != nil {
		return 0
	}
	return len(strings.Fields(out))
}

// parseNetworkSubnets pulls IPv4 CIDRs out of a `network inspect` document.
//
// Three shapes are in play on the hosts this runs on, and the version that
// produces each is not knowable in advance from the command name:
//
//	podman 4.x / netavark : [{"subnets":[{"subnet":"10.88.0.0/16"}]}]
//	docker                : [{"IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}}]
//	podman 3.x / CNI      : [{"plugins":[{"ipam":{"ranges":[[{"subnet":…}]]}}]}]
//
// internal/wsl/wsl.go's header documents why the CNI-era one is still live
// here: jammy ships podman 3.4.4. Rather than three parsers gated on a version
// string this walks the decoded document for any key named `subnet`/`Subnet`
// whose value parses as an IPv4 CIDR. That cannot drift when a fourth shape
// appears, and it cannot invent one either — net.ParseCIDR is the filter, so a
// field that merely looks like a subnet does not become a routing rule.
func parseNetworkSubnets(raw string) []string {
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var found []string
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, value := range v {
				if s, ok := value.(string); ok && strings.EqualFold(key, "subnet") {
					if cidr := normaliseV4CIDR(s); cidr != "" && !seen[cidr] {
						seen[cidr] = true
						found = append(found, cidr)
					}
					continue
				}
				walk(value)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(doc)
	sort.Strings(found)
	return found
}

// normaliseV4CIDR returns the masked IPv4 CIDR, or "" for anything that is not
// one. Masking matters: a rule has to be keyed on the network, and
// "10.89.0.1/24" and "10.89.0.0/24" are the same network written two ways.
func normaliseV4CIDR(raw string) string {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || ipnet.IP.To4() == nil {
		return ""
	}
	return ipnet.String()
}

// ContainerSubnets flattens the networks into the deduplicated, sorted prefix
// list the routing rules are built from. Two networks sharing a subnet — which
// happens when one is recreated under a new name — must produce one rule, not
// two, or the cleanup count stops matching what was installed.
func ContainerSubnets(nets []ContainerNetwork) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nets {
		for _, s := range n.Subnets {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// NetworksFor names which networks a prefix came from, for the narration. A
// bare CIDR does not tell an operator which of their containers just moved.
func NetworksFor(nets []ContainerNetwork, subnet string) []string {
	var out []string
	for _, n := range nets {
		for _, s := range n.Subnets {
			if s == subnet {
				out = append(out, n.Name)
			}
		}
	}
	return out
}

// NoAttachedContainerRefusal is the refusal one step further than
// NoContainerNetworkRefusal: every network the runtime named has an IPv4
// subnet, but none has a single container attached to probe from. Kept
// separate because the remedy is different — start a container on one of
// them, not create a new network.
const NoAttachedContainerRefusal = "start a container on one of them (or point this host at the network that already has containers) and re-run; routing the host instead is not an option this verb offers."

// PickProbeNetwork chooses the network the egress probe runs on, and reports
// why — so the plan text can say which network was picked instead of merely
// asserting one.
//
// This used to prefer the runtime's DEFAULT-NAMED network unconditionally,
// which assumed the default network is the populated one. Measured wrong on
// the aw-remote-host workspace container itself (b614f41828c8, 2026-09-01):
// `podman` (10.88.0.0/16) is the default-named network and it is EMPTY,
// while all 75 real containers are on `aw-remote-host` (10.89.0.0/24). A
// probe run there would have measured nothing while a `--plan` confidently
// named the empty network.
//
// The choice is now MEASURED: a network only qualifies if it has at least
// one container ATTACHED (ContainerNetwork.Attached, from `ps --filter
// network=<name>`). Among networks that qualify, the runtime's default name
// is still preferred and the fallback is still the first by name — nets
// arrives sorted from ContainerNetworks — so a host measured twice with the
// same containers attached still reports the same network.
//
// Returns "" with the reason when no network qualifies. That is a refusal,
// not "pick the first one anyway": a host with networks but no attached
// containers has nothing whose egress this feature could move.
func PickProbeNetwork(rt ContainerRuntime, nets []ContainerNetwork) (network, reason string) {
	var populated []ContainerNetwork
	for _, n := range nets {
		if n.Attached > 0 {
			populated = append(populated, n)
		}
	}
	if len(populated) == 0 {
		return "", fmt.Sprintf("none of the %d container network(s) this host defines has a container attached, so there is nothing to measure egress from", len(nets))
	}
	for _, n := range populated {
		if n.Name == rt.DefaultNetwork() {
			return n.Name, fmt.Sprintf("%s (%d container(s) attached) — the runtime's default network", n.Name, n.Attached)
		}
	}
	n := populated[0]
	return n.Name, fmt.Sprintf("%s (%d container(s) attached) — the runtime's default network (%s) has none attached", n.Name, n.Attached, rt.DefaultNetwork())
}

// ContainerEgressResult is one container-egress measurement, with everything
// needed to attribute it.
type ContainerEgressResult struct {
	// Runtime and Network say what was measured, so the number can be compared
	// with a later one rather than merely believed.
	Runtime string `json:"runtime"`
	Network string `json:"network"`
	IP      string `json:"ip"`
	Via     string `json:"via"`
	// Error is why there is no address. Kept alongside an empty IP rather than
	// replacing the whole result: the honesty contract this shares with
	// vpn_public_ip is that a failed measurement says it failed and NEVER
	// renders a remembered address. A host with no runtime says exactly that.
	Error string `json:"error,omitempty"`
}

// MeasureContainerEgress runs a throwaway container and reads the address it
// leaves the internet from.
//
// This is the ONE container-egress measurement in this module, and the two
// cards it serves share it rather than each growing their own: the exit gate
// uses it as half of its confirmation, and the per-host dual public IP
// (vpn_public_ip) reports it next to the host's own. Two implementations would
// drift, and the divergence between the two addresses is the entire feature —
// a divergence produced by two different measurement methods would prove
// nothing.
//
// Measurement discipline, all three deliberate:
//
//   - FRESH CONNECTION BY CONSTRUCTION. A new container, a new process, a new
//     socket. There is no pool that could answer over the path that existed
//     before the route moved, which is the specific way this kind of check
//     lies (and why --expect-egress had to exist).
//   - BY IP FIRST. The first endpoint is an IP literal, so a container with a
//     broken or absent resolver does not report "no internet" for a gate that
//     is forwarding. Networks with dns_enabled=false are normal here.
//   - NEVER THE HOST'S ANSWER. If the container cannot be run or cannot reach
//     anything, this returns the reason. It never falls back to the host's
//     own public IP — under the corrected model those two numbers differing
//     IS the result, so copying one into the other would fabricate exactly
//     the evidence somebody is about to trust.
func MeasureContainerEgress(ctx context.Context, r Runner, rt ContainerRuntime, network string) ContainerEgressResult {
	res := ContainerEgressResult{Runtime: rt.Name, Network: network}
	if !rt.Present() {
		res.Error = NoContainerRuntimeRefusal
		return res
	}
	if network == "" {
		res.Error = "no container network to measure on: the runtime answered but defines no network with an IPv4 subnet"
		return res
	}

	args := []string{"run", "--rm", "--network", network, "--entrypoint", "sh", ContainerProbeImage, "-c", containerEgressScript()}
	out, err := r.Run(ctx, rt.Name, args...)
	if err != nil {
		res.Error = fmt.Sprintf("%s run on network %s could not measure container egress: %v: %s", rt.Name, network, err, strings.TrimSpace(lastLine(out)))
		return res
	}
	via, ip := parseContainerEgress(out)
	if ip == "" {
		res.Error = fmt.Sprintf("the probe container ran on network %s but produced no usable address (output: %q)", network, strings.TrimSpace(lastLine(out)))
		return res
	}
	res.IP, res.Via = ip, via
	return res
}

// containerEgressScript tries each endpoint in one container rather than
// starting one container per endpoint. Same fresh-connection guarantee, a
// single image start, and the endpoint that answered comes back with the
// address so a surprising number can be attributed to a provider.
func containerEgressScript() string {
	var b strings.Builder
	b.WriteString("for u in ")
	b.WriteString(strings.Join(containerEgressEndpoints, " "))
	b.WriteString("; do\n")
	b.WriteString("  out=$(curl -sS -4 --max-time 8 \"$u\" 2>/dev/null) || continue\n")
	// cdn-cgi/trace answers a key=value blob; the others answer a bare
	// address. Pull the keyed form first, fall back to the first line.
	b.WriteString("  ip=$(printf '%s\\n' \"$out\" | sed -n 's/^ip=//p' | head -1)\n")
	b.WriteString("  [ -n \"$ip\" ] || ip=$(printf '%s\\n' \"$out\" | head -1)\n")
	b.WriteString("  if [ -n \"$ip\" ]; then echo \"AW_EGRESS $u $ip\"; exit 0; fi\n")
	b.WriteString("done\n")
	b.WriteString("exit 1\n")
	return b.String()
}

// parseContainerEgress reads the probe's one marked line. The marker is what
// keeps a pull progress line, a podman warning on stderr, or an image's own
// banner from being mistaken for an address — and net.ParseIP is what keeps
// anything that is not one from becoming a measurement.
func parseContainerEgress(out string) (via, ip string) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 3 || fields[0] != "AW_EGRESS" {
			continue
		}
		parsed := net.ParseIP(fields[2])
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		return fields[1], parsed.To4().String()
	}
	return "", ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func lastLine(s string) string {
	trimmed := strings.TrimRight(s, "\n")
	if i := strings.LastIndexByte(trimmed, '\n'); i >= 0 {
		return trimmed[i+1:]
	}
	return trimmed
}
