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

const (
	// exclusionPriority is the `ip rule` priority the route exclusions are
	// installed at.
	//
	// Measured on aw-baremetal 2026-08-25 — tailscale's own rules are:
	//
	//	5210: from all fwmark 0x80000/0xff0000 lookup main
	//	5230: from all fwmark 0x80000/0xff0000 lookup default
	//	5250: from all fwmark 0x80000/0xff0000 unreachable
	//	5270: from all lookup 52
	//
	// 5270 is the catch-all that puts every packet into tailscale's table.
	// 5260 is immediately above it, so an exclusion wins over the tunnel; the
	// three fwmark rules above only ever match tailscaled's OWN packets, so
	// sitting below them shadows nothing. Living inside tailscale's reserved
	// 5210-5270 block is also why this priority is safe to delete blindly in
	// ClearExclusions: nothing else in the system allocates there.
	exclusionPriority = 5260

	// exitConfirmEndpointTimeout bounds a single public-IP lookup. Short on
	// purpose — when an exit gate is broken these hang, and every second
	// spent hanging is a second the machine is off the internet.
	exitConfirmEndpointTimeout = 8 * time.Second
)

// egressEndpoints are the plain-text "what is my public IP" services tried in
// order. Three, from three different operators, because the confirmation step
// is what stands between a broken exit node and a stranded host: one
// provider having a bad day must not read as "the route is broken", and must
// not read as "the route is fine" either.
var egressEndpoints = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
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

	for _, ip := range plan.ControlPlaneIPs {
		add(ip+"/32", "the control plane / /link tunnel endpoint ("+host+") — the only remote-management path this host has")
	}
	for _, l := range locals {
		add(l.Prefix, "directly attached network on "+l.Iface+" (LAN prefix / container bridge — internal/lanfastpath depends on the LAN one)")
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

// ApplyExclusions installs the plan as `ip rule` entries.
//
// Existing exclusions are cleared first, so a second use-exit against a
// different gate does not leave the first run's pins behind. It is also why
// this is not additive: two overlapping generations of exclusion is precisely
// the leftover-state failure the package header describes.
func ApplyExclusions(ctx context.Context, r Runner, ex []Exclusion) error {
	if _, err := clearIPRuleExclusions(ctx, r); err != nil {
		return err
	}
	for _, e := range ex {
		out, err := r.Run(ctx, "ip", "rule", "add", "to", e.Prefix, "lookup", "main", "priority", fmt.Sprint(exclusionPriority))
		if err != nil {
			// Roll back rather than leave a half-applied exclusion set: a
			// partial set is worse than none, because it reads like the
			// management path is pinned when it may be the one that failed.
			_, _ = clearIPRuleExclusions(ctx, r)
			return fmt.Errorf("install route exclusion for %s: %w: %s", e.Prefix, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// ClearExclusions removes whatever this host's platform installed. On a Mac
// that is nothing, and it answers (0, nil) rather than reaching for `ip`.
func ClearExclusions(ctx context.Context, r Runner) (int, error) {
	return currentPlatform().clearExclusions(ctx, r)
}

// clearIPRuleExclusions removes every rule this package installed, by
// deleting at its own priority until the kernel says there are none left.
//
// Deleting by priority rather than by exact spec is what makes cleanup total.
// A rule whose spec drifted (a prefix rewritten by something else, a run that
// died between two adds) would survive a spec-matched delete and become the
// leftover this whole design is built to avoid.
func clearIPRuleExclusions(ctx context.Context, r Runner) (int, error) {
	removed := 0
	for i := 0; i < 64; i++ {
		out, err := r.Run(ctx, "ip", "rule", "del", "priority", fmt.Sprint(exclusionPriority))
		if err != nil {
			// The kernel answers "RTNETLINK answers: No such file or
			// directory" once the last one is gone. That is the loop's exit
			// condition, not a failure.
			if isNoSuchRule(out) {
				return removed, nil
			}
			return removed, fmt.Errorf("remove route exclusions: %w: %s", err, strings.TrimSpace(out))
		}
		removed++
	}
	return removed, fmt.Errorf("removed %d route exclusions and there are still more at priority %d — refusing to loop", removed, exclusionPriority)
}

func isNoSuchRule(out string) bool {
	lowered := strings.ToLower(out)
	return strings.Contains(lowered, "no such file") || strings.Contains(lowered, "cannot find")
}

// ListExclusions reads back the exclusions actually in force. `status` shows
// this rather than what state.json remembers being asked for — the whole
// hazard is a rule outliving the intent that created it.
func ListExclusions(ctx context.Context, r Runner) ([]string, error) {
	return currentPlatform().listExclusions(ctx, r)
}

func listIPRuleExclusions(ctx context.Context, r Runner) ([]string, error) {
	out, err := r.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return nil, fmt.Errorf("read ip rules: %w: %s", err, strings.TrimSpace(out))
	}
	return parseExclusionRules(out), nil
}

// parseExclusionRules picks the exclusion lines out of `ip rule show`. The
// format is "5260:\tfrom all to 1.2.3.4 lookup main".
func parseExclusionRules(out string) []string {
	var found []string
	prefix := fmt.Sprint(exclusionPriority) + ":"
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "to" && i+1 < len(fields) {
				found = append(found, fields[i+1])
			}
		}
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
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
			continue
		}
		return Egress{IP: ip, Via: endpoint}, nil
	}
	return Egress{}, fmt.Errorf("could not determine this host's public IP from any endpoint: %s", strings.Join(errs, "; "))
}

func fetchIP(ctx context.Context, endpoint string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, exitConfirmEndpointTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return "", fmt.Errorf("answered %q, which is not an IP address", strings.TrimSpace(string(body)))
	}
	return ip.String(), nil
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
type ConfirmResult struct {
	Baseline        string
	Observed        string
	ObservedVia     string
	Expected        string // "" when the caller did not state one
	DefaultDevice   string
	ControlPlaneOK  bool
	ControlPlaneErr error
	OK              bool
	Reason          string
}

// ConfirmEgress decides whether the switch actually worked.
//
// Three things have to be true, and "the interface is up" is not one of them:
//
//  1. The machine can still reach the internet at all. This is the
//     anti-lockout check and it is why a failure here triggers a revert.
//  2. The traffic really moved. With an expected address (--expect-egress, or
//     whatever the console knows the gate's address to be) that is an exact
//     match. Without one, the only available evidence is that the public IP
//     CHANGED — so an unchanged address is treated as a failure, per the
//     card's rule, even though there are legitimate topologies where a
//     correct switch produces the same address (a gate that NATs to the same
//     public IP the client already used). Those topologies are exactly what
//     --expect-egress is for, and the failure message says so rather than
//     leaving the operator to guess.
//  3. The control plane is still reachable. If it is not, the exclusion did
//     not do its job and the machine has lost its management path even
//     though it still has internet.
func ConfirmEgress(ctx context.Context, r Runner, baseline, expected, controlPlaneURL string) ConfirmResult {
	return confirmEgress(ctx, r, currentPlatform(), baseline, expected, controlPlaneURL)
}

func confirmEgress(ctx context.Context, r Runner, plat exitPlatform, baseline, expected, controlPlaneURL string) ConfirmResult {
	res := ConfirmResult{Baseline: baseline, Expected: expected}

	if dev, err := plat.routeDevice(ctx, r, "1.1.1.1"); err == nil {
		res.DefaultDevice = dev
	}

	egress, err := PublicIP(ctx)
	if err != nil {
		res.Reason = "this host could not reach the internet at all through the new route: " + err.Error()
		return res
	}
	res.Observed = egress.IP
	res.ObservedVia = egress.Via

	if err := Reachable(ctx, controlPlaneURL); err != nil {
		res.ControlPlaneErr = err
		res.Reason = fmt.Sprintf("the control plane (%s) is NOT reachable with the exit node in force: %v — the route exclusion that is supposed to keep the management path outside the tunnel is not working", controlPlaneURL, err)
		return res
	}
	res.ControlPlaneOK = true

	res.OK, res.Reason = egressVerdict(baseline, expected, egress)
	return res
}

// egressVerdict is the decision, split out from the I/O so it can be tested
// against every combination rather than only against whatever the machine
// running `go test` happens to be behind.
func egressVerdict(baseline, expected string, egress Egress) (bool, string) {
	switch {
	case expected != "":
		if egress.IP != expected {
			return false, fmt.Sprintf("egress is %s (via %s) but the exit gate was expected to present %s — traffic is not leaving through the gate that was selected", egress.IP, egress.Via, expected)
		}
	case baseline == "":
		return false, "there is no baseline public IP to compare against, so the switch cannot be confirmed — re-run with --expect-egress <ip> to state what the gate should present"
	case egress.IP == baseline:
		return false, fmt.Sprintf("egress is still %s (via %s), the same address as before the switch — nothing measurable changed, so this cannot be reported as working. If this gate legitimately presents the same public IP this host already used, re-run with --expect-egress %s to state that up front", egress.IP, egress.Via, egress.IP)
	}
	return true, ""
}

// Describe renders a confirmation for a human, success or failure alike.
func (c ConfirmResult) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "egress before: %s\n", orNone(c.Baseline))
	fmt.Fprintf(&b, "egress now:    %s", orNone(c.Observed))
	if c.ObservedVia != "" {
		fmt.Fprintf(&b, " (measured via %s)", c.ObservedVia)
	}
	b.WriteString("\n")
	if c.Expected != "" {
		fmt.Fprintf(&b, "egress expected: %s\n", c.Expected)
	}
	if c.DefaultDevice != "" {
		fmt.Fprintf(&b, "default route for 1.1.1.1 leaves via: %s\n", c.DefaultDevice)
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
