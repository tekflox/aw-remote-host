package vpn

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// Gate 2 of the DNS-tunnelling design: plan, apply, revert, the revert SCRIPT
// and each refusal, all against a fake runner — no podman, no network, no
// host.
//
// The bias throughout is that a FAILED proof must be indistinguishable from
// never having tried: no rule left behind, no upstream left behind,
// DNSTunneled false and DNSNotTunnelledWarning present. That asymmetry is the
// whole safety case — the failure this feature can cause (30 containers with
// no external DNS) is worse than the leak it closes, so every path out of a
// half-applied state is tested here rather than discovered on the host.
//
// REVISION 1 (§11 of the design) moved the mechanism from a MAIN-TABLE /32 to
// a policy rule scoped to `ipproto {udp,tcp} dport 53`. Everything about the
// two flows — the resolver's queries and this host's own HTTPS egress probe to
// the same address — is asserted here, because the withdrawn version was
// correct about every file it touched and wrong about exactly that.

const (
	testDNS        = "10.9.9.9"
	testPodmanPath = "/usr/bin/podman"
	testNetwork    = "aw-remote-host"
	testContainer  = "5584662f4f57"
	// testTunnelDev / testMainDev are what the two proofs discriminate on.
	testTunnelDev = "wg0"
	testMainDev   = "enp41s0"
)

// podmanHost is healthyHost's shape with podman as the runtime and a container
// on one network, which is what this deployment actually looks like — measured
// 2026-09-08: aw-remote-host-workspace at 10.89.0.39 on network aw-remote-host
// (podman1, 10.89.0.0/24), aardvark bound to 10.89.0.1 with a BARE first line.
func podmanHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"ip -V":                                        "ip utility, iproute2-6.15.0",
		"podman network ls":                            "aw-remote-host\npodman\n",
		"podman --version":                             "podman version 5.4.2",
		"podman inspect -f {{.Id}}":                    testContainer + " 10.89.0.39 ",
		"podman inspect -f {{range $k":                 testNetwork + " ",
		"ip route show table 200":                      "default via 10.8.0.2 dev wg0 \n10.89.0.0/24 dev podman1 scope link \n",
		"ip route show default":                        "default via 65.109.66.65 dev enp41s0 proto static onlink \n",
		"ip -4 -o addr show":                           "1: lo    inet 127.0.0.1/8 scope host lo\n2: enp41s0    inet 65.109.66.88/32 scope global enp41s0\n",
		"cat " + aardvarkConfigDir + "/" + testNetwork: "10.89.0.1\n",
	}}
}

// applyingRunner is a tableRunner that REACTS to the writes made through it:
// an `ip rule add` makes `ip rule show` start listing it, and a `--dns-add`
// rewrites the aardvark config's first line.
//
// A static fixture cannot express this, and the difference is not cosmetic —
// it is the whole revert path. Every undo here is check-then-delete, so a
// fixture where the add left no trace would let a revert "pass" by skipping
// the delete it was supposed to make, which is precisely the orphaned rule
// into a disappearing tunnel that this test file is about. The `ip rule show`
// line it renders is VERBATIM the shape measured on the host 2026-09-08:
//
//	5390:	from all to 198.51.100.7 ipproto udp dport 53 lookup 9911
//
// — note that `ip` drops the `/32` from a single-host prefix, exactly as it
// does from the container rule's `from`.
type applyingRunner struct {
	*tableRunner
	network string
	// rules is priority -> the line `ip rule show` prints for it.
	rules map[int]string
	// noConfigWrite reproduces the §4.4 case that the read-back exists for: a
	// `podman network update` that exits 0 while the aardvark config is
	// unchanged. Without a switch for it the read-back could only ever be
	// tested against a runner that also faked the failure of the command.
	noConfigWrite bool
}

func newApplyingRunner(base *tableRunner) *applyingRunner {
	a := &applyingRunner{tableRunner: base, network: testNetwork, rules: map[int]string{}}
	a.renderRules()
	return a
}

// renderRules keeps `ip rule show` consistent with what has been added, with
// the container rule always present so the fixture reads like a real host.
func (a *applyingRunner) renderRules() {
	lines := []string{"0:\tfrom all lookup local"}
	for _, pri := range sortedPriorities(a.rules) {
		lines = append(lines, a.rules[pri])
	}
	lines = append(lines, "32766:\tfrom all lookup main")
	a.answers["ip rule show"] = strings.Join(lines, "\n") + "\n"
}

func sortedPriorities(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (a *applyingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := a.tableRunner.Run(ctx, name, args...)
	if err != nil {
		return out, err
	}
	cfg := "cat " + aardvarkConfigDir + "/" + a.network
	switch {
	case name == "ip" && len(args) > 1 && args[0] == "rule" && (args[1] == "add" || args[1] == "del"):
		if line, pri, ok := parseDNSRuleArgs(args); ok {
			if args[1] == "add" {
				a.rules[pri] = line
			} else {
				delete(a.rules, pri)
			}
			a.renderRules()
		}
	case strings.Contains(strings.Join(args, " "), "network update"):
		full := strings.Join(args, " ")
		for _, dns := range dnsAddressesIn(full, "--dns-add") {
			if a.noConfigWrite {
				continue
			}
			a.answers[cfg] = "10.89.0.1 " + strings.Join(appendUnique(currentUpstreams(a.answers[cfg]), dns), ",") + "\n"
		}
		for _, dns := range dnsAddressesIn(full, "--dns-drop") {
			left := removeAddress(currentUpstreams(a.answers[cfg]), dns)
			if len(left) == 0 {
				a.answers[cfg] = "10.89.0.1\n"
			} else {
				a.answers[cfg] = "10.89.0.1 " + strings.Join(left, ",") + "\n"
			}
		}
	}
	return out, err
}

// parseDNSRuleArgs turns the args this package builds back into the line the
// kernel would print for them. It reads the SELECTOR rather than pattern
// matching a string, so a rule added with one spelling and deleted with
// another would not cancel out here either — which is the bug the assertions
// about `ip rule del` exist to catch.
func parseDNSRuleArgs(args []string) (line string, priority int, ok bool) {
	var to, proto, dport, table, pri string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "to":
			to = args[i+1]
		case "ipproto":
			proto = args[i+1]
		case "dport":
			dport = args[i+1]
		case "lookup":
			table = args[i+1]
		case "priority":
			pri = args[i+1]
		}
	}
	if to == "" || proto == "" || dport == "" || table == "" || pri == "" {
		return "", 0, false
	}
	n, err := strconv.Atoi(pri)
	if err != nil {
		return "", 0, false
	}
	return fmt.Sprintf("%s:\tfrom all to %s ipproto %s dport %s lookup %s",
		pri, strings.TrimSuffix(to, "/32"), proto, dport, table), n, true
}

func dnsAddressesIn(full, flag string) []string {
	var out []string
	f := strings.Fields(full)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == flag {
			out = append(out, f[i+1])
		}
	}
	return out
}

func currentUpstreams(line string) []string {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 {
		return nil
	}
	var out []string
	for _, part := range strings.Split(f[1], ",") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func removeAddress(list []string, v string) []string {
	var out []string
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// withFakePodmanPath makes §4.2's absolute-path resolution deterministic. The
// real lookup is exec.LookPath, so a test that used it would pass or fail on
// whether the machine running `go test` happens to have podman installed.
func withFakePodmanPath(t *testing.T, path string, err error) {
	t.Helper()
	prev := lookupExternalBinary
	lookupExternalBinary = func(name string) (string, error) {
		if name == "podman" {
			return path, err
		}
		return prev(name)
	}
	t.Cleanup(func() { lookupExternalBinary = prev })
}

func planDNSOn(t *testing.T, r Runner, dns []string) *ExternalRoutePlan {
	t.Helper()
	plan, err := PlanExternalRoute(context.Background(), ExternalRouteSpec{
		Container: "aw-remote-host-workspace",
		Runner:    r,
		Runtime:   ContainerRuntime{Name: "podman"},
		TunnelDNS: true,
		DNS:       dns,
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Refusal != "" {
		t.Fatalf("the DNS half must never turn into a REFUSAL of the route: %s", plan.Refusal)
	}
	return plan
}

// collectProgress captures the narration so a test can assert a case was
// NAMED, not merely handled.
func collectProgress(lines *[]string) Progress {
	return func(level, message string) { *lines = append(*lines, level+": "+message) }
}

// --- §4.1 / §4.2, plan time -------------------------------------------------

func TestPlanResolvesTheDNSHalfFromTheProfileAndTheRuntime(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{testDNS})

	if len(plan.DNSServers) != 1 || plan.DNSServers[0] != testDNS {
		t.Fatalf("dns servers: %v", plan.DNSServers)
	}
	// RESOLVED from `podman inspect`, never assumed. §9 records that writing
	// this as a constant is the door that closes the day a second network
	// exists on this host.
	if plan.DNSNetwork != testNetwork {
		t.Fatalf("network must come from inspect, got %q", plan.DNSNetwork)
	}
	if plan.DNSPodmanPath != testPodmanPath {
		t.Fatalf("podman path must be absolute and resolved at plan time, got %q", plan.DNSPodmanPath)
	}
	// The host's measured state today: a bare first line, no upstream.
	if len(plan.DNSPrior) != 0 {
		t.Fatalf("prior upstreams: %v", plan.DNSPrior)
	}
	// The priority band is resolved at PLAN time and persisted, because
	// `ip rule del` matches on it: a revert that recomputed it would delete
	// nothing on a host whose apply used a different base.
	if plan.DNSPriority != ExternalRouteDNSPriority {
		t.Fatalf("dns priority band: got %d, want %d", plan.DNSPriority, ExternalRouteDNSPriority)
	}
	// A PLAN has applied nothing, so it may not claim the resolver moved.
	if plan.DNSTunneled {
		t.Fatal("dns_tunneled=true on a plan — nothing has been applied, so this would be a claim about a change that has not happened")
	}
}

// Each plan-time precondition, failing on its own, has to leave the DNS half
// entirely unresolved — and leave the ROUTE alone. A route that failed because
// DNS could not be tunnelled would regress behaviour that has shipped.
func TestEachPlanTimePreconditionLeavesTheDNSHalfUnattempted(t *testing.T) {
	cases := []struct {
		name  string
		why   string
		setup func(t *testing.T) (*tableRunner, ExternalRouteSpec)
	}{
		{
			name: "the caller did not ask",
			why:  "the change is network-wide, so it must never be opt-out",
			setup: func(t *testing.T) (*tableRunner, ExternalRouteSpec) {
				withFakePodmanPath(t, testPodmanPath, nil)
				return podmanHost(), ExternalRouteSpec{TunnelDNS: false, DNS: []string{testDNS}}
			},
		},
		{
			name: "§4.1 the profile carries no resolver",
			why:  "there is nothing to point aardvark at",
			setup: func(t *testing.T) (*tableRunner, ExternalRouteSpec) {
				withFakePodmanPath(t, testPodmanPath, nil)
				return podmanHost(), ExternalRouteSpec{TunnelDNS: true, DNS: nil}
			},
		},
		{
			name: "§4.1 the profile's resolver is not an IP",
			why:  "this string ends up inside a dead-man's shell script",
			setup: func(t *testing.T) (*tableRunner, ExternalRouteSpec) {
				withFakePodmanPath(t, testPodmanPath, nil)
				return podmanHost(), ExternalRouteSpec{TunnelDNS: true, DNS: []string{"dns.example.com"}}
			},
		},
		{
			name: "§4.2 podman's absolute path does not resolve",
			why:  "a DNS change the dead-man cannot revert is the change that was rejected once already",
			setup: func(t *testing.T) (*tableRunner, ExternalRouteSpec) {
				withFakePodmanPath(t, "", fmt.Errorf("exec: \"podman\": executable file not found in $PATH"))
				return podmanHost(), ExternalRouteSpec{TunnelDNS: true, DNS: []string{testDNS}}
			},
		},
		{
			name: "the container is on more than one network",
			why:  "moving one network's resolver would half-move the container's DNS",
			setup: func(t *testing.T) (*tableRunner, ExternalRouteSpec) {
				withFakePodmanPath(t, testPodmanPath, nil)
				r := podmanHost()
				r.answers["podman inspect -f {{range $k"] = "aw-remote-host second-net "
				return r, ExternalRouteSpec{TunnelDNS: true, DNS: []string{testDNS}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, spec := tc.setup(t)
			spec.Container = "aw-remote-host-workspace"
			spec.Runner = r
			spec.Runtime = ContainerRuntime{Name: "podman"}
			plan, err := PlanExternalRoute(context.Background(), spec)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if plan.Refusal != "" {
				t.Fatalf("this must not refuse the ROUTE (%s): %s", tc.why, plan.Refusal)
			}
			if len(plan.DNSServers) != 0 || plan.DNSNetwork != "" || plan.DNSPodmanPath != "" {
				t.Fatalf("the DNS half was resolved anyway (%s): servers=%v network=%q podman=%q",
					tc.why, plan.DNSServers, plan.DNSNetwork, plan.DNSPodmanPath)
			}
			if plan.DNSTunneled {
				t.Fatalf("dns_tunneled=true (%s)", tc.why)
			}
			if !containsString(plan.Warnings, DNSNotTunnelledWarning) {
				t.Fatalf("the honest warning is missing (%s): %v", tc.why, plan.Warnings)
			}
			// And nothing was touched. Plan mode is read-only, and a plan that
			// wrote would make `--plan` a second code path that might disagree.
			if r.ran("podman network update") || r.ran("ip rule add") || r.ran("ip route add") {
				t.Fatalf("plan mutated the machine (%s): %v", tc.why, r.calls)
			}
		})
	}
}

// A runtime that is not podman gets the warning rather than an attempt: docker
// has no `network update`, so there is no verb to move an upstream with.
func TestDockerHostCannotTunnelDNSAndSaysSo(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan, err := PlanExternalRoute(context.Background(), ExternalRouteSpec{
		Container: "aw-remote-host",
		Runner:    healthyHost(),
		Runtime:   ContainerRuntime{Name: "docker"},
		TunnelDNS: true,
		DNS:       []string{testDNS},
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Refusal != "" {
		t.Fatalf("a docker host must still be routable: %s", plan.Refusal)
	}
	if len(plan.DNSServers) != 0 {
		t.Fatalf("docker has no `network update`, so nothing may be planned: %v", plan.DNSServers)
	}
	if !containsString(plan.Warnings, DNSNotTunnelledWarning) {
		t.Fatalf("warnings: %v", plan.Warnings)
	}
}

// --- the two flow proofs, §11.4 ---------------------------------------------

// readyHost is a machine on which every proof WILL hold: nothing applied yet,
// plus the answers an applyingRunner cannot synthesise because they are facts
// about the tunnel rather than echoes of a command — what the kernel says each
// FLOW's device is, and what the probe in the container's namespace resolves.
//
// The two `ip route get` shapes per resolver are the fixture's whole point:
// with a dport-53 selector the answer is the tunnel, without one it is the
// main path. That is the disagreement gate 1b proved on the real kernel
// (iproute2-6.15.0 / 7.0.0-22-generic, 2026-09-08) and it is what makes this
// mechanism legitimate where a main-table /32 was not.
func readyHost(dns ...string) *applyingRunner {
	r := podmanHost()
	for _, d := range dns {
		r.answers["ip route get "+d+" ipproto udp dport 53"] = d + " dev " + testTunnelDev + " table 200 src 10.8.0.12 uid 0 \n    cache \n"
		r.answers["ip route get "+d+" ipproto tcp dport 53"] = d + " dev " + testTunnelDev + " table 200 src 10.8.0.12 uid 0 \n    cache \n"
		r.answers["ip route get "+d] = d + " via 65.109.66.65 dev " + testMainDev + " src 65.109.66.88 uid 0 \n    cache \n"
	}
	r.answers[testPodmanPath+" run --rm --network container:"] = "AW_DNS_OK example.com\n"
	return newApplyingRunner(r)
}

// appliedHost is podmanHost with both writes ALREADY in place — the state a
// reassert pass or a status poll finds on a healthy machine, where nothing is
// being written and so nothing has to react.
func appliedHost() *tableRunner {
	r := podmanHost()
	r.answers["ip rule show"] = "0:\tfrom all lookup local\n" +
		"5399:\tfrom 10.89.0.39 lookup 200\n" +
		strconv.Itoa(ExternalRouteDNSPriority) + ":\tfrom all to " + testDNS + " ipproto udp dport 53 lookup 200\n" +
		strconv.Itoa(ExternalRouteDNSPriority+1) + ":\tfrom all to " + testDNS + " ipproto tcp dport 53 lookup 200\n" +
		"32766:\tfrom all lookup main\n"
	r.answers["ip route get "+testDNS+" ipproto udp dport 53"] = testDNS + " dev wg0 table 200 src 10.8.0.12 uid 0 \n"
	r.answers["ip route get "+testDNS+" ipproto tcp dport 53"] = testDNS + " dev wg0 table 200 src 10.8.0.12 uid 0 \n"
	r.answers["ip route get "+testDNS] = testDNS + " via 65.109.66.65 dev enp41s0 src 65.109.66.88 uid 0 \n"
	r.answers["cat "+aardvarkConfigDir+"/"+testNetwork] = "10.89.0.1 " + testDNS + "\n"
	r.answers[testPodmanPath+" run --rm --network container:"] = "AW_DNS_OK example.com\n"
	return r
}

func TestApplyTunnelDNSInstallsBothRulesBeforeMovingTheUpstream(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{testDNS})
	r := readyHost(testDNS)

	if !applyTunnelDNS(context.Background(), r, *plan, nil) {
		t.Fatalf("apply reported DNS not tunnelled on a host where every proof holds: %v", r.calls)
	}

	// TCP IS NOT OPTIONAL. A response over 512 bytes without EDNS retries over
	// TCP, so a udp-only rule leaks exactly those queries — a PARTIAL leak
	// that looks like success from every surface, which is the false
	// reassurance externalguarantees.go exists to prevent.
	udp := "ip rule add to " + testDNS + "/32 ipproto udp dport 53 lookup 200 priority " + strconv.Itoa(ExternalRouteDNSPriority)
	tcp := "ip rule add to " + testDNS + "/32 ipproto tcp dport 53 lookup 200 priority " + strconv.Itoa(ExternalRouteDNSPriority+1)
	if !r.ran(udp) {
		t.Fatalf("the udp rule was never installed: %v", r.calls)
	}
	if !r.ran(tcp) {
		t.Fatalf("the tcp rule was never installed — >512-byte responses would leave in the clear: %v", r.calls)
	}

	// NOTHING goes into the main table. The withdrawn version's `<dns>/32 via
	// <tunnel>` is what routed this host's own egress probe into the tunnel;
	// reinstating one "for reachability" would bring that bug straight back,
	// and the rule already reaches the resolver through table 200's own
	// default (which tableDefault refuses to leave empty).
	for _, c := range r.calls {
		if strings.HasPrefix(c, "ip route add "+testDNS) {
			t.Fatalf("a main-table route to the resolver was installed — that is the withdrawn mechanism: %v", r.calls)
		}
	}

	// THE ORDERING IS THE POINT (§10). aardvark forwards from the HOST netns,
	// so an upstream added before the rules exist is an upstream whose queries
	// take the main path for as long as the window lasts.
	ruleAt, updateAt := -1, -1
	for i, c := range r.calls {
		if ruleAt < 0 && strings.HasPrefix(c, "ip rule add to "+testDNS) {
			ruleAt = i
		}
		if updateAt < 0 && strings.HasPrefix(c, testPodmanPath+" network update") {
			updateAt = i
		}
	}
	if ruleAt < 0 || updateAt < 0 {
		t.Fatalf("rule=%d update=%d: %v", ruleAt, updateAt, r.calls)
	}
	if ruleAt > updateAt {
		t.Fatalf("the upstream was moved BEFORE the rules that tunnel it existed: %v", r.calls)
	}
}

// THE CASE THE ONLY REAL PROFILE ON THIS DEPLOYMENT HITS — and the test that
// commit 7210497's refusal used to own.
//
// gl-inet, the one configured profile, carries DNS = 1.1.1.1, which is also
// egressEndpoints[0]: the IP literal PublicIP tries FIRST to measure this
// host's own address. The withdrawn main-table /32 routed that probe into the
// tunnel and made every connect revert itself, so the DNS half refused — and
// the feature was inert for 100% of configured profiles.
//
// It is no longer refused, because the collision is between FLOWS and not
// addresses: the rule captures dport 53, the probe is an HTTPS round trip on
// 443. Both halves of that are asserted here, and neither is optional.
func TestAResolverThatIsAlsoTheHostEgressProbeIsTunnelledWithBothProofs(t *testing.T) {
	const collidingDNS = "1.1.1.1"
	if !isHostEgressProbeAddress(collidingDNS) {
		t.Fatal("1.1.1.1 is egressEndpoints[0] and must still be recognised as such — the guard is not deleted, its role changed")
	}
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{collidingDNS})
	if len(plan.DNSServers) != 1 || plan.DNSServers[0] != collidingDNS {
		t.Fatalf("the DNS half must now be PLANNED for the only profile that exists: %v", plan.DNSServers)
	}

	r := readyHost(collidingDNS)
	var narration []string
	if !applyTunnelDNS(context.Background(), r, *plan, collectProgress(&narration)) {
		t.Fatalf("dns_tunneled=false for the only configured profile — the feature is inert again: %v", r.calls)
	}

	// PROOF 1: the DNS flows moved, both transports.
	for _, proto := range []string{"udp", "tcp"} {
		if !r.ran("ip route get " + collidingDNS + " ipproto " + proto + " dport 53") {
			t.Fatalf("the %s DNS flow was never proven to have moved: %v", proto, r.calls)
		}
	}
	// PROOF 2: the probe flow did not. The UNSELECTED lookup is what
	// hostPublicIP's 443 round trip performs, and asserting it positively is
	// the reason this design may claim what the withdrawn one could not.
	if !ranExactly(r.calls, "ip route get "+collidingDNS) {
		t.Fatalf("the unselected lookup — the host's own egress probe — was never checked: %v", r.calls)
	}
	// And it is NAMED in the narration, so an operator does not have to infer
	// from silence that the probe is deliberately still in the clear.
	if !strings.Contains(strings.Join(narration, "\n"), dnsProbeCollisionNotice) {
		t.Fatalf("the resolver/probe collision was handled but never named: %v", narration)
	}
}

// ranExactly is `ran` without the prefix semantics — needed because
// `ip route get 1.1.1.1` is a prefix of the selected lookups, and this
// assertion is specifically about the UNSELECTED one having been made.
func ranExactly(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// REMOVING PROOF 2 MUST MAKE THIS TEST FAIL. That is the bar QA held the old
// refusal to (it mutation-tested the guard), and it is the bar the replacement
// has to hold.
//
// The failure being modelled: something has put the WHOLE address into the
// tunnel — a reinstated main-table /32 is the obvious way, and is exactly what
// §11.10 tells the next reader not to add "for reachability". The dport-53
// rules still prove out perfectly, so proof 1 alone cannot see it. Left
// standing, confirmExternal would read the tunnel's address as this machine's
// and revert the whole route on every connect.
func TestTheProbeFlowLeavingByTheTunnelBacksTheDNSHalfOut(t *testing.T) {
	const collidingDNS = "1.1.1.1"
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{collidingDNS})
	r := readyHost(collidingDNS)
	// The unselected lookup now reports the TUNNEL: everything to this address
	// is diverted, not just its DNS.
	r.answers["ip route get "+collidingDNS] = collidingDNS + " dev " + testTunnelDev + " table 200 src 10.8.0.12 uid 0 \n"

	if applyTunnelDNS(context.Background(), r, *plan, nil) {
		t.Fatal("dns_tunneled=true while this host's own egress probe to that address is inside the tunnel — confirmExternal would then read the tunnel's IP as the machine's and revert the entire route")
	}
	// The upstream must not have been moved on the strength of a proof that
	// failed...
	if r.ran(testPodmanPath + " network update " + testNetwork + " --dns-add") {
		t.Fatalf("the upstream was moved despite proof 2 failing: %v", r.calls)
	}
	// ...and the rules it did install must be gone again, spelled the same way
	// they were added.
	if !r.ran("ip rule del to " + collidingDNS + "/32 ipproto") {
		t.Fatalf("no DNS rule was deleted on the way out: %v", r.calls)
	}
	if len(r.rules) != 0 {
		t.Fatalf("rules survived the back-out, pointing into a tunnel this apply abandoned: %v", r.rules)
	}
}

// QA's residual finding on the withdrawn design, and it costs almost nothing
// now: a profile with TWO resolvers where only one collides with the host's
// egress probe. With per-resolver rules there is no special case at all —
// each resolver gets its own band and its own pair of proofs.
func TestTwoResolversEachGetTheirOwnRulesAndTheirOwnProofs(t *testing.T) {
	const colliding, plain = "1.1.1.1", "9.9.9.9"
	if !isHostEgressProbeAddress(colliding) || isHostEgressProbeAddress(plain) {
		t.Fatal("this test needs exactly one of the two to be an egress probe address")
	}
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{colliding, plain})
	r := readyHost(colliding, plain)

	if !applyTunnelDNS(context.Background(), r, *plan, nil) {
		t.Fatalf("a two-resolver profile did not tunnel: %v", r.calls)
	}

	// Four rules, four distinct priorities in one contiguous band, resolver
	// order preserved. Two resolvers sharing a priority would mean the second
	// `ip rule del` removes the first's rule and leaves the second's behind.
	want := map[int]string{
		ExternalRouteDNSPriority:     colliding + " udp",
		ExternalRouteDNSPriority + 1: colliding + " tcp",
		ExternalRouteDNSPriority + 2: plain + " udp",
		ExternalRouteDNSPriority + 3: plain + " tcp",
	}
	for pri, what := range want {
		f := strings.Fields(what)
		add := "ip rule add to " + f[0] + "/32 ipproto " + f[1] + " dport 53 lookup 200 priority " + strconv.Itoa(pri)
		if !r.ran(add) {
			t.Fatalf("missing rule %q: %v", add, r.calls)
		}
	}
	if len(r.rules) != 4 {
		t.Fatalf("expected four live rules, got %d: %v", len(r.rules), r.rules)
	}
	// Both resolvers were proven, both ways, independently.
	for _, dns := range []string{colliding, plain} {
		for _, proto := range []string{"udp", "tcp"} {
			if !r.ran("ip route get " + dns + " ipproto " + proto + " dport 53") {
				t.Fatalf("%s/%s was never proven: %v", dns, proto, r.calls)
			}
		}
		if !ranExactly(r.calls, "ip route get "+dns) {
			t.Fatalf("the unselected lookup for %s was never made: %v", dns, r.calls)
		}
	}
}

// §11.4 proof 1's teeth. `ip rule add` can exit 0 while something else still
// owns the flow, so what is asserted is the KERNEL's answer to "which device
// would this leave by".
//
// This is the case the design names explicitly: a resolver still REACHABLE
// over the main default is one §4.5's end-to-end check would happily pass on,
// while every query left this machine in the clear. Claiming that as tunnelled
// DNS is the exact false reassurance externalguarantees.go exists to prevent.
func TestResolverStillReachedOffTunnelOnDNSPortDoesNotFlipTheFlag(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	const publicDNS = "9.9.9.9"
	plan := planDNSOn(t, podmanHost(), []string{publicDNS})
	r := readyHost(publicDNS)
	// The rule was added and did NOT win: the kernel still sends even the
	// dport-53 flow out the host's own uplink. Meanwhile the probe resolves
	// perfectly — which is precisely why the flow has to be proven separately
	// from the path.
	r.answers["ip route get "+publicDNS+" ipproto udp dport 53"] = publicDNS + " via 65.109.66.65 dev " + testMainDev + " src 65.109.66.88 uid 0 \n"

	if applyTunnelDNS(context.Background(), r, *plan, nil) {
		t.Fatal("dns_tunneled=true for a resolver the host still reaches over its OWN default — the queries leave in the clear, and reporting that as tunnelled is worse than reporting the leak")
	}
	if r.ran(testPodmanPath + " network update " + testNetwork + " --dns-add") {
		t.Fatalf("the upstream was moved despite the flow proof failing: %v", r.calls)
	}
	// And it cleaned up after itself: no orphan rule pointing into a tunnel.
	if len(r.rules) != 0 {
		t.Fatalf("rules were left behind: %v", r.rules)
	}
}

// Each APPLY-time proof, failing on its own, must undo the DNS half
// completely — resolver dropped, rules removed — and report false.
func TestEachApplyTimeProofFailingBacksTheDNSHalfOut(t *testing.T) {
	cases := []struct {
		name    string
		break_  func(r *applyingRunner)
		wantOut bool // whether the upstream landed and so must be dropped again
	}{
		{
			name: "§11.4 proof 1 the rule cannot be installed",
			break_: func(r *applyingRunner) {
				r.errs = map[string]error{"ip rule add to " + testDNS: fmt.Errorf("Error: argument \"dport\" is wrong")}
			},
		},
		{
			name: "§11.4 proof 1 the DNS flow did not move",
			break_: func(r *applyingRunner) {
				r.answers["ip route get "+testDNS+" ipproto tcp dport 53"] = testDNS + " via 65.109.66.65 dev " + testMainDev + " \n"
			},
		},
		{
			name: "§11.4 proof 2 the probe flow moved too",
			break_: func(r *applyingRunner) {
				r.answers["ip route get "+testDNS] = testDNS + " dev " + testTunnelDev + " table 200 \n"
			},
		},
		{
			name: "§4.4 podman network update fails",
			break_: func(r *applyingRunner) {
				r.errs = map[string]error{testPodmanPath + " network update": fmt.Errorf("exit status 125")}
			},
		},
		{
			name: "§4.4 the update exits 0 but the aardvark config did not change",
			break_: func(r *applyingRunner) {
				r.noConfigWrite = true
			},
			wantOut: true,
		},
		{
			name: "§4.5 nothing resolves through the new upstream",
			break_: func(r *applyingRunner) {
				r.answers[testPodmanPath+" run --rm --network container:"] = "AW_DNS_FAIL\n"
			},
			wantOut: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakePodmanPath(t, testPodmanPath, nil)
			plan := planDNSOn(t, podmanHost(), []string{testDNS})
			r := readyHost(testDNS)
			tc.break_(r)

			if applyTunnelDNS(context.Background(), r, *plan, nil) {
				t.Fatalf("dns_tunneled=true despite a failed proof: %v", r.calls)
			}
			// RESOLVER OUT BEFORE RULES, on the way back too — leaving
			// aardvark pointed at an address whose path into the tunnel has
			// been withdrawn is the black hole this ordering exists to avoid.
			if tc.wantOut && !r.ran(testPodmanPath+" network update "+testNetwork+" --dns-drop "+testDNS) {
				t.Fatalf("the upstream was left in place: %v", r.calls)
			}
			dropAt, delAt := -1, -1
			for i, c := range r.calls {
				if dropAt < 0 && strings.Contains(c, "--dns-drop") {
					dropAt = i
				}
				if delAt < 0 && strings.HasPrefix(c, "ip rule del to "+testDNS) {
					delAt = i
				}
			}
			if dropAt >= 0 && delAt >= 0 && dropAt > delAt {
				t.Fatalf("the rules tunnelling the resolver were withdrawn before the resolver was: %v", r.calls)
			}
			// Nothing half-applied survives, whichever proof failed.
			if len(r.rules) != 0 {
				t.Fatalf("rules left behind: %v", r.rules)
			}
		})
	}
}

// `ip rule del` matches on the WHOLE selector. A rule added one way and
// deleted another is a rule that outlives its own revert — the same property
// TestRuleIsAlwaysASlashThirtyTwo asserts for the container rule, and the
// reason both verbs go through one function.
func TestEveryDNSRuleIsDeletedExactlyAsItWasAdded(t *testing.T) {
	plan := ExternalRoutePlan{Table: 200, DNSServers: []string{testDNS, "9.9.9.9"}, DNSPriority: ExternalRouteDNSPriority}
	for _, ru := range plan.dnsRules() {
		add := plan.dnsRuleArgs("add", ru)
		del := plan.dnsRuleArgs("del", ru)
		if len(add) != len(del) {
			t.Fatalf("add and del differ in shape:\nadd %v\ndel %v", add, del)
		}
		for i := range add {
			if i == 1 {
				continue // the verb itself
			}
			if add[i] != del[i] {
				t.Fatalf("field %d differs between add and del (%q vs %q) — the revert would not match:\nadd %v\ndel %v", i, add[i], del[i], add, del)
			}
		}
		if !containsString(add, "dport") || !containsString(add, "53") {
			t.Fatalf("the rule is not scoped to DNS — it would capture this host's own egress probe: %v", add)
		}
		if containsString(add, "onlink") || add[0] != "rule" {
			t.Fatalf("this must be a policy RULE and write nothing to any route table: %v", add)
		}
	}
}

// --- the dead-man's switch --------------------------------------------------

// THE TEST THAT RETIRES THE PREDECESSOR CARD'S OBJECTION.
//
// The aardvark-config approach was rejected because the change sat inside the
// dead-man's revert path and could not be undone by it. What podman 5 changed
// is that the undo is a CLI verb a three-line POSIX sh script can call by
// ABSOLUTE PATH — the same shape as deadman.go's `tailscale set --exit-node=`.
// If this assertion ever fails, the design is back to the one that was
// already refused once.
func TestRevertScriptCarriesTheDNSDropAndBothRuleDeletions(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{testDNS})
	script := externalRevertScript(PrivilegedRunner{Sudo: true}, *plan)

	wantDrop := "sudo -n " + testPodmanPath + " network update " + testNetwork + " --dns-drop " + testDNS
	if !strings.Contains(script, wantDrop) {
		t.Fatalf("the dead-man cannot undo the DNS change.\nwant a line: %s\ngot:\n%s", wantDrop, script)
	}
	// BOTH transports. A dead-man that removes only the udp rule leaves the
	// tcp one pointing at a table whose tunnel is gone.
	for _, spec := range []string{
		"ip rule del to " + testDNS + "/32 ipproto udp dport 53 lookup 200 priority " + strconv.Itoa(ExternalRouteDNSPriority),
		"ip rule del to " + testDNS + "/32 ipproto tcp dport 53 lookup 200 priority " + strconv.Itoa(ExternalRouteDNSPriority+1),
	} {
		if !strings.Contains(script, spec) {
			t.Fatalf("the dead-man leaves a DNS rule behind.\nwant: %s\ngot:\n%s", spec, script)
		}
	}
	// And it writes nothing to a route table, because this feature no longer
	// puts anything there.
	if strings.Contains(script, "ip route del "+testDNS) {
		t.Fatalf("the revert still carries the withdrawn main-table /32:\n%s", script)
	}
	// Absolute, because this runs on a machine whose network has just gone and
	// with whatever PATH it inherited. A bare `podman` here is the failure.
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "network update") && !strings.Contains(line, testPodmanPath) {
			t.Fatalf("the podman in the revert is not the absolute path resolved at plan time: %q", line)
		}
	}
	// RESOLVER OUT BEFORE RULES, and the DNS rules before the policy rule that
	// carries the container itself.
	dropAt := strings.Index(script, "--dns-drop")
	dnsRuleAt := strings.Index(script, "rule del to "+testDNS)
	containerRuleAt := strings.Index(script, "rule del from ")
	if !(dropAt < dnsRuleAt && dnsRuleAt < containerRuleAt) {
		t.Fatalf("the revert is in the wrong order (drop=%d dnsrule=%d containerrule=%d):\n%s", dropAt, dnsRuleAt, containerRuleAt, script)
	}
	// Every line survives its own failure: this script must never exit
	// non-zero on a machine that has just lost its default route.
	for _, line := range strings.Split(strings.TrimSpace(script), "\n") {
		if line != "" && !strings.HasSuffix(line, "|| true") {
			t.Fatalf("a revert line can abort the rest of the revert: %q", line)
		}
	}
}

// A route with no DNS half must not put a podman line in the revert at all — a
// switch that runs a command for a change nobody made is a switch that can
// fail for a reason that does not exist.
func TestRevertScriptHasNoDNSLineWhenTheDNSHalfWasNotAttempted(t *testing.T) {
	plan := planOn(t, healthyHost())
	script := externalRevertScript(PrivilegedRunner{Sudo: true}, *plan)
	if strings.Contains(script, "network update") || strings.Contains(script, "podman") {
		t.Fatalf("a route without --tunnel-dns must not reference podman:\n%s", script)
	}
	if strings.Contains(script, "dport 53") {
		t.Fatalf("a route without --tunnel-dns must not delete DNS rules it never added:\n%s", script)
	}
}

// --- reassert ---------------------------------------------------------------

// The daily unattended-apt restart flushes this host's policy rules, and
// anything that reloads the network drops the aardvark upstream. Neither
// breaks loudly: the first silently puts the queries back on the main path,
// the second silently reopens the leak. Both have to come back on the timer.
func TestReassertRestoresADroppedUpstreamAndFlushedRules(t *testing.T) {
	plan := ExternalRoutePlan{
		Container: "aw-remote-host-workspace", ContainerID: testContainer,
		SourceIP: "10.89.0.39", Table: 200, Priority: 5399, Runtime: "podman",
		TunnelVia: "10.8.0.2", TunnelDev: "wg0",
		DNSServers: []string{testDNS}, DNSNetwork: testNetwork, DNSPodmanPath: testPodmanPath,
		DNSPriority: ExternalRouteDNSPriority,
	}
	r := podmanHost()
	// The container rule itself survived; only the DNS half was taken away.
	r.answers["ip rule show"] = "5399:\tfrom 10.89.0.39 lookup 200\n"

	restored, updated, gone, err := reassertPlan(context.Background(), r, plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if gone || updated != nil {
		t.Fatalf("the container is unchanged: gone=%v updated=%v", gone, updated)
	}
	for _, proto := range []string{"udp", "tcp"} {
		pri := ExternalRouteDNSPriority
		if proto == "tcp" {
			pri++
		}
		want := "ip rule add to " + testDNS + "/32 ipproto " + proto + " dport 53 lookup 200 priority " + strconv.Itoa(pri)
		if !r.ran(want) {
			t.Fatalf("the flushed %s DNS rule was not put back: %v", proto, r.calls)
		}
	}
	// And it re-asserts a RULE, never a main-table route.
	if r.ran("ip route add " + testDNS) {
		t.Fatalf("reassert installed the withdrawn main-table /32: %v", r.calls)
	}
	if !r.ran(testPodmanPath + " network update " + testNetwork + " --dns-add " + testDNS) {
		t.Fatalf("the dropped aardvark upstream was not put back: %v", r.calls)
	}
	joined := strings.Join(restored, "; ")
	if !strings.Contains(joined, testDNS) || !strings.Contains(joined, testNetwork) {
		t.Fatalf("a silent restore is the thing this loop exists to make visible: %v", restored)
	}
}

// An upstream that is still in force is NOT re-applied. `podman network
// update` on every 30s tick would be churn on a shared network for no reason.
func TestReassertLeavesAHealthyDNSHalfAlone(t *testing.T) {
	plan := ExternalRoutePlan{
		Container: "aw-remote-host-workspace", ContainerID: testContainer,
		SourceIP: "10.89.0.39", Table: 200, Priority: 5399, Runtime: "podman",
		TunnelVia: "10.8.0.2", TunnelDev: "wg0",
		DNSServers: []string{testDNS}, DNSNetwork: testNetwork, DNSPodmanPath: testPodmanPath,
		DNSPriority: ExternalRouteDNSPriority,
	}
	r := appliedHost()

	if _, _, _, err := reassertPlan(context.Background(), r, plan); err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if r.ran(testPodmanPath + " network update") {
		t.Fatalf("a healthy upstream was re-applied: %v", r.calls)
	}
	if r.ran("ip rule add to " + testDNS) {
		t.Fatalf("an intact DNS rule was re-added: %v", r.calls)
	}
}

// A container that no longer exists takes the resolver back with it. Leaving
// 30 containers pointed at a VPN resolver on behalf of a workload that is gone
// is the same orphan the rule is, with a much wider blast radius.
func TestReassertDropsTheUpstreamWhenTheContainerIsGone(t *testing.T) {
	plan := ExternalRoutePlan{
		Container: "aw-remote-host-workspace", ContainerID: testContainer,
		SourceIP: "10.89.0.39", Table: 200, Priority: 5399, Runtime: "podman",
		TunnelVia: "10.8.0.2", TunnelDev: "wg0",
		DNSServers: []string{testDNS}, DNSNetwork: testNetwork, DNSPodmanPath: testPodmanPath,
		DNSPriority: ExternalRouteDNSPriority,
	}
	r := appliedHost()
	r.errs = map[string]error{"podman inspect -f {{.Id}}": fmt.Errorf("no such container")}

	restored, _, gone, err := reassertPlan(context.Background(), r, plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if !gone {
		t.Fatal("the container is gone and reassert did not say so")
	}
	if !r.ran(testPodmanPath + " network update " + testNetwork + " --dns-drop " + testDNS) {
		t.Fatalf("the orphaned upstream was left on a shared network: %v", r.calls)
	}
	if !r.ran("ip rule del to " + testDNS) {
		t.Fatalf("the orphaned DNS rules were left behind: %v", r.calls)
	}
	if !strings.Contains(strings.Join(restored, "; "), "orphaned DNS upstream") {
		t.Fatalf("restored: %v", restored)
	}
}

// --- status -----------------------------------------------------------------

// The counterpart to TestStatusIsHonestThatDNSIsNotFullyTunnelled: with a DNS
// half recorded AND still measurably in force, the report says so.
//
// Measured on every call rather than replayed, for the same reason the kill
// switch is: a status that replayed "dns_tunneled: true" from the record would
// be claiming a privacy guarantee that had already lapsed.
func TestStatusReportsDNSTunnelledOnlyWhenBothHalvesAreStillInForce(t *testing.T) {
	route := &state.ExternalRouteState{
		Container: "aw-remote-host-workspace", ContainerID: testContainer,
		SourceIP: "10.89.0.39", Table: 200, Priority: 5399, Runtime: "podman",
		DNSServers: []string{testDNS}, DNSNetwork: testNetwork, DNSPodmanPath: testPodmanPath,
		DNSPriority: ExternalRouteDNSPriority,
	}

	if !measuredDNSTunneled(context.Background(), appliedHost(), route) {
		t.Fatal("both halves are in force and the status says DNS is not tunnelled")
	}

	// Half one gone: the aardvark upstream was reset by a network reload. The
	// leak is silently back and only a measurement can tell.
	upstreamGone := appliedHost()
	upstreamGone.answers["cat "+aardvarkConfigDir+"/"+testNetwork] = "10.89.0.1\n"
	if measuredDNSTunneled(context.Background(), upstreamGone, route) {
		t.Fatal("the upstream is gone and the status still claims tunnelled DNS")
	}

	// Half two gone: the rules were flushed. The config file still LOOKS right
	// while every query on the network goes out in the clear.
	rulesGone := appliedHost()
	rulesGone.answers["ip rule show"] = "0:\tfrom all lookup local\n5399:\tfrom 10.89.0.39 lookup 200\n32766:\tfrom all lookup main\n"
	if measuredDNSTunneled(context.Background(), rulesGone, route) {
		t.Fatal("the DNS rules are flushed and the status still claims tunnelled DNS")
	}

	// ONLY THE TCP RULE GONE. This is the partial leak that reads as success:
	// udp queries still tunnel, anything over 512 bytes retries over tcp and
	// leaves in the clear. A status that rounded this up to `true` would be
	// making exactly the privacy claim it cannot support.
	tcpGone := appliedHost()
	tcpGone.answers["ip rule show"] = "0:\tfrom all lookup local\n" +
		strconv.Itoa(ExternalRouteDNSPriority) + ":\tfrom all to " + testDNS + " ipproto udp dport 53 lookup 200\n" +
		"32766:\tfrom all lookup main\n"
	if measuredDNSTunneled(context.Background(), tcpGone, route) {
		t.Fatal("only the udp rule survives — TCP fallbacks leave in the clear, and this reports full tunnelled DNS")
	}

	// And a route recorded with no DNS half at all is simply false.
	if measuredDNSTunneled(context.Background(), appliedHost(), &state.ExternalRouteState{Container: "x"}) {
		t.Fatal("a route applied without --tunnel-dns must report false")
	}
}

// --- the aardvark config parser ---------------------------------------------

// §10: the upstream list is the FIRST LINE, sharing it with the bind address,
// and podman writes multiple upstreams COMMA-separated (measured 2026-09-08:
// `10.89.1.1 9.9.9.9,149.112.112.112`). A grep over the whole file would match
// a container's own A record further down and report success for a change that
// never landed.
func TestAardvarkUpstreamsReadsLineOneAndSplitsOnCommas(t *testing.T) {
	cfg := "10.89.0.1 9.9.9.9,149.112.112.112\n" +
		"aw-app-kb 10.89.0.7 \n" +
		"some-container 10.9.9.9 \n" // the trap: line 3 holds the address being asserted on

	r := &tableRunner{answers: map[string]string{"cat " + aardvarkConfigDir + "/" + testNetwork: cfg}}
	got := aardvarkUpstreams(context.Background(), r, testNetwork)
	if len(got) != 2 || got[0] != "9.9.9.9" || got[1] != "149.112.112.112" {
		t.Fatalf("upstreams: %v", got)
	}
	if containsAddress(got, "10.9.9.9") {
		t.Fatal("an address from a RECORD line below was read as an upstream — that is the position-sensitivity §10 warns about")
	}
	if addr := aardvarkBindAddress(context.Background(), r, testNetwork); addr != "10.89.0.1" {
		t.Fatalf("bind address: %q", addr)
	}

	// This host's measured state today: a bare first line, no upstream at all.
	bare := &tableRunner{answers: map[string]string{"cat " + aardvarkConfigDir + "/" + testNetwork: "10.89.0.1\n"}}
	if got := aardvarkUpstreams(context.Background(), bare, testNetwork); len(got) != 0 {
		t.Fatalf("a bare first line means no upstream: %v", got)
	}
	// An unreadable file is "no upstreams", never an error: this is called on
	// the reassert timer and must not turn a fresh host into a log of failures.
	if got := aardvarkUpstreams(context.Background(), &tableRunner{errs: map[string]error{"cat": fmt.Errorf("no such file")}}, testNetwork); got != nil {
		t.Fatalf("unreadable config: %v", got)
	}
}
