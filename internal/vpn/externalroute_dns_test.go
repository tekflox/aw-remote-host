package vpn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// Gate 2 of the DNS-tunnelling design: plan, apply, revert, the revert SCRIPT
// and each §4 refusal, all against a fake runner — no podman, no network, no
// host.
//
// The bias throughout is that a FAILED proof must be indistinguishable from
// never having tried: no route left behind, no upstream left behind,
// DNSTunneled false and DNSNotTunnelledWarning present. That asymmetry is the
// whole safety case — the failure this feature can cause (30 containers with
// no external DNS) is worse than the leak it closes, so every path out of a
// half-applied state is tested here rather than discovered on the host.

const (
	testDNS        = "10.9.9.9"
	testPodmanPath = "/usr/bin/podman"
	testNetwork    = "aw-remote-host"
	testContainer  = "5584662f4f57"
)

// podmanHost is healthyHost's shape with podman as the runtime and a container
// on one network, which is what this deployment actually looks like — measured
// 2026-09-08: aw-remote-host-workspace at 10.89.0.39 on network aw-remote-host
// (podman1, 10.89.0.0/24), aardvark bound to 10.89.0.1 with a BARE first line.
func podmanHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"ip -V":                                        "ip utility, iproute2-6.1.0",
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
// an `ip route add` makes the matching `ip route show` start answering, and a
// `--dns-add` rewrites the aardvark config's first line.
//
// A static fixture cannot express this, and the difference is not cosmetic —
// it is the whole revert path. Every undo here is check-then-delete, so a
// fixture where the add left no trace would let a revert "pass" by skipping
// the delete it was supposed to make, which is precisely the orphaned /32 into
// a disappearing tunnel that this test file is about. Reality was measured on
// the host 2026-09-08; this is that behaviour, not a convenience.
type applyingRunner struct {
	*tableRunner
	dns     string
	network string
	via     string
	dev     string
	// noConfigWrite reproduces the §4.4 case that the read-back exists for: a
	// `podman network update` that exits 0 while the aardvark config is
	// unchanged. Without a switch for it the read-back could only ever be
	// tested against a runner that also faked the failure of the command.
	noConfigWrite bool
}

func newApplyingRunner(base *tableRunner, dns string) *applyingRunner {
	return &applyingRunner{tableRunner: base, dns: dns, network: testNetwork, via: "10.8.0.2", dev: "wg0"}
}

func (a *applyingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := a.tableRunner.Run(ctx, name, args...)
	if err != nil {
		return out, err
	}
	full := strings.TrimSpace(name + " " + strings.Join(args, " "))
	cfg := "cat " + aardvarkConfigDir + "/" + a.network
	switch {
	case strings.HasPrefix(full, "ip route add "+a.dns+"/32"):
		a.answers["ip route show "+a.dns+"/32"] = a.dns + " via " + a.via + " dev " + a.dev + " onlink \n"
	case strings.HasPrefix(full, "ip route del "+a.dns+"/32"):
		delete(a.answers, "ip route show "+a.dns+"/32")
	case strings.Contains(full, "network update") && strings.Contains(full, "--dns-add "+a.dns):
		if !a.noConfigWrite {
			a.answers[cfg] = "10.89.0.1 " + a.dns + "\n"
		}
	case strings.Contains(full, "network update") && strings.Contains(full, "--dns-drop "+a.dns):
		a.answers[cfg] = "10.89.0.1\n"
	}
	return out, err
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
	// A PLAN has applied nothing, so it may not claim the resolver moved.
	if plan.DNSTunneled {
		t.Fatal("dns_tunneled=true on a plan — nothing has been applied, so this would be a claim about a change that has not happened")
	}
}

// Each §4 plan-time precondition, failing on its own, has to leave the DNS
// half entirely unresolved — and leave the ROUTE alone. A route that failed
// because DNS could not be tunnelled would regress behaviour that has shipped.
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
			if r.ran("podman network update") || r.ran("ip route add") {
				t.Fatalf("plan mutated the machine (%s): %v", tc.why, r.calls)
			}
		})
	}
}

// THE CASE THE ONLY REAL PROFILE ON THIS DEPLOYMENT HITS.
//
// gl-inet, the one configured profile, carries DNS = 1.1.1.1 — which is also
// egressEndpoints[0], the IP literal PublicIP tries FIRST to measure this
// host's own address. Installing the main-table /32 for it would route the
// confirmation probe into the tunnel, confirmExternal would read the tunnel's
// address as the machine's, and the whole route would revert with "THIS
// MACHINE'S OWN EGRESS MOVED" — on every single connect.
//
// The design assumed a private resolver here and said to verify that rather
// than assume it. It does not hold, so the DNS half refuses and the route is
// untouched. If this test ever fails, connecting the VPN is broken outright,
// which is a much worse bug than the leak this feature closes.
func TestAResolverThatIsAlsoTheHostEgressProbeIsRefused(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan, err := PlanExternalRoute(context.Background(), ExternalRouteSpec{
		Container: "aw-remote-host-workspace",
		Runner:    podmanHost(),
		Runtime:   ContainerRuntime{Name: "podman"},
		TunnelDNS: true,
		DNS:       []string{"1.1.1.1"},
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Refusal != "" {
		t.Fatalf("the ROUTE must still work — only the DNS half backs off: %s", plan.Refusal)
	}
	if len(plan.DNSServers) != 0 {
		t.Fatalf("a /32 for %v would route this host's OWN egress probe into the tunnel and make every connect revert itself", plan.DNSServers)
	}
	if !containsString(plan.Warnings, DNSNotTunnelledWarning) {
		t.Fatalf("warnings: %v", plan.Warnings)
	}
	if !isHostEgressProbeAddress("1.1.1.1") {
		t.Fatal("1.1.1.1 is egressEndpoints[0] and must be recognised as such")
	}
	// A resolver that is NOT a probe endpoint is unaffected — the guard has to
	// be this collision and not "public resolvers are refused".
	if isHostEgressProbeAddress("9.9.9.9") {
		t.Fatal("the guard is too wide: it must catch the probe collision, not every public resolver")
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

// --- §4.3 / §4.4 / §4.5, apply time -----------------------------------------

// readyHost is a machine on which every proof WILL hold: nothing applied yet,
// plus the two answers an applyingRunner cannot synthesise because they are
// facts about the tunnel rather than echoes of a command — what the kernel
// says the resolver's route is, and what the probe in the container's
// namespace resolves.
func readyHost(dns string) *applyingRunner {
	r := podmanHost()
	r.answers["ip route get "+dns] = dns + " via 10.8.0.2 dev wg0 src 10.8.0.12 uid 0 \n    cache \n"
	r.answers[testPodmanPath+" run --rm --network container:"] = "AW_DNS_OK example.com\n"
	return newApplyingRunner(r, dns)
}

// appliedHost is podmanHost with both writes ALREADY in place — the state a
// reassert pass or a status poll finds on a healthy machine, where nothing is
// being written and so nothing has to react.
func appliedHost() *tableRunner {
	r := podmanHost()
	r.answers["ip route show "+testDNS+"/32"] = testDNS + " via 10.8.0.2 dev wg0 onlink \n"
	r.answers["ip route get "+testDNS] = testDNS + " via 10.8.0.2 dev wg0 src 10.8.0.12 uid 0 \n    cache \n"
	r.answers["cat "+aardvarkConfigDir+"/"+testNetwork] = "10.89.0.1 " + testDNS + "\n"
	r.answers[testPodmanPath+" run --rm --network container:"] = "AW_DNS_OK example.com\n"
	return r
}

func TestApplyTunnelDNSInstallsTheMainTableRouteBeforeMovingTheUpstream(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{testDNS})
	r := readyHost(testDNS)

	if !applyTunnelDNS(context.Background(), r, *plan, nil) {
		t.Fatalf("apply reported DNS not tunnelled on a host where every proof holds: %v", r.calls)
	}

	// THE ORDERING IS THE POINT (§10). aardvark forwards from the HOST netns
	// using the MAIN table, so an upstream added before the /32 exists is an
	// upstream this host cannot reach — and every container on the network
	// loses external DNS, which is strictly worse than the leak.
	routeAt, updateAt := -1, -1
	for i, c := range r.calls {
		if routeAt < 0 && strings.HasPrefix(c, "ip route add "+testDNS+"/32") {
			routeAt = i
		}
		if updateAt < 0 && strings.HasPrefix(c, testPodmanPath+" network update") {
			updateAt = i
		}
	}
	if routeAt < 0 {
		t.Fatalf("the main-table /32 was never installed: %v", r.calls)
	}
	if updateAt < 0 {
		t.Fatalf("the upstream was never moved: %v", r.calls)
	}
	if routeAt > updateAt {
		t.Fatalf("the upstream was moved BEFORE the route to it existed — that black-holes DNS for every container on the network: %v", r.calls)
	}
	// onlink, for the measured reason excludeArgs carries it: a wg device with
	// a /32 address has no connected subnet holding the tunnel gateway, and
	// without onlink the kernel refuses the route outright.
	if !r.ran("ip route add " + testDNS + "/32 via 10.8.0.2 dev wg0 onlink") {
		t.Fatalf("the /32 was not spelled with onlink: %v", r.calls)
	}
}

// §4.3's real teeth. The route command can exit 0 while something else still
// owns the destination, so what is asserted is the KERNEL's answer to "which
// device would this leave by".
//
// This is the case the design names explicitly: a profile whose resolver is a
// PUBLIC one is still REACHABLE over the main default, so §4.5's end-to-end
// check would happily pass while every query left this machine in the clear.
// Claiming that as tunnelled DNS is the exact false reassurance
// externalguarantees.go exists to prevent.
func TestPublicResolverStillReachableOffTunnelDoesNotFlipTheFlag(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	// 9.9.9.9 rather than 1.1.1.1: a PUBLIC resolver, but not one of this
	// host's own egress probe endpoints, so the collision guard does not fire
	// and this test stays about the thing it is named for — the route proof.
	// The 1.1.1.1 case is TestAResolverThatIsAlsoTheHostEgressProbeIsRefused.
	const publicDNS = "9.9.9.9"
	plan := planDNSOn(t, podmanHost(), []string{publicDNS})
	r := readyHost(publicDNS)
	// The /32 was added and did NOT win: the kernel still sends this out the
	// host's own uplink. Meanwhile the probe resolves perfectly — which is
	// precisely why the route has to be proven separately from the path.
	r.answers["ip route get "+publicDNS] = publicDNS + " via 65.109.66.65 dev enp41s0 src 65.109.66.88 uid 0 \n"

	if applyTunnelDNS(context.Background(), r, *plan, nil) {
		t.Fatal("dns_tunneled=true for a resolver the host reaches over its OWN default — the queries leave in the clear, and reporting that as tunnelled is worse than reporting the leak")
	}
	if r.ran(testPodmanPath + " network update " + testNetwork + " --dns-add") {
		t.Fatalf("the upstream was moved despite the route proof failing: %v", r.calls)
	}
	// And it cleaned up after itself: no orphan /32 pointing into a tunnel.
	if !r.ran("ip route del " + publicDNS + "/32") {
		t.Fatalf("the main-table /32 was left behind: %v", r.calls)
	}
}

// Each APPLY-time proof, failing on its own, must undo the DNS half
// completely — resolver dropped, route removed — and report false.
func TestEachApplyTimeProofFailingBacksTheDNSHalfOut(t *testing.T) {
	cases := []struct {
		name    string
		break_  func(r *applyingRunner)
		wantOut bool // whether the upstream landed and so must be dropped again
	}{
		{
			name: "§4.3 the main-table route cannot be installed",
			break_: func(r *applyingRunner) {
				r.errs = map[string]error{"ip route add " + testDNS: fmt.Errorf("Error: Nexthop has invalid gateway")}
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
			// RESOLVER OUT BEFORE ROUTE, on the way back too — leaving
			// aardvark pointed at an address whose route has been withdrawn is
			// the black hole this whole ordering exists to avoid.
			if tc.wantOut && !r.ran(testPodmanPath+" network update "+testNetwork+" --dns-drop "+testDNS) {
				t.Fatalf("the upstream was left in place: %v", r.calls)
			}
			dropAt, delAt := -1, -1
			for i, c := range r.calls {
				if dropAt < 0 && strings.Contains(c, "--dns-drop") {
					dropAt = i
				}
				if delAt < 0 && strings.HasPrefix(c, "ip route del "+testDNS) {
					delAt = i
				}
			}
			if dropAt >= 0 && delAt >= 0 && dropAt > delAt {
				t.Fatalf("the route to the resolver was withdrawn before the resolver was: %v", r.calls)
			}
		})
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
func TestRevertScriptCarriesTheDNSDropWithAnAbsolutePodmanPath(t *testing.T) {
	withFakePodmanPath(t, testPodmanPath, nil)
	plan := planDNSOn(t, podmanHost(), []string{testDNS})
	script := externalRevertScript(PrivilegedRunner{Sudo: true}, *plan)

	wantDrop := "sudo -n " + testPodmanPath + " network update " + testNetwork + " --dns-drop " + testDNS
	if !strings.Contains(script, wantDrop) {
		t.Fatalf("the dead-man cannot undo the DNS change.\nwant a line: %s\ngot:\n%s", wantDrop, script)
	}
	if !strings.Contains(script, "ip route del "+testDNS+"/32") {
		t.Fatalf("the dead-man leaves the main-table /32 behind:\n%s", script)
	}
	// Absolute, because this runs on a machine whose network has just gone and
	// with whatever PATH it inherited. A bare `podman` here is the failure.
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "network update") && !strings.Contains(line, testPodmanPath) {
			t.Fatalf("the podman in the revert is not the absolute path resolved at plan time: %q", line)
		}
	}
	// RESOLVER OUT BEFORE ROUTE, and both before the policy rule.
	dropAt := strings.Index(script, "--dns-drop")
	routeDelAt := strings.Index(script, "ip route del "+testDNS)
	ruleDelAt := strings.Index(script, "rule del")
	if !(dropAt < routeDelAt && routeDelAt < ruleDelAt) {
		t.Fatalf("the revert is in the wrong order (drop=%d routedel=%d ruledel=%d):\n%s", dropAt, routeDelAt, ruleDelAt, script)
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
}

// --- reassert ---------------------------------------------------------------

// The daily unattended-apt restart of systemd-networkd flushes the main-table
// /32, and anything that reloads the network drops the aardvark upstream.
// Neither breaks loudly: the first black-holes the resolver, the second
// silently reopens the leak. Both have to come back on the timer.
func TestReassertRestoresADroppedUpstreamAndAFlushedRoute(t *testing.T) {
	plan := ExternalRoutePlan{
		Container: "aw-remote-host-workspace", ContainerID: testContainer,
		SourceIP: "10.89.0.39", Table: 200, Priority: 5399, Runtime: "podman",
		TunnelVia: "10.8.0.2", TunnelDev: "wg0",
		DNSServers: []string{testDNS}, DNSNetwork: testNetwork, DNSPodmanPath: testPodmanPath,
	}
	r := podmanHost()
	// The rule itself survived; only the DNS half was taken away.
	r.answers["ip rule show"] = "5399:\tfrom 10.89.0.39 lookup 200\n"

	restored, updated, gone, err := reassertPlan(context.Background(), r, plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if gone || updated != nil {
		t.Fatalf("the container is unchanged: gone=%v updated=%v", gone, updated)
	}
	if !r.ran("ip route add " + testDNS + "/32 via 10.8.0.2 dev wg0 onlink") {
		t.Fatalf("the flushed main-table route to the resolver was not put back: %v", r.calls)
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
	}
	r := appliedHost()
	r.answers["ip rule show"] = "5399:\tfrom 10.89.0.39 lookup 200\n"

	if _, _, _, err := reassertPlan(context.Background(), r, plan); err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if r.ran(testPodmanPath + " network update") {
		t.Fatalf("a healthy upstream was re-applied: %v", r.calls)
	}
	if r.ran("ip route add " + testDNS) {
		t.Fatalf("an intact route was re-added: %v", r.calls)
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

	// Half two gone: systemd-networkd flushed the main-table /32. This is the
	// more dangerous one — the config file still LOOKS right while every
	// container on the network has lost external DNS.
	routeGone := appliedHost()
	delete(routeGone.answers, "ip route show "+testDNS+"/32")
	if measuredDNSTunneled(context.Background(), routeGone, route) {
		t.Fatal("the route to the resolver is flushed and the status still claims tunnelled DNS")
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
