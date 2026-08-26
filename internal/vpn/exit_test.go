package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// recordingRunner records every command and answers from a scripted table,
// so the exclusion logic is exercised without an `ip` binary or a kernel.
type recordingRunner struct {
	calls []string
	// answers maps a joined command line to what it should return. A command
	// with no entry succeeds with empty output.
	answers map[string]struct {
		out string
		err error
	}
}

func newRecordingRunner() *recordingRunner {
	return &recordingRunner{answers: map[string]struct {
		out string
		err error
	}{}}
}

func (r *recordingRunner) answer(cmd, out string, err error) {
	r.answers[cmd] = struct {
		out string
		err error
	}{out, err}
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, line)
	if a, ok := r.answers[line]; ok {
		return a.out, a.err
	}
	return "", nil
}

// noRule is what the kernel actually answers once the last rule at a priority
// is gone. ClearExclusions treats it as the loop's exit condition, not an
// error, and getting that wrong would make every cleanup "fail".
const noRule = "RTNETLINK answers: No such file or directory"

func staticResolver(ips ...string) Resolver {
	return func(string) ([]string, error) { return ips, nil }
}

// The one exclusion that is not negotiable. If the control plane cannot be
// pinned outside the tunnel there is no safe way to continue, because losing
// the mesh would then also mean losing the only way to be told to stop.
func TestPlanExclusionsRefusesWithoutTheControlPlane(t *testing.T) {
	_, err := PlanExclusions("https://api.aw.tekflox.com", nil, nil, func(string) ([]string, error) {
		return nil, errors.New("no such host")
	})
	if err == nil {
		t.Fatal("a control plane that cannot be resolved must stop the whole operation, not be skipped")
	}
	if !strings.Contains(err.Error(), "refusing to move the default route") {
		t.Fatalf("the refusal has to say what it refused to do, got %q", err)
	}

	if _, err := PlanExclusions("https://api.aw.tekflox.com", nil, nil, staticResolver()); err == nil {
		t.Fatal("resolving to zero IPv4 addresses is the same situation as failing to resolve")
	}
}

func TestPlanExclusionsPinsControlPlaneFirst(t *testing.T) {
	locals := []LocalPrefix{
		{Iface: "podman1", Prefix: "10.89.0.0/24"},
		{Iface: "eth0", Prefix: "192.168.1.0/24"},
	}
	plan, err := PlanExclusions("https://api.aw.tekflox.com", locals, nil, staticResolver("65.109.66.88"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.ControlPlaneHost != "api.aw.tekflox.com" {
		t.Fatalf("host = %q", plan.ControlPlaneHost)
	}
	if len(plan.Exclusions) != 3 {
		t.Fatalf("exclusions = %+v", plan.Exclusions)
	}
	// First, and said out loud: this ordering is what a human reads off
	// --plan when deciding whether it is safe to run.
	if plan.Exclusions[0].Prefix != "65.109.66.88/32" {
		t.Fatalf("the control plane must be the first exclusion, got %+v", plan.Exclusions)
	}
	// RE-DERIVED under container-scoped routing rather than inherited: the
	// host's route no longer moves, so this is no longer the anti-lockout pin.
	// It is here because a CONTAINER's traffic to the control plane would
	// otherwise leave through the gate, and the reason has to say so — a
	// justification that no longer holds is how an exclusion set outlives the
	// model it was built for.
	if !strings.Contains(plan.Exclusions[0].Reason, "this host's own path rather than through the gate") {
		t.Fatalf("reason = %q", plan.Exclusions[0].Reason)
	}
	for _, e := range plan.Exclusions[1:] {
		if !strings.Contains(e.Reason, "container-to-LAN") {
			t.Fatalf("an attached-network exclusion must justify itself as container traffic, got %q", e.Reason)
		}
	}
	// The podman subnet and the LAN prefix, the two the card names
	// explicitly (internal/lanfastpath depends on the second).
	for _, want := range []string{"10.89.0.0/24", "192.168.1.0/24"} {
		if !hasPrefix(plan, want) {
			t.Fatalf("%s missing from %+v", want, plan.Exclusions)
		}
	}
}

func TestPlanExclusionsAcceptsABareControlPlaneAddress(t *testing.T) {
	// A control plane given as an IP must not go through DNS at all — on a
	// machine whose resolver is about to be in question, that would be a
	// dependency this step cannot afford.
	plan, err := PlanExclusions("https://65.109.66.88:8443", nil, nil, func(string) ([]string, error) {
		t.Fatal("an IP literal must not be resolved")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Exclusions[0].Prefix != "65.109.66.88/32" {
		t.Fatalf("got %+v", plan.Exclusions)
	}
}

func TestPlanExclusionsNormalisesAndDeduplicatesExtras(t *testing.T) {
	locals := []LocalPrefix{{Iface: "eth0", Prefix: "192.168.1.0/24"}}
	plan, err := PlanExclusions("api.aw.tekflox.com", locals, []string{" 10.0.0.5 ", "192.168.1.0/24", "172.16.4.0/22", ""}, staticResolver("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrefix(plan, "10.0.0.5/32") {
		t.Fatalf("a bare address must become a /32, got %+v", plan.Exclusions)
	}
	if !hasPrefix(plan, "172.16.4.0/22") {
		t.Fatalf("got %+v", plan.Exclusions)
	}
	// A duplicate of an attached network must not produce two identical ip
	// rules — the second would survive the first delete and become a
	// leftover, which is the failure mode this whole feature is built around.
	count := 0
	for _, e := range plan.Exclusions {
		if e.Prefix == "192.168.1.0/24" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("192.168.1.0/24 appears %d times: %+v", count, plan.Exclusions)
	}
}

func TestPlanExclusionsRejectsGarbageExtras(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "2001:db8::/32", "10.0.0.0/99"} {
		if _, err := PlanExclusions("api.aw.tekflox.com", nil, []string{bad}, staticResolver("1.2.3.4")); err == nil {
			t.Fatalf("--exclude %q should have been rejected", bad)
		}
	}
}

func hasPrefix(p ExclusionPlan, want string) bool {
	for _, e := range p.Exclusions {
		if e.Prefix == want {
			return true
		}
	}
	return false
}

// nothingToClear scripts the kernel's "no such rule" for every priority this
// module owns, so a test's pre-clear terminates instead of looping 64 times
// against a runner that cheerfully succeeds at everything.
func nothingToClear(r *recordingRunner) {
	for _, p := range routePriorities {
		r.answer(fmt.Sprintf("ip rule del priority %d", p), noRule, errors.New("exit status 2"))
	}
}

func containerRoutes(prefixes ...string) []ContainerRoute {
	var out []ContainerRoute
	for _, p := range prefixes {
		out = append(out, ContainerRoute{Prefix: p, Networks: []string{"net-" + p}})
	}
	return out
}

// THE INVARIANT, as a command sequence. Only container networks may be sent
// into the tunnel's table, and the machine's own traffic must be claimed for
// the main table BEFORE anything else is installed — the window in which the
// host could take the gate has to be zero, not small.
func TestApplyRoutesPinsTheHostBeforeItRoutesAnything(t *testing.T) {
	r := newRecordingRunner()
	nothingToClear(r)
	err := ApplyRoutes(context.Background(), r, RoutePlan{
		Containers: containerRoutes("10.89.0.0/24", "10.88.0.0/16"),
		Exclusions: []Exclusion{{Prefix: "65.109.66.88/32"}, {Prefix: "192.168.1.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The pre-clear comes first, and the first thing INSTALLED is the bypass.
	firstAdd := ""
	for _, c := range r.calls {
		if strings.Contains(c, "rule add") {
			firstAdd = c
			break
		}
	}
	wantBypass := fmt.Sprintf("ip rule add from all lookup main priority %d", hostBypassPriority)
	if firstAdd != wantBypass {
		t.Fatalf("first rule installed was %q, want the host bypass %q — anything else leaves a window where this machine's own egress could take the gate", firstAdd, wantBypass)
	}
	if !strings.HasPrefix(r.calls[0], "ip rule del priority") {
		t.Fatalf("first call was %q, want a pre-clear: two overlapping generations of rules is the leftover state this design refuses to create", r.calls[0])
	}

	for _, want := range []string{
		wantBypass,
		fmt.Sprintf("ip rule add to %s lookup 52 priority %d", meshPrefix, meshPreservePriority),
		fmt.Sprintf("ip rule add to 65.109.66.88/32 lookup main priority %d", exclusionPriority),
		fmt.Sprintf("ip rule add from 10.89.0.0/24 lookup 52 priority %d", containerRoutePriority),
		fmt.Sprintf("ip rule add from 10.88.0.0/16 lookup 52 priority %d", containerRoutePriority),
	} {
		if !called(r, want) {
			t.Fatalf("missing %q in %v", want, r.calls)
		}
	}

	// The heart of it: nothing that is not a container network may be sent
	// into table 52 by a `from` rule. A `from all lookup 52` here would be the
	// old, wrong shape of this whole feature reappearing.
	routed := map[string]bool{"10.89.0.0/24": true, "10.88.0.0/16": true}
	for _, c := range r.calls {
		fields := strings.Fields(c)
		if !strings.Contains(c, "rule add") || !strings.Contains(c, "lookup 52") {
			continue
		}
		for i, f := range fields {
			if f == "from" && !routed[fields[i+1]] {
				t.Fatalf("only container networks may be routed into the tunnel's table; %q routes %q", c, fields[i+1])
			}
		}
	}
}

// A container rule keyed on an individual address is the aw-console outage
// (`ip rule from 172.18.0.5 lookup 51821`): container IPs are ephemeral AND
// recycled, so the rule silently starts applying to a different container.
// Every routed source must be a network.
func TestApplyRoutesNeverRoutesASingleContainerAddress(t *testing.T) {
	r := newRecordingRunner()
	nothingToClear(r)
	if err := ApplyRoutes(context.Background(), r, RoutePlan{Containers: containerRoutes("172.18.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if !strings.Contains(c, "rule add") || !strings.Contains(c, "lookup 52") {
			continue
		}
		fields := strings.Fields(c)
		for i, f := range fields {
			if f != "from" {
				continue
			}
			source := fields[i+1]
			if source == "all" {
				continue
			}
			if strings.HasSuffix(source, "/32") || !strings.Contains(source, "/") {
				t.Fatalf("%q routes a host address, not a network — that is the rule shape that took a container off the internet for two days", c)
			}
		}
	}
}

func TestApplyRoutesRollsBackAPartialSet(t *testing.T) {
	r := newRecordingRunner()
	nothingToClear(r)
	r.answer(fmt.Sprintf("ip rule add from 10.89.0.0/24 lookup 52 priority %d", containerRoutePriority), "RTNETLINK answers: Operation not permitted", errors.New("exit status 2"))
	err := ApplyRoutes(context.Background(), r, RoutePlan{
		Containers: containerRoutes("10.89.0.0/24"),
		Exclusions: []Exclusion{{Prefix: "65.109.66.88/32"}},
	})
	if err == nil {
		t.Fatal("expected the failure to propagate")
	}
	// A half-applied set is worse than none: it reads as though the host is
	// pinned when the failed rule may be the pin.
	dels := 0
	for _, c := range r.calls {
		if c == fmt.Sprintf("ip rule del priority %d", hostBypassPriority) {
			dels++
		}
	}
	if dels < 2 {
		t.Fatalf("a failed apply must roll back every priority it owns, calls: %v", r.calls)
	}
}

// A cleanup that knows about only some of the priorities is how a rule outlives
// the intent that created it — and one of them points into the tunnel's table.
func TestClearRoutesSweepsEveryPriorityThisModuleInstalls(t *testing.T) {
	r := newRecordingRunner()
	nothingToClear(r)
	if _, err := clearRouteRules(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for _, p := range routePriorities {
		if !called(r, fmt.Sprintf("ip rule del priority %d", p)) {
			t.Fatalf("priority %d was installed but never swept: %v", p, r.calls)
		}
	}
}

func TestClearRoutesStopsOnTheKernelsNoSuchRule(t *testing.T) {
	// Two rules present, then the kernel's "no such file".
	calls := 0
	stub := runnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		calls++
		if calls <= 2 {
			return "", nil
		}
		return noRule, errors.New("exit status 2")
	})
	removed, err := clearRulesAtPriority(context.Background(), stub, exclusionPriority)
	if err != nil {
		t.Fatalf("the kernel's 'no such rule' is the loop's exit condition, not a failure: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d", removed)
	}
}

func TestClearRoutesPropagatesARealError(t *testing.T) {
	stub := runnerFunc(func(context.Context, string, ...string) (string, error) {
		return "RTNETLINK answers: Operation not permitted", errors.New("exit status 2")
	})
	if _, err := clearRouteRules(context.Background(), stub); err == nil {
		t.Fatal("a permission error is not 'there were none left'")
	}
}

type runnerFunc func(ctx context.Context, name string, args ...string) (string, error)

func (f runnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}

func called(r *recordingRunner, want string) bool {
	for _, c := range r.calls {
		if c == want {
			return true
		}
	}
	return false
}

// Verbatim `ip rule show` from the Surface, 2026-08-26 (tailscale's own
// priorities, not an approximation), with this module's full container-scoped
// set added at the priorities it really installs.
const ipRuleShowWithExclusions = `0:	from all lookup local
5210:	from all fwmark 0x80000/0xff0000 lookup main
5230:	from all fwmark 0x80000/0xff0000 lookup default
5250:	from all fwmark 0x80000/0xff0000 unreachable
5259:	from all to 100.64.0.0/10 lookup 52
5260:	from all to 65.109.66.88 lookup main
5260:	from all to 10.89.0.0/24 lookup main
5261:	from 10.89.0.0/24 lookup 52
5265:	from all lookup main
5270:	from all lookup 52
32766:	from all lookup main
32767:	from all lookup default`

func TestParseRouteRulesReadsBackWhatIsInForce(t *testing.T) {
	got := parseRouteRules(ipRuleShowWithExclusions)
	want := []string{
		"from all to 100.64.0.0/10 lookup 52",
		"from all to 65.109.66.88 lookup main",
		"from all to 10.89.0.0/24 lookup main",
		"from 10.89.0.0/24 lookup 52",
		"from all lookup main",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule %d = %q, want %q", i, got[i], want[i])
		}
	}
	// Verbatim, not summarised into bare prefixes: under container-scoped
	// routing the DIRECTION of a rule is its whole meaning, and `from
	// 10.89.0.0/24 lookup 52` (into the tunnel) and `to 10.89.0.0/24 lookup
	// main` (out of it) would collapse into the same string.
	if got[2] == got[3] {
		t.Fatal("a rule's direction must survive being read back")
	}
}

// THE PRIORITY ORDER IS THE DESIGN. Every one of these comparisons is a
// separate failure if it inverts, and none of them is visible from the running
// system until something is already routed wrong.
func TestPriorityOrderIsTheWholeSafetyProperty(t *testing.T) {
	const tailscaleCatchAll = 5270
	if hostBypassPriority >= tailscaleCatchAll {
		t.Fatalf("the host bypass (%d) must be consulted BEFORE tailscale's catch-all (%d), or this machine's own traffic goes into the tunnel — which is the bug this feature was rewritten to remove", hostBypassPriority, tailscaleCatchAll)
	}
	if containerRoutePriority >= hostBypassPriority {
		t.Fatalf("the container routes (%d) must be consulted BEFORE the host bypass (%d), or the bypass swallows them and the gate silently does nothing", containerRoutePriority, hostBypassPriority)
	}
	if exclusionPriority >= containerRoutePriority {
		t.Fatalf("the exclusions (%d) must be consulted BEFORE the container routes (%d), or container-to-LAN and container-to-control-plane traffic is sent into the tunnel", exclusionPriority, containerRoutePriority)
	}
	if meshPreservePriority >= hostBypassPriority {
		t.Fatalf("the mesh-preserve rule (%d) must be consulted BEFORE the host bypass (%d) — measured on the Surface 2026-08-26, the main table has NO route for %s, so the bypass alone takes the host off the mesh", meshPreservePriority, hostBypassPriority, meshPrefix)
	}
	// And all of them inside tailscale's reserved block, which is what makes
	// deleting blindly at these priorities safe.
	for _, p := range routePriorities {
		if p < 5210 || p > tailscaleCatchAll {
			t.Fatalf("priority %d is outside tailscale's reserved 5210-%d block, so something else may allocate there and a blind delete would remove somebody else's rule", p, tailscaleCatchAll)
		}
	}
	if !strings.Contains(ipRuleShowWithExclusions, fmt.Sprintf("%d:\tfrom all lookup 52", tailscaleCatchAll)) {
		t.Fatal("the captured rule table no longer shows tailscale's catch-all where this test assumes it")
	}
}

func TestParseRouteDevice(t *testing.T) {
	// Verbatim shapes from `ip route get`.
	cases := map[string]string{
		"1.1.1.1 dev tailscale0 table 52 src 100.64.0.2 uid 0 \n    cache ": "tailscale0",
		"1.1.1.1 via 172.17.0.1 dev eth0 src 172.17.0.5 uid 0 \n    cache ": "eth0",
		"": "",
	}
	for out, want := range cases {
		if got := parseRouteDevice(out); got != want {
			t.Fatalf("parseRouteDevice(%q) = %q, want %q", out, got, want)
		}
	}
}

func measured(ip string) ContainerEgressResult {
	return ContainerEgressResult{IP: ip, Via: "https://1.1.1.1/cdn-cgi/trace", Runtime: "podman", Network: "podman"}
}

func TestContainerEgressVerdictExactMatchWins(t *testing.T) {
	host := "188.250.165.236"
	ok, _ := containerEgressVerdict(measured(host), measured("65.109.66.88"), "65.109.66.88", host)
	if !ok {
		t.Fatal("an exact match with the stated gate address is a confirmation")
	}
	ok, reason := containerEgressVerdict(measured(host), measured("1.2.3.4"), "65.109.66.88", host)
	if ok {
		t.Fatal("landing somewhere other than the stated gate is not a confirmation")
	}
	if !strings.Contains(reason, "not leaving through the gate") {
		t.Fatalf("reason = %q", reason)
	}
}

// The card's rule, literally: if the containers' public IP did not change,
// revert and report failure. "The interface is up" proves nothing.
func TestContainerEgressVerdictUnchangedAddressIsAFailure(t *testing.T) {
	ok, reason := containerEgressVerdict(measured("65.109.66.88"), measured("65.109.66.88"), "", "188.250.165.236")
	if ok {
		t.Fatal("an unchanged container IP cannot be reported as a working switch")
	}
	// And it has to say what to do about the legitimate case — a gate that
	// really does present the address the client already used — rather than
	// leaving the operator to guess why a correct setup keeps reverting.
	if !strings.Contains(reason, "--expect-egress") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestContainerEgressVerdictNeedsSomethingToCompareAgainst(t *testing.T) {
	ok, reason := containerEgressVerdict(ContainerEgressResult{Error: "no runtime"}, measured("65.109.66.88"), "", "188.250.165.236")
	if ok {
		t.Fatal("with no baseline and no expectation there is nothing that would count as proof")
	}
	if !strings.Contains(reason, "--expect-egress") {
		t.Fatalf("reason = %q", reason)
	}
}

// THE FAILURE THAT USED TO LOOK LIKE SUCCESS. The containers' address changed
// from their own baseline and still equals the host's — which, with the host
// proven to have held, can only mean the rules matched nothing. Read from the
// container's number alone this is indistinguishable from a working gate.
func TestContainerEgressEqualToTheHostsIsNeverAConfirmation(t *testing.T) {
	ok, reason := containerEgressVerdict(measured("1.2.3.4"), measured("188.250.165.236"), "", "188.250.165.236")
	if ok {
		t.Fatal("container egress equal to the host's means nothing was routed, however much it changed")
	}
	if !strings.Contains(reason, "not going through the gate at all") {
		t.Fatalf("reason = %q", reason)
	}
}

// A container that cannot reach anything is a failure with a reason, never a
// silent pass and never the host's address stood in for it.
func TestContainerEgressVerdictReportsAnUnreachableContainer(t *testing.T) {
	ok, reason := containerEgressVerdict(measured("1.2.3.4"), ContainerEgressResult{Error: "curl: (28) timed out"}, "", "188.250.165.236")
	if ok {
		t.Fatal("no measurement is not a confirmation")
	}
	if !strings.Contains(reason, "timed out") {
		t.Fatalf("the reason must carry the evidence: %q", reason)
	}
}

// BOTH PAIRS, ALWAYS. A description that showed only the containers' addresses
// would hide the one fact that decides whether this was a success or a
// production machine losing its address.
func TestConfirmResultDescribeShowsBothHalves(t *testing.T) {
	c := ConfirmResult{
		HostBefore: "188.250.165.236", HostAfter: "188.250.165.236",
		HostAfterVia: "https://1.1.1.1/cdn-cgi/trace", HostHeld: true,
		ContainerBefore: measured("188.250.165.236"), ContainerAfter: measured("65.109.66.88"),
		DefaultDevice: "eth0", ControlPlaneOK: true, OK: false, Reason: "something",
	}
	desc := c.Describe()
	for _, want := range []string{
		"host egress before: 188.250.165.236",
		"held, as required",
		"container egress before: 188.250.165.236",
		"container egress now:    65.109.66.88",
		"eth0",
		"control plane: reachable",
		"NOT CONFIRMED",
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("%q missing from:\n%s", want, desc)
		}
	}

	moved := ConfirmResult{HostBefore: "188.250.165.236", HostAfter: "65.109.66.88", HostMoved: true, Reason: "x"}
	if !strings.Contains(moved.Describe(), "MOVED. This is a failed apply.") {
		t.Fatalf("a host that moved must say so in words, not leave it to be inferred from two numbers:\n%s", moved.Describe())
	}
}

func exitPeerStatus() Status {
	return Status{
		Installed: true, BackendState: "Running",
		Peers: []Peer{
			{Name: "aw-baremetal", DNSName: "aw-baremetal.mesh.aw.tekflox.com", IPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, Online: true, OffersExit: true},
			{Name: "aw-mac", IPs: []string{"100.64.0.3"}, Online: true, OffersExit: false},
			{Name: "aw-offline-gate", IPs: []string{"100.64.0.9"}, Online: false, OffersExit: true},
		},
	}
}

func TestResolveExitPeerAcceptsEveryFormAStatusListingPrints(t *testing.T) {
	s := exitPeerStatus()
	for _, name := range []string{"aw-baremetal", "AW-BAREMETAL", "aw-baremetal.mesh.aw.tekflox.com", "100.64.0.1"} {
		p, err := ResolveExitPeer(s, name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if p.Name != "aw-baremetal" {
			t.Fatalf("%q resolved to %q", name, p.Name)
		}
	}
}

// The two refusals a human has to be able to tell apart, because they need
// different people: "not advertising" is the gate's operator, "advertised but
// unapproved" is a headscale admin.
func TestResolveExitPeerRefusesAPeerThatOffersNoExit(t *testing.T) {
	_, err := ResolveExitPeer(exitPeerStatus(), "aw-mac")
	if err == nil {
		t.Fatal("selecting a peer that offers no exit route would move the default route onto a gate that forwards nothing")
	}
	if !strings.Contains(err.Error(), "approved") || !strings.Contains(err.Error(), "advertise-exit-node") {
		t.Fatalf("the refusal must name both reasons, got %q", err)
	}
}

func TestResolveExitPeerRefusesAnOfflineGate(t *testing.T) {
	_, err := ResolveExitPeer(exitPeerStatus(), "aw-offline-gate")
	if err == nil || !strings.Contains(err.Error(), "OFFLINE") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveExitPeerListsWhatIsAvailableWhenTheNameIsWrong(t *testing.T) {
	_, err := ResolveExitPeer(exitPeerStatus(), "typo")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "aw-baremetal [offers exit]") {
		t.Fatalf("an unknown name should show which peers could actually be used, got %q", err)
	}
}

// --accept-dns=false is forced on every call, clearing included. Accepting
// MagicDNS rewrites the resolver, which is the same lockout arriving through
// DNS instead of through routing — so there must be no path through this
// package that leaves it to tailscale's default.
func TestSetExitNodeAlwaysForcesAcceptDNSOff(t *testing.T) {
	for _, ip := range []string{"100.64.0.1", ""} {
		r := newRecordingRunner()
		if err := SetExitNode(context.Background(), r, ip); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Fatalf("calls = %v", r.calls)
		}
		if !strings.Contains(r.calls[0], "--accept-dns=false") {
			t.Fatalf("got %q", r.calls[0])
		}
		if !strings.Contains(r.calls[0], "--exit-node="+ip+" ") {
			t.Fatalf("got %q", r.calls[0])
		}
	}
}

func TestSetExitNodeAllowsLANAccessOnlyWhileAGateIsSelected(t *testing.T) {
	r := newRecordingRunner()
	_ = SetExitNode(context.Background(), r, "100.64.0.1")
	if !strings.Contains(r.calls[0], "--exit-node-allow-lan-access=true") {
		t.Fatalf("the LAN has to stay reachable while the default route is elsewhere: %q", r.calls[0])
	}
	r2 := newRecordingRunner()
	_ = SetExitNode(context.Background(), r2, "")
	if !strings.Contains(r2.calls[0], "--exit-node-allow-lan-access=false") {
		t.Fatalf("clearing must leave no exit-node settings behind: %q", r2.calls[0])
	}
}

func TestHostOfStripsSchemeAndPort(t *testing.T) {
	cases := map[string]string{
		"https://api.aw.tekflox.com":        "api.aw.tekflox.com",
		"https://api.aw.tekflox.com/":       "api.aw.tekflox.com",
		"http://10.0.0.1:9030/link":         "10.0.0.1",
		"api.aw.tekflox.com":                "api.aw.tekflox.com",
		"  https://api.aw.tekflox.com/api ": "api.aw.tekflox.com",
		"":                                  "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Fatalf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
