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
	if !strings.Contains(plan.Exclusions[0].Reason, "remote-management") {
		t.Fatalf("reason = %q", plan.Exclusions[0].Reason)
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

// Exclusions are installed as "send this prefix to the MAIN table", never as
// a rule pointing into a table the tunnel owns. That choice is what makes a
// leftover rule inert instead of a black hole — the recorded accident on this
// infrastructure was `ip rule from 172.18.0.5 lookup 51821`, pointing at a
// table whose gateway had ceased to exist.
func TestApplyExclusionsAlwaysLooksUpMain(t *testing.T) {
	r := newRecordingRunner()
	r.answer("ip rule del priority 5260", noRule, errors.New("exit status 2"))
	if err := ApplyExclusions(context.Background(), r, []Exclusion{
		{Prefix: "65.109.66.88/32"}, {Prefix: "10.89.0.0/24"},
	}); err != nil {
		t.Fatal(err)
	}
	wantAdds := []string{
		"ip rule add to 65.109.66.88/32 lookup main priority 5260",
		"ip rule add to 10.89.0.0/24 lookup main priority 5260",
	}
	for _, want := range wantAdds {
		if !called(r, want) {
			t.Fatalf("missing %q in %v", want, r.calls)
		}
	}
	for _, c := range r.calls {
		if strings.Contains(c, "rule add") && !strings.Contains(c, "lookup main") {
			t.Fatalf("an exclusion must never point anywhere but the main table: %q", c)
		}
	}
	// Cleared before applying: two overlapping generations of exclusion is
	// exactly the leftover state this design refuses to create.
	if r.calls[0] != "ip rule del priority 5260" {
		t.Fatalf("first call was %q, want the pre-clear", r.calls[0])
	}
}

func TestApplyExclusionsRollsBackAPartialSet(t *testing.T) {
	r := newRecordingRunner()
	r.answer("ip rule del priority 5260", noRule, errors.New("exit status 2"))
	r.answer("ip rule add to 10.89.0.0/24 lookup main priority 5260", "RTNETLINK answers: Operation not permitted", errors.New("exit status 2"))
	err := ApplyExclusions(context.Background(), r, []Exclusion{
		{Prefix: "65.109.66.88/32"}, {Prefix: "10.89.0.0/24"},
	})
	if err == nil {
		t.Fatal("expected the failure to propagate")
	}
	// A half-applied set is worse than none: it reads as though the
	// management path is pinned when the failed rule may be the pin.
	dels := 0
	for _, c := range r.calls {
		if c == "ip rule del priority 5260" {
			dels++
		}
	}
	if dels < 2 {
		t.Fatalf("a failed apply must roll back, calls: %v", r.calls)
	}
}

func TestClearExclusionsStopsOnTheKernelsNoSuchRule(t *testing.T) {
	// Two rules present, then the kernel's "no such file".
	calls := 0
	stub := runnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		calls++
		if calls <= 2 {
			return "", nil
		}
		return noRule, errors.New("exit status 2")
	})
	removed, err := clearIPRuleExclusions(context.Background(), stub)
	if err != nil {
		t.Fatalf("the kernel's 'no such rule' is the loop's exit condition, not a failure: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d", removed)
	}
}

func TestClearExclusionsPropagatesARealError(t *testing.T) {
	stub := runnerFunc(func(context.Context, string, ...string) (string, error) {
		return "RTNETLINK answers: Operation not permitted", errors.New("exit status 2")
	})
	if _, err := clearIPRuleExclusions(context.Background(), stub); err == nil {
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

// Verbatim `ip rule show` from aw-baremetal, 2026-08-25, with two exclusions
// added — the priorities tailscale really uses, not an approximation.
const ipRuleShowWithExclusions = `0:	from all lookup local
5210:	from all fwmark 0x80000/0xff0000 lookup main
5230:	from all fwmark 0x80000/0xff0000 lookup default
5250:	from all fwmark 0x80000/0xff0000 unreachable
5260:	from all to 65.109.66.88 lookup main
5260:	from all to 10.89.0.0/24 lookup main
5270:	from all lookup 52
32766:	from all lookup main
32767:	from all lookup default`

func TestParseExclusionRulesReadsBackWhatIsInForce(t *testing.T) {
	got := parseExclusionRules(ipRuleShowWithExclusions)
	if len(got) != 2 || got[0] != "65.109.66.88" || got[1] != "10.89.0.0/24" {
		t.Fatalf("got %v", got)
	}
}

// 5260 has to sit ABOVE tailscale's catch-all at 5270, or the exclusions are
// never consulted and the control plane goes into the tunnel with everything
// else. This is the single number the whole safety property rests on.
func TestExclusionPriorityBeatsTailscalesCatchAll(t *testing.T) {
	const tailscaleCatchAll = 5270
	if exclusionPriority >= tailscaleCatchAll {
		t.Fatalf("exclusion priority %d must be lower than tailscale's catch-all %d — a higher number is consulted later, which means never", exclusionPriority, tailscaleCatchAll)
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

func TestEgressVerdictExactMatchWins(t *testing.T) {
	ok, _ := egressVerdict("188.250.165.236", "65.109.66.88", Egress{IP: "65.109.66.88", Via: "x"})
	if !ok {
		t.Fatal("an exact match with the stated gate address is a confirmation")
	}
	ok, reason := egressVerdict("188.250.165.236", "65.109.66.88", Egress{IP: "1.2.3.4", Via: "x"})
	if ok {
		t.Fatal("landing somewhere other than the stated gate is not a confirmation")
	}
	if !strings.Contains(reason, "not leaving through the gate") {
		t.Fatalf("reason = %q", reason)
	}
}

// The card's rule, literally: if the public IP did not change, revert and
// report failure. "The interface is up" proves nothing.
func TestEgressVerdictUnchangedAddressIsAFailure(t *testing.T) {
	ok, reason := egressVerdict("65.109.66.88", "", Egress{IP: "65.109.66.88", Via: "https://api.ipify.org"})
	if ok {
		t.Fatal("an unchanged public IP cannot be reported as a working switch")
	}
	// And it has to say what to do about the legitimate case — a gate that
	// really does present the address the client already used — rather than
	// leaving the operator to guess why a correct setup keeps reverting.
	if !strings.Contains(reason, "--expect-egress") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestEgressVerdictNeedsSomethingToCompareAgainst(t *testing.T) {
	ok, reason := egressVerdict("", "", Egress{IP: "65.109.66.88"})
	if ok {
		t.Fatal("with no baseline and no expectation there is nothing that would count as proof")
	}
	if !strings.Contains(reason, "--expect-egress") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestConfirmResultDescribeShowsTheEvidenceNotAVerdict(t *testing.T) {
	c := ConfirmResult{
		Baseline: "188.250.165.236", Observed: "65.109.66.88", ObservedVia: "https://api.ipify.org",
		DefaultDevice: "tailscale0", ControlPlaneOK: true, OK: false, Reason: "something",
	}
	desc := c.Describe()
	for _, want := range []string{"188.250.165.236", "65.109.66.88", "tailscale0", "control plane: reachable", "NOT CONFIRMED"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("%q missing from:\n%s", want, desc)
		}
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
