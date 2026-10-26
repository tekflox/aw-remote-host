package vpn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// tableRunner answers each command from a table keyed on the first few
// arguments, so a test can describe a machine ("this host has these rules and
// this table") rather than stub a Runner per case. An unmatched command
// answers empty with no error, which is the shape `ip` itself uses for "no
// such thing", so a test only has to spell out what it cares about.
type tableRunner struct {
	answers map[string]string
	errs    map[string]error
	calls   []string
}

// The LONGEST matching prefix wins, in both tables. Map iteration order in Go
// is randomised, so a first-match-wins lookup is nondeterministic the moment
// one key is a prefix of another — and that is not hypothetical here:
// `ip route get 1.1.1.1` is a prefix of `ip route get 1.1.1.1 ipproto udp
// dport 53`, and those two commands are REQUIRED to answer differently. That
// pair is the whole point of the DNS rule proofs, so the fixture has to be
// able to express it without flaking one run in two.
func (s *tableRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	full := strings.TrimSpace(name + " " + strings.Join(args, " "))
	s.calls = append(s.calls, full)
	bestErrLen := -1
	var bestErr error
	for prefix, err := range s.errs {
		if strings.HasPrefix(full, prefix) && len(prefix) > bestErrLen {
			bestErrLen, bestErr = len(prefix), err
		}
	}
	if bestErrLen >= 0 {
		return "", bestErr
	}
	bestLen := -1
	best := ""
	for prefix, out := range s.answers {
		if strings.HasPrefix(full, prefix) && len(prefix) > bestLen {
			bestLen, best = len(prefix), out
		}
	}
	if bestLen >= 0 {
		return best, nil
	}
	return "", nil
}

func (s *tableRunner) ran(prefix string) bool {
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// A healthy production-shaped host: the hub's table 200, a Hetzner-style
// onlink default, and one container attached to one network.
//
// The tunnel device carries 10.8.0.11/32, which is the measured shape of this
// deployment's gl-inet and not an arbitrary address: it is INSIDE 10.0.0.0/8,
// so every test built on this fixture exercises the one collision the external
// path has and the mesh path does not. See privateTableExclusions.
func healthyHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"ip -V":                      "ip utility, iproute2-6.1.0",
		"docker --version":           "Docker version 27.0.0",
		"docker inspect -f":          "e91aacf5a3a39a17 172.18.0.4 ",
		"ip route show table 200":    "default via 10.8.0.2 dev wg0 \n172.18.0.0/16 dev br-2c9cd32e2d2f scope link \n",
		"ip route show default":      "default via 65.109.66.65 dev enp41s0 proto static onlink \n",
		"ip -4 -o addr show":         "1: lo    inet 127.0.0.1/8 scope host lo\n2: enp41s0    inet 65.109.66.88/32 scope global enp41s0\n",
		"ip -4 -o addr show dev wg0": "7: wg0    inet 10.8.0.11/32 scope global wg0\n",
		"docker exec e91aacf5a3a39a17 cat /etc/resolv.conf": "nameserver 127.0.0.11\n",
		"cat /run/systemd/resolve/resolv.conf":              "nameserver 185.12.64.1\nnameserver 185.12.64.2\n",
	}}
}

// privateOnHealthyHost is what the fixture above must hold outside the tunnel:
// every private block EXCEPT the one its own tunnel address lives in. Spelled
// once so a test asserts the whole set rather than the member it remembered.
var privateOnHealthyHost = []string{"172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}

// privateRoutesInTable200 is those same blocks as `ip route show table 200`
// prints them once installed, for the fixtures that describe a host where the
// exclusions are already in place and must therefore be left alone.
const privateRoutesInTable200 = "172.16.0.0/12 via 65.109.66.65 dev enp41s0 onlink \n" +
	"192.168.0.0/16 via 65.109.66.65 dev enp41s0 onlink \n" +
	"169.254.0.0/16 via 65.109.66.65 dev enp41s0 onlink \n"

func planOn(t *testing.T, r Runner) *ExternalRoutePlan {
	t.Helper()
	return planOnWithControlPlane(t, r, "")
}

// planOnWithControlPlane pins the control plane to an IP LITERAL. Go's
// resolver short-circuits a literal, so this exercises the one exclusion that
// still exists without the test depending on DNS — which would be a poor
// dependency for a test about DNS.
func planOnWithControlPlane(t *testing.T, r Runner, controlPlane string) *ExternalRoutePlan {
	t.Helper()
	plan, err := PlanExternalRoute(context.Background(), ExternalRouteSpec{
		Container:    "aw-remote-host",
		Runner:       r,
		Runtime:      ContainerRuntime{Name: "docker"},
		ControlPlane: controlPlane,
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

// THE refusal. 172.18.0.0/16 on the production bare metal carries aw-backend,
// aw-caddy, aw-headscale, aw-derper, aw-sandbox and
// agents-platform-multitenant. A rule written on a network CIDR instead of a
// host address would route all of production through a residential line in one
// command, so nothing wider than a /32 may reach the kernel.
func TestRefusesAnythingWiderThanASingleHost(t *testing.T) {
	for _, src := range []string{"172.18.0.0/16", "172.18.0.0/24", "172.18.0.4/32"} {
		if err := mustBeSingleHost(src); err == nil {
			t.Fatalf("%s was accepted; only a bare single address may be", src)
		}
	}
	if err := mustBeSingleHost("172.18.0.4"); err != nil {
		t.Fatalf("a single host address must be accepted: %v", err)
	}
}

// The plan must produce a /32 rule and nothing else, spelled the same way it
// will be removed. A rule added one way and deleted another is a rule that
// outlives its own revert.
func TestRuleIsAlwaysASlashThirtyTwo(t *testing.T) {
	plan := planOn(t, healthyHost())
	add := strings.Join(plan.ruleArgs("add"), " ")
	del := strings.Join(plan.ruleArgs("del"), " ")
	if !strings.Contains(add, "from 172.18.0.4/32") {
		t.Fatalf("rule is not a /32: %s", add)
	}
	if !strings.Contains(add, "lookup 200") || !strings.Contains(add, "priority 5399") {
		t.Fatalf("rule lost its table or priority: %s", add)
	}
	if strings.Replace(add, " add ", " del ", 1) != del {
		t.Fatalf("add and del disagree:\n add %s\n del %s", add, del)
	}
}

// A rule pointing at a table with no default route does not fall through to
// main — it black-holes every packet that matches. That is the difference
// between "the tunnel is down" and "the workspace lost the internet", so an
// empty table has to be a refusal and never an apply.
func TestRefusesATableWithNoDefaultRoute(t *testing.T) {
	r := healthyHost()
	r.answers["ip route show table 200"] = "172.18.0.0/16 dev br-2c9cd32e2d2f scope link \n"
	plan := planOn(t, r)
	if !strings.Contains(plan.Refusal, "black-hole") {
		t.Fatalf("refusal = %q", plan.Refusal)
	}
}

// A container address that is also one of this machine's own addresses would
// route the host. That is the failure the 2026-08-26 invariant exists to
// prevent, and it has to be proven rather than assumed.
func TestRefusesASourceThatIsThisMachine(t *testing.T) {
	r := healthyHost()
	r.answers["docker inspect -f"] = "someid 65.109.66.88 "
	plan := planOn(t, r)
	if !strings.Contains(plan.Refusal, "THIS MACHINE") {
		t.Fatalf("refusal = %q", plan.Refusal)
	}
}

// An unresolvable container is a refusal, never a guessed address: this rule
// keys on runtime IPAM, which is recycled, so a remembered address eventually
// points at whatever moved into that slot.
func TestRefusesAContainerItCannotResolve(t *testing.T) {
	r := healthyHost()
	delete(r.answers, "docker inspect -f")
	plan := planOn(t, r)
	if !strings.Contains(plan.Refusal, "no IPv4 address") {
		t.Fatalf("refusal = %q", plan.Refusal)
	}
}

// Routing one of several attachments moves part of a container's traffic and
// not the rest, so its egress would depend on which network a given connection
// happened to use. Refusing beats picking.
func TestRefusesAContainerOnSeveralNetworks(t *testing.T) {
	r := healthyHost()
	r.answers["docker inspect -f"] = "someid 172.18.0.8 172.20.0.2 172.21.0.2 "
	plan := planOn(t, r)
	if !strings.Contains(plan.Refusal, "routes exactly one source address") {
		t.Fatalf("refusal = %q", plan.Refusal)
	}
}

// DNS GOES THROUGH THE VPN — Frederico's decision, 2026-09-05. This test used
// to assert the exact opposite, and that is the point of keeping it here
// rather than deleting it: pinning the resolvers outside the tunnel meant a
// user who switched the VPN on still resolved through their ISP, which is the
// single most recognisable way a VPN leaks, and it was the default.
//
// The fixture still ANSWERS the resolv.conf reads. That is deliberate: if the
// nameservers came back as exclusions this test would fail, so the assertion
// cannot pass merely because the fixture went quiet.
func TestNameserversAreNoLongerHeldOutsideTheTunnel(t *testing.T) {
	r := healthyHost()
	plan := planOn(t, r)
	got := strings.Join(plan.Exclusions, " ")
	for _, resolver := range []string{"185.12.64.1", "185.12.64.2", "127.0.0.11"} {
		if strings.Contains(got, resolver) {
			t.Fatalf("%s is still pinned outside the tunnel, so DNS would leak to the ISP: %v", resolver, plan.Exclusions)
		}
	}
	// Not merely absent from the output — never asked for. A read whose answer
	// is discarded is a resolver list one refactor away from coming back.
	for _, probe := range []string{
		"docker exec e91aacf5a3a39a17 cat /etc/resolv.conf",
		"cat /run/systemd/resolve/resolv.conf",
		"cat /etc/resolv.conf",
	} {
		if r.ran(probe) {
			t.Fatalf("the planner still reads the resolver list (%q); it has no reason to", probe)
		}
	}
}

// THE ONE EXCLUSION THAT STAYS, and it is the kill switch rather than a
// nicety: core has to reach aw-backend to issue `external-down`, so without
// this pin a half-broken tunnel blocks its own Disconnect — the recovery
// surface goes down with the thing being recovered.
func TestControlPlaneStaysOutsideTheTunnelBecauseItIsTheKillSwitch(t *testing.T) {
	plan := planOnWithControlPlane(t, healthyHost(), "https://198.51.100.7:8443")
	// FIRST, not merely present. applyExternalRoute writes this list in order,
	// so the kill switch is the first route installed and the one most likely
	// to be in place if the apply dies halfway.
	if len(plan.Exclusions) == 0 || plan.Exclusions[0] != "198.51.100.7/32" {
		t.Fatalf("the control plane is not held outside the tunnel, first: %v", plan.Exclusions)
	}
	// The rest is the unconditional private half and nothing else — the
	// resolvers used to fill this list, and no longer do.
	if got := strings.Join(plan.Exclusions[1:], " "); got != strings.Join(privateOnHealthyHost, " ") {
		t.Fatalf("exclusions after the control plane = %q, want %q", got, strings.Join(privateOnHealthyHost, " "))
	}
	// And with no control plane the kill switch is simply absent; the private
	// half is not a substitute for it and must not make the list look pinned.
	bare := planOn(t, healthyHost())
	if strings.Contains(strings.Join(bare.Exclusions, " "), "/32") {
		t.Fatalf("something is pinned as a control plane when none was given: %v", bare.Exclusions)
	}
}

// REGRESSION, named for the incident: 2026-10-26, dialling the external
// tunnel killed every agents-platform run on this deployment. The rule is
// `from 10.89.0.25 lookup 200` and 10.89.0.25 is the workspace container whose
// netns every aw-warm-* agent CLI shares; AP-MT's shared Redis — the
// `run:{run_id}:events` stream a run's entire output travels on — answers on
// 172.18.0.1, a docker bridge of the PHYSICAL machine that is neither an
// interface here nor a route in table 200. It rode the tunnel's default and
// vanished: `POST /execute` still answered 200 while every run died at 600s
// with XLEN 0 on its stream. 172.16.0.0/12 is the line that covers it, and it
// existed in exit.go (table 52) for 24 days before it existed here.
func TestPrivateSpaceIsHeldOutsideTheExternalTunnel(t *testing.T) {
	plan := planOn(t, healthyHost())
	for _, block := range privateOnHealthyHost {
		if !containsString(plan.Exclusions, block) {
			t.Fatalf("%s is not held outside the tunnel: %v", block, plan.Exclusions)
		}
	}
	// The address that was actually measured being swallowed, checked as an
	// address rather than as the block that happens to contain it today.
	if !prefixCovers(t, plan.Exclusions, "172.18.0.1") {
		t.Fatalf("the runners' event Redis at 172.18.0.1 is still inside the tunnel: %v", plan.Exclusions)
	}
	if !prefixCovers(t, plan.Exclusions, "172.19.0.1") {
		t.Fatalf("172.19.0.1 is still inside the tunnel: %v", plan.Exclusions)
	}
}

// THE ONE DIFFERENCE FROM THE MESH PATH, and the reason this was not a copy of
// 89a87ee. On the mesh tailscale lives in 100.64.0.0/10, so 10.0.0.0/8 was
// free to exclude. An external tunnel's inner network sits inside private
// space — gl-inet carries 10.8.0.11/32 and its hub answers on 10.8.0.2 — and
// an exclusion is a route in the tunnel's OWN table, more specific than that
// table's `default dev <iface>`. A blind 10.0.0.0/8 would take the tunnel's
// inner network off the tunnel.
//
// Asserted in BOTH directions, because a hardcoded "never exclude 10/8" would
// pass the first half and leave every 10.x destination swallowed on a tunnel
// whose inner network is somewhere else entirely.
func TestTheTunnelsOwnInnerNetworkIsNotExcludedOutFromUnderIt(t *testing.T) {
	inside := planOn(t, healthyHost())
	if containsString(inside.Exclusions, "10.0.0.0/8") {
		t.Fatalf("10.0.0.0/8 was excluded while the tunnel itself lives on 10.8.0.11 — that beats `default dev wg0` for the tunnel's own inner network: %v", inside.Exclusions)
	}
	// Left out, never silently: the reason travels with the plan.
	if !strings.Contains(strings.Join(inside.PrivateSkipped, " "), "10.0.0.0/8") ||
		!strings.Contains(strings.Join(inside.PrivateSkipped, " "), "10.8.0.11") {
		t.Fatalf("the skipped block did not say which address it collided with: %v", inside.PrivateSkipped)
	}

	// Same code, a tunnel whose inner network is NOT in private space: the
	// full list applies, 10.0.0.0/8 included.
	elsewhere := healthyHost()
	elsewhere.answers["ip -4 -o addr show dev wg0"] = "7: wg0    inet 100.64.0.5/32 scope global wg0\n"
	out := planOn(t, elsewhere)
	if !containsString(out.Exclusions, "10.0.0.0/8") {
		t.Fatalf("10.0.0.0/8 was skipped on a tunnel that does not live in it, so the skip is hardcoded rather than derived: %v", out.Exclusions)
	}
	if len(out.PrivateSkipped) != 0 {
		t.Fatalf("nothing should have been skipped here: %v", out.PrivateSkipped)
	}
	// And it is the DEVICE that was asked, not an assumption about the name.
	if !elsewhere.ran("ip -4 -o addr show dev wg0") {
		t.Fatalf("the tunnel device's own addresses were never read: %v", elsewhere.calls)
	}
}

// A block the table already carries link-scope must not be excluded a second
// time through the main gateway. `ip route add` on a prefix already present
// fails, and `ip route del` with the other nexthop removes the wrong route —
// so the duplicate would turn an apply into a refusal and a revert into a
// deletion of the connected route the containers depend on.
func TestAPrivateBlockAlreadyCarriedLinkScopeIsNotExcludedAgain(t *testing.T) {
	r := healthyHost()
	r.answers["ip route show table 200"] = "default via 10.8.0.2 dev wg0 \n" +
		"192.168.0.0/16 dev br-2c9cd32e2d2f scope link \n"
	plan := planOn(t, r)
	if containsString(plan.Exclusions, "192.168.0.0/16") {
		t.Fatalf("192.168.0.0/16 is already in the table link-scope and was excluded anyway: %v", plan.Exclusions)
	}
	if !strings.Contains(strings.Join(plan.PrivateSkipped, " "), "192.168.0.0/16") {
		t.Fatalf("the skip was not explained: %v", plan.PrivateSkipped)
	}
	// A block merely CONTAINING a link-scope route is still excluded —
	// longest prefix wins, so 172.18.0.0/16 dev br0 keeps beating
	// 172.16.0.0/12 via the gateway and both belong in the table.
	if !containsString(plan.Exclusions, "172.16.0.0/12") {
		t.Fatalf("172.16.0.0/12 was dropped because a /16 inside it is connected; longest prefix already handles that: %v", plan.Exclusions)
	}
}

// prefixCovers reports whether any of prefixes contains addr. The assertion is
// about the ADDRESS that was measured being unreachable, not about the block
// that happens to cover it in this revision.
func prefixCovers(t *testing.T, prefixes []string, addr string) bool {
	t.Helper()
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("%q is not an address", addr)
	}
	for _, p := range prefixes {
		_, parsed, err := net.ParseCIDR(p)
		if err == nil && parsed.Contains(ip) {
			return true
		}
	}
	return false
}

// onlink is not decoration. The production bare metal carries 65.109.66.88/32
// with its gateway outside any interface subnet; without onlink the kernel
// answers "Nexthop has invalid gateway" and the exclusion silently never
// installs — measured on the first attempt at exactly this.
func TestExclusionRoutesAreOnlinkAndInsideTheTunnelTable(t *testing.T) {
	plan := planOn(t, healthyHost())
	add := strings.Join(plan.excludeArgs("add", "185.12.64.1/32"), " ")
	if !strings.Contains(add, "onlink") {
		t.Fatalf("exclusion is not onlink and will not install on this host: %s", add)
	}
	if !strings.Contains(add, "table 200") {
		t.Fatalf("exclusion must live INSIDE the tunnel table to beat its default: %s", add)
	}
	// `ip route del` rejects onlink on some kernels and does not need it.
	if strings.Contains(strings.Join(plan.excludeArgs("del", "185.12.64.1/32"), " "), "onlink") {
		t.Fatal("del must not carry onlink")
	}
}

// The dead-man's switch is the whole guarantee on this path, and its script
// has to remove exactly what was installed. It must also never reference this
// binary — a self-referential revert dies with any update of the tool that
// armed it.
func TestDeadmanScriptUndoesExactlyWhatWasInstalled(t *testing.T) {
	// A control plane is supplied so the exclusion loop below actually has
	// something to check. Without one the plan now has NO exclusions at all
	// (DNS goes through the VPN), and a loop over an empty slice asserts
	// nothing while still reporting a pass.
	plan := planOnWithControlPlane(t, healthyHost(), "https://198.51.100.7:8443")
	script := externalRevertScript(PrivilegedRunner{Sudo: true}, *plan)
	if !strings.Contains(script, "ip rule del from 172.18.0.4/32 lookup 200 priority 5399") {
		t.Fatalf("script does not remove the rule:\n%s", script)
	}
	if len(plan.Exclusions) == 0 {
		t.Fatal("the fixture produced no exclusions, so this test would assert nothing")
	}
	for _, ex := range plan.Exclusions {
		if !strings.Contains(script, ex) {
			t.Fatalf("script does not remove exclusion %s:\n%s", ex, script)
		}
	}
	if strings.Contains(script, "aw-remote-host ") {
		t.Fatalf("the revert must not call this binary:\n%s", script)
	}
	if !strings.Contains(script, "sudo -n ip") {
		t.Fatalf("a non-root host needs the privilege prefix baked in:\n%s", script)
	}
}

// Arm used to require a tailscale path. This path has no mesh selection to
// clear, so that requirement had to be relaxed — but relaxing it must not
// allow a switch whose entire body is comments, which would report a
// guarantee it does not provide.
func TestArmRefusesASwitchWithNothingToRun(t *testing.T) {
	if _, err := Arm(ArmSpec{After: time.Minute}); err == nil {
		t.Fatal("a switch with neither a tailscale path nor a revert must be refused")
	}
	script := ArmSpec{After: time.Minute, ExclusionRevert: "ip rule del from 1.2.3.4/32 lookup 200"}.revertScript()
	if strings.Contains(script, "set --exit-node=") {
		t.Fatalf("a specless-of-tailscale switch must not emit a bare tailscale call:\n%s", script)
	}
	if !strings.Contains(script, "ip rule del from 1.2.3.4/32") {
		t.Fatalf("the revert body was dropped:\n%s", script)
	}
}

// The mesh path must keep working exactly as before — this change relaxed a
// validation that use-exit still depends on.
func TestArmStillEmitsTheMeshRevertWhenTailscaleIsGiven(t *testing.T) {
	script := ArmSpec{After: time.Minute, TailscalePath: "/usr/bin/tailscale", ExclusionRevert: "ip rule del x"}.revertScript()
	if !strings.Contains(script, "/usr/bin/tailscale set --exit-node= --exit-node-allow-lan-access=false --accept-dns=false") {
		t.Fatalf("mesh revert lost:\n%s", script)
	}
}

// ruleInstalled parses `ip rule show`, which prints a single-host source
// WITHOUT its /32. Matching the literal "172.18.0.4/32" against that output
// would report the rule as missing forever, and Reassert would add a duplicate
// every 30 seconds.
func TestRuleInstalledMatchesHowIpRuleActuallyPrints(t *testing.T) {
	plan := planOn(t, healthyHost())
	r := &tableRunner{answers: map[string]string{
		"ip rule show": "0:\tfrom all lookup local\n5399:\tfrom 172.18.0.4 lookup 200\n32766:\tfrom all lookup main\n",
	}}
	ok, err := ruleInstalled(context.Background(), r, *plan)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v — the rule is present and must be recognised", ok, err)
	}

	empty := &tableRunner{answers: map[string]string{
		"ip rule show": "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n",
	}}
	ok, err = ruleInstalled(context.Background(), empty, *plan)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v — a flushed table must read as missing", ok, err)
	}
}

// Applying twice must not install two identical rules. `ip rule add` happily
// does, and a duplicate is invisible in every symptom but takes two `del`s to
// remove — which is exactly how a revert leaves a machine still routed.
func TestApplyIsIdempotent(t *testing.T) {
	plan := planOn(t, healthyHost())
	r := &tableRunner{answers: map[string]string{
		"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n" + privateRoutesInTable200,
	}}
	if _, err := applyExternalRoute(context.Background(), r, *plan, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if r.ran("ip rule add") {
		t.Fatal("apply added a rule that was already present")
	}
	if r.ran("ip route add") {
		t.Fatal("apply added an exclusion that was already present")
	}
}

// Reassert is what makes this survive systemd-networkd, which flushes every
// foreign routing policy rule when the daily apt upgrade restarts it. A
// flushed rule must come back; an intact one must not be touched.
//
// Every case here re-resolves the container by its recorded ContainerID
// through the runtime ("docker inspect -f") on every pass now — that inspect
// answer has to be present in the table, and pinning it to the SAME address
// the plan already carries is what isolates "a rule got flushed" from "the
// container moved", which TestReassertReResolvesAndReplacesAStaleAddress and
// its siblings below exercise on their own.
func TestReassertPutsBackAFlushedRule(t *testing.T) {
	plan := planOn(t, healthyHost())
	flushed := &tableRunner{answers: map[string]string{
		"ip rule show":            "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n" + privateRoutesInTable200,
		"docker inspect -f":       plan.ContainerID + " " + plan.SourceIP + " ",
	}}
	restored, updated, gone, err := reassertPlan(context.Background(), flushed, *plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if gone || updated != nil {
		t.Fatalf("an address that resolved unchanged must not be reported as moved or gone: updated=%v gone=%v", updated, gone)
	}
	if !flushed.ran("ip rule add from 172.18.0.4/32 lookup 200 priority 5399") {
		t.Fatalf("the flushed rule was not put back; calls: %v", flushed.calls)
	}
	if len(restored) != 1 {
		t.Fatalf("restored = %v, want exactly the rule", restored)
	}
}

// AN EXCLUSION THAT IS NOT RE-ASSERTED IS THIS BUG COMING BACK TOMORROW.
// This file's header records it: on the production bare metal the daily
// unattended apt upgrade restarts systemd-networkd, which flushes every
// routing policy entry it does not own, so anything installed once here has a
// life expectancy shorter than a day. The manual palliative applied during the
// 2026-10-26 outage (`ip route add 172.16.0.0/12 via 172.22.0.1 dev eth0 table
// 200`) dies exactly that way, and that is the whole reason the fix had to
// reach this loop rather than only the apply.
func TestReassertPutsBackADeletedPrivateExclusion(t *testing.T) {
	plan := planOn(t, healthyHost())
	// The rule is intact and so is one exclusion; 172.16.0.0/12 — the block
	// covering the runners' event Redis — is the one that went missing.
	stripped := &tableRunner{answers: map[string]string{
		"ip rule show": "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n" +
			"192.168.0.0/16 via 65.109.66.65 dev enp41s0 onlink \n" +
			"169.254.0.0/16 via 65.109.66.65 dev enp41s0 onlink \n",
		"docker inspect -f": plan.ContainerID + " " + plan.SourceIP + " ",
	}}
	restored, updated, gone, err := reassertPlan(context.Background(), stripped, *plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if gone || updated != nil {
		t.Fatalf("nothing moved here: updated=%v gone=%v", updated, gone)
	}
	// Spelled by excludeArgs, onlink included — the same code the apply used.
	// A re-assert that spelled it differently would silently install nothing on
	// this deployment's Hetzner-style layout.
	if !stripped.ran("ip route add 172.16.0.0/12 via 65.109.66.65 dev enp41s0 onlink table 200") {
		t.Fatalf("the deleted exclusion was not put back; calls: %v", stripped.calls)
	}
	if len(restored) != 1 || !strings.Contains(restored[0], "172.16.0.0/12") {
		t.Fatalf("restored = %v, want exactly the missing exclusion", restored)
	}
	// And the two that were still there were left alone.
	if stripped.ran("ip route add 192.168.0.0/16") || stripped.ran("ip route add 169.254.0.0/16") {
		t.Fatalf("reassert rewrote exclusions that were already in place: %v", stripped.calls)
	}
}

func TestReassertIsSilentWhenNothingWasFlushed(t *testing.T) {
	plan := planOn(t, healthyHost())
	intact := &tableRunner{answers: map[string]string{
		"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n" + privateRoutesInTable200,
		"docker inspect -f":       plan.ContainerID + " " + plan.SourceIP + " ",
	}}
	restored, updated, gone, err := reassertPlan(context.Background(), intact, *plan)
	if err != nil || len(restored) != 0 {
		t.Fatalf("restored=%v err=%v — an intact host must be left alone", restored, err)
	}
	if gone || updated != nil {
		t.Fatalf("an address that resolved unchanged must not be reported as moved or gone: updated=%v gone=%v", updated, gone)
	}
	if intact.ran("ip rule add") || intact.ran("ip route add") {
		t.Fatalf("reassert wrote to an intact host: %v", intact.calls)
	}
}

// THE FIX. A rule that still matches the RECORDED source IP can be sitting
// untouched in the kernel while that address now belongs to a different
// container — Docker handed 172.18.0.4 to whatever it started after the
// workspace container was recreated. ruleInstalled alone would call this
// host "intact" and never notice. Reassert has to re-resolve the container by
// its ContainerID on every pass, see the address moved, tear out the rule for
// the OLD address and install one for the new — and persist that, so the
// record does not go on lying to the next pass too.
func TestReassertReResolvesAndReplacesAStaleAddress(t *testing.T) {
	plan := planOn(t, healthyHost())
	moved := &tableRunner{answers: map[string]string{
		// The old rule is still installed and would read as "present" by
		// address alone — exactly the trap.
		"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n" + privateRoutesInTable200,
		// Same container id, a new address — what the runtime says NOW.
		"docker inspect -f": plan.ContainerID + " 172.18.0.9 ",
	}}
	restored, updated, gone, err := reassertPlan(context.Background(), moved, *plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if gone {
		t.Fatal("the container still resolves; it must not be reported as gone")
	}
	if updated == nil || updated.SourceIP != "172.18.0.9" {
		t.Fatalf("updated = %v, want a plan carrying the new address 172.18.0.9", updated)
	}
	if !moved.ran("ip rule del from 172.18.0.4/32 lookup 200 priority 5399") {
		t.Fatalf("the stale rule for 172.18.0.4 was not removed; calls: %v", moved.calls)
	}
	if !moved.ran("ip rule add from 172.18.0.9/32 lookup 200 priority 5399") {
		t.Fatalf("the new rule for 172.18.0.9 was not installed; calls: %v", moved.calls)
	}
	found := false
	for _, r := range restored {
		if strings.Contains(r, "172.18.0.9") {
			found = true
		}
	}
	if !found {
		t.Fatalf("restored = %v, want a note that the address moved", restored)
	}
}

// mustNotBeThisHost guards the initial apply (PlanExternalRoute); a reassert
// that re-resolves to a new address has to prove the same invariant again,
// or a container migrating to host networking would route the host itself
// the moment ReassertLoop's next pass notices the address moved.
func TestReassertRefusesWhenTheNewAddressIsThisHost(t *testing.T) {
	plan := planOn(t, healthyHost())
	migrated := &tableRunner{answers: map[string]string{
		"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n" + privateRoutesInTable200,
		// Same container id, but the address it now resolves to is one of
		// THIS HOST's own addresses (see healthyHost's "ip -4 -o addr show").
		"docker inspect -f":  plan.ContainerID + " 65.109.66.88 ",
		"ip -4 -o addr show": "1: lo    inet 127.0.0.1/8 scope host lo\n2: enp41s0    inet 65.109.66.88/32 scope global enp41s0\n",
	}}
	_, updated, gone, err := reassertPlan(context.Background(), migrated, *plan)
	if err == nil {
		t.Fatal("reassert must refuse when the re-resolved address is this host's own")
	}
	if updated != nil {
		t.Fatalf("updated = %v, want nil — a refused address must never be persisted", updated)
	}
	if gone {
		t.Fatal("this is a refusal, not a container that disappeared")
	}
	if migrated.ran("ip rule del") || migrated.ran("ip rule add") {
		t.Fatalf("no rule may be touched once the new address fails the this-host check: %v", migrated.calls)
	}
}

// The other half of the same fix, and the one that actually closes the
// security risk: a container that no longer resolves at all must not leave
// its /32 rule (or its state record) behind for some unrelated container to
// inherit later. Nothing gets reinstalled — there is nothing left to
// reassert — and the caller (Reassert) is told to clear the record.
func TestReassertClearsTheRecordWhenTheContainerIsGone(t *testing.T) {
	plan := planOn(t, healthyHost())
	gone := &tableRunner{
		answers: map[string]string{
			"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
			"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n" + privateRoutesInTable200,
		},
		errs: map[string]error{
			"docker inspect -f": fmt.Errorf("Error: No such object: %s", plan.ContainerID),
		},
	}
	restored, updated, isGone, err := reassertPlan(context.Background(), gone, *plan)
	if err != nil {
		t.Fatalf("reassert: %v", err)
	}
	if !isGone {
		t.Fatal("a container that no longer resolves must be reported as gone")
	}
	if updated != nil {
		t.Fatalf("updated = %v, want nil — there is no address left to persist", updated)
	}
	if !gone.ran("ip rule del from 172.18.0.4/32 lookup 200 priority 5399") {
		t.Fatalf("the orphaned rule was not removed; calls: %v", gone.calls)
	}
	if gone.ran("ip rule add") {
		t.Fatalf("a gone container must never get a rule reinstalled: %v", gone.calls)
	}
	if len(restored) == 0 {
		t.Fatal("restored should note the orphaned rule was cleaned up, for the journal")
	}
}

// The revert removes the rule FIRST, so that if removing the exclusions then
// fails the container is already off the tunnel rather than on it with half
// its pins gone. Same ordering usexit.go's revert makes, for the same reason.
func TestRevertRemovesTheRuleBeforeTheExclusions(t *testing.T) {
	// The control plane is what produces an exclusion now that the resolvers
	// no longer do; without it there is no second thing to be ordered against
	// and this test would pass vacuously.
	plan := planOnWithControlPlane(t, healthyHost(), "https://198.51.100.7:8443")
	r := &tableRunner{answers: map[string]string{
		"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n198.51.100.7/32 via 65.109.66.65 dev enp41s0 onlink \n",
	}}
	_ = revertExternalRoute(context.Background(), r, *plan, nil)
	var ruleAt, routeAt = -1, -1
	for i, c := range r.calls {
		if ruleAt < 0 && strings.HasPrefix(c, "ip rule del") {
			ruleAt = i
		}
		if routeAt < 0 && strings.HasPrefix(c, "ip route del") {
			routeAt = i
		}
	}
	if ruleAt < 0 || routeAt < 0 || ruleAt > routeAt {
		t.Fatalf("rule must be removed before exclusions; rule=%d route=%d calls=%v", ruleAt, routeAt, r.calls)
	}
}

// The probe has to run in the TARGET's network namespace. A probe on the
// network instead gets a fresh address that this /32 rule does not match, so
// it would faithfully report the host's egress no matter how well the rule
// worked — a confirmation that can never fail is not a confirmation.
func TestEgressProbeSharesTheTargetsNamespace(t *testing.T) {
	// The MARKED line containerEgressScript actually emits — not a bare
	// address. A test that asserted the bare form passed while the real probe
	// output was rejected on the production bare metal, so the fixture has to
	// be the real shape.
	r := &tableRunner{answers: map[string]string{
		"docker run": "AW_EGRESS https://1.1.1.1/cdn-cgi/trace 24.90.8.255\n",
	}}
	got := MeasureNetnsEgress(context.Background(), r, "docker", "e91aacf5a3a39a17")
	if got.IP != "24.90.8.255" {
		t.Fatalf("ip = %q (%s)", got.IP, got.Error)
	}

	// And a probe that printed something else must NOT be read as an address.
	noisy := &tableRunner{answers: map[string]string{"docker run": "curl: (28) timeout\n1.2.3.4\n"}}
	if got := MeasureNetnsEgress(context.Background(), noisy, "docker", "x"); got.IP != "" {
		t.Fatalf("an unmarked line was accepted as the answer: %q", got.IP)
	}
	if !r.ran("docker run --rm --network container:e91aacf5a3a39a17") {
		t.Fatalf("probe did not share the target's namespace: %v", r.calls)
	}
}

// A confirmation that cannot re-measure the host must FAIL, not pass. Silence
// about the host is precisely the half-measure the corrected invariant rules
// out.
func TestConfirmationFailsWhenTheHostCannotBeReMeasured(t *testing.T) {
	c := externalConfirmOnce(context.Background(), &tableRunner{}, ExternalRoutePlan{Runtime: "docker", ContainerID: "x"},
		externalConfirmSpec{hostBefore: ""})
	if c.ok {
		t.Fatal("confirmation passed without proving the host held")
	}
}

// A defaulted spec must never leave the confirmation window outliving the
// switch that is racing it, however little the caller supplied — the /link
// verb reaches this with whatever JSON gave it, which is routinely nothing.
func TestSpecDefaultsKeepConfirmInsideTheDeadman(t *testing.T) {
	for _, s := range []ExternalRouteSpec{
		{},
		{Deadman: 30 * time.Second, ConfirmTimeout: 120 * time.Second},
		{Deadman: 10 * time.Second, ConfirmTimeout: 10 * time.Second},
	} {
		got := s.withDefaults()
		if got.ConfirmTimeout >= got.Deadman {
			t.Fatalf("confirm %s must stay inside deadman %s", got.ConfirmTimeout, got.Deadman)
		}
		if got.Table != ExternalRouteTable || got.Priority != ExternalRoutePriority {
			t.Fatalf("defaults not applied: %+v", got)
		}
	}
}

// The chosen priority has to sit clear of the two ranges already in use on
// this host, and the reason is measured: tailscale owns 5210-5270 (use-exit
// works inside that at 5259-5265) and aw-vpn-hub owns 100-107 for its own
// clients. Colliding with either shadows a rule silently.
func TestPriorityDoesNotCollideWithTailscaleOrTheHub(t *testing.T) {
	if ExternalRoutePriority >= 5210 && ExternalRoutePriority <= 5270 {
		t.Fatalf("priority %d lands inside tailscale's 5210-5270 band", ExternalRoutePriority)
	}
	if ExternalRoutePriority >= 100 && ExternalRoutePriority <= 107 {
		t.Fatalf("priority %d lands inside aw-vpn-hub's client range", ExternalRoutePriority)
	}
	// It must still be evaluated before the kernel's main lookup, or the
	// container leaves via the host's uplink and nothing happens at all.
	if ExternalRoutePriority >= 32766 {
		t.Fatalf("priority %d is after the main table lookup", ExternalRoutePriority)
	}
}

// hostEgressForTest is the address the fixtures report as this machine's own.
// withStubbedHostEgress pins it so the confirmation can be exercised without a
// live HTTPS round trip to measure a public IP.
const hostEgressForTest = "65.109.66.88"

func withStubbedHostEgress(t *testing.T) {
	t.Helper()
	original := hostPublicIP
	hostPublicIP = func(context.Context) (Egress, error) {
		return Egress{IP: hostEgressForTest, Via: "test"}, nil
	}
	t.Cleanup(func() { hostPublicIP = original })
}

// BLOCKER B's signature, as a test — the failure that cost hours against a
// live tunnel because every route on this side is correct.
//
// MEASURED both ways on 2026-09-05 (see CryptokeyRoutingHint): with the peer's
// AllowedIPs covering our tunnel address, a routed container's public IP
// changed with policy routing ALONE and no SNAT of ours. With the AllowedIPs
// narrowed so it does NOT cover us, the routing is byte-for-byte identical,
// `ip route get` still picks the tunnel, and the container's egress simply
// dies.
//
// Two things must hold, and this asserts both: the apply is NOT confirmed
// (so it reverts rather than leaving a container black-holed), and the reason
// names the far end instead of sending the reader back through their own
// routes.
func TestEgressThatDidNotMoveIsUnconfirmedAndBlamesTheFarEnd(t *testing.T) {
	withStubbedHostEgress(t)
	plan := planOn(t, healthyHost())

	// The probe answers with the SAME address as before: routing installed,
	// nothing moved. This is what a peer rejecting our source looks like from
	// here when the packets are dropped after a successful handshake.
	r := healthyHost()
	r.answers["docker run --rm --network container:"] = "AW_EGRESS https://1.1.1.1/cdn-cgi/trace 65.109.66.88\n"

	got := externalConfirmOnce(context.Background(), r, *plan, externalConfirmSpec{
		hostBefore:      hostEgressForTest,
		containerBefore: "65.109.66.88",
	})
	if got.ok {
		t.Fatal("an apply whose container egress never changed was CONFIRMED — it would leave the rule installed with traffic black-holed")
	}
	if !strings.Contains(got.reason, "nothing moved") {
		t.Fatalf("reason does not state the symptom: %s", got.reason)
	}
	if !strings.Contains(got.reason, "AllowedIPs") {
		t.Fatalf("reason does not name the measured cause, so the next person re-derives it from scratch: %s", got.reason)
	}
}

// The same hint has to reach the OTHER shape of this failure: a probe that
// times out entirely rather than returning the old address. Against the live
// hub that is what actually happened — the container's curl returned nothing
// at all — so a hint attached only to the "unchanged" branch would have missed
// the real run.
func TestAnEgressThatCannotBeMeasuredAlsoBlamesTheFarEnd(t *testing.T) {
	withStubbedHostEgress(t)
	plan := planOn(t, healthyHost())
	r := healthyHost()
	r.errs = map[string]error{"docker run --rm --network container:": fmt.Errorf("exit status 28")}

	got := externalConfirmOnce(context.Background(), r, *plan, externalConfirmSpec{
		hostBefore:      hostEgressForTest,
		containerBefore: "65.109.66.88",
	})
	if got.ok {
		t.Fatal("an unmeasurable egress was confirmed")
	}
	if !strings.Contains(got.reason, "AllowedIPs") {
		t.Fatalf("the timeout branch does not carry the cause: %s", got.reason)
	}
}
