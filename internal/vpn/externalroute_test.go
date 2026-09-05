package vpn

import (
	"context"
	"fmt"
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

func (s *tableRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	full := strings.TrimSpace(name + " " + strings.Join(args, " "))
	s.calls = append(s.calls, full)
	for prefix, err := range s.errs {
		if strings.HasPrefix(full, prefix) {
			return "", err
		}
	}
	for prefix, out := range s.answers {
		if strings.HasPrefix(full, prefix) {
			return out, nil
		}
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
func healthyHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"ip -V":                   "ip utility, iproute2-6.1.0",
		"docker --version":        "Docker version 27.0.0",
		"docker inspect -f":       "e91aacf5a3a39a17 172.18.0.4 ",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n172.18.0.0/16 dev br-2c9cd32e2d2f scope link \n",
		"ip route show default":   "default via 65.109.66.65 dev enp41s0 proto static onlink \n",
		"ip -4 -o addr show":      "1: lo    inet 127.0.0.1/8 scope host lo\n2: enp41s0    inet 65.109.66.88/32 scope global enp41s0\n",
		"docker exec e91aacf5a3a39a17 cat /etc/resolv.conf": "nameserver 127.0.0.11\n",
		"cat /run/systemd/resolve/resolv.conf":              "nameserver 185.12.64.1\nnameserver 185.12.64.2\n",
	}}
}

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
	if len(plan.Exclusions) != 1 || plan.Exclusions[0] != "198.51.100.7/32" {
		t.Fatalf("the control plane is not held outside the tunnel: %v", plan.Exclusions)
	}
	// And with no control plane there is nothing left to pin at all — the
	// resolvers used to fill this list, and no longer do.
	if bare := planOn(t, healthyHost()); len(bare.Exclusions) != 0 {
		t.Fatalf("something other than the control plane is still being excluded: %v", bare.Exclusions)
	}
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
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n",
	}}
	if err := applyExternalRoute(context.Background(), r, *plan); err != nil {
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
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n",
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

func TestReassertIsSilentWhenNothingWasFlushed(t *testing.T) {
	plan := planOn(t, healthyHost())
	intact := &tableRunner{answers: map[string]string{
		"ip rule show":            "5399:\tfrom 172.18.0.4 lookup 200\n",
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n",
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
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n",
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
		"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n",
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
			"ip route show table 200": "default via 10.8.0.2 dev wg0 \n185.12.64.1/32 via 65.109.66.65 dev enp41s0 onlink \n185.12.64.2/32 via 65.109.66.65 dev enp41s0 onlink \n",
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
	got := measureNetnsEgress(context.Background(), r, "docker", "e91aacf5a3a39a17")
	if got.IP != "24.90.8.255" {
		t.Fatalf("ip = %q (%s)", got.IP, got.Error)
	}

	// And a probe that printed something else must NOT be read as an address.
	noisy := &tableRunner{answers: map[string]string{"docker run": "curl: (28) timeout\n1.2.3.4\n"}}
	if got := measureNetnsEgress(context.Background(), noisy, "docker", "x"); got.IP != "" {
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
