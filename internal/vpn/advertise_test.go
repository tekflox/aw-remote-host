package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// forwardingOn is what `sysctl -n <key>` answers on a kernel that will forward.
const forwardingOn = "1\n"

// advertiseRunner is a recordingRunner primed to look like a healthy, enrolled
// Linux gate: forwarding enables, the route to the internet is eth0, and
// tailscale reports the node afterwards.
func advertiseRunner() *recordingRunner {
	r := newRecordingRunner()
	r.answer("sysctl -n net.ipv4.ip_forward", forwardingOn, nil)
	r.answer("sysctl -n net.ipv6.conf.all.forwarding", forwardingOn, nil)
	r.answer("ip route get 1.1.1.1", "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.44\n", nil)
	r.answer("tailscale debug prefs", `{"ControlURL":"https://headscale.example.com","Hostname":"aw-surface-wsl","AdvertiseRoutes":["0.0.0.0/0","::/0"]}`, nil)
	r.answer("tailscale status --json", `{"BackendState":"Running","Version":"1.102.3","Self":{"ID":"2","HostName":"aw-surface-wsl","DNSName":"aw-surface-wsl.mesh.example.com.","OS":"linux","TailscaleIPs":["100.64.0.2"],"Online":true,"ExitNodeOption":false},"CurrentTailnet":{"Name":"headscale.example.com","MagicDNSSuffix":"mesh.example.com"},"Peer":{}}`, nil)
	return r
}

func wslEligibility() Eligibility { return Resolve(surfaceWSL()) }

// THE INVARIANT. Offering is not using, and it is proved on every call rather
// than asserted in a comment: the route to the public internet is measured
// before and after, and a change is reported as evidence, not swallowed.
func TestAdvertiseDoesNotMoveTheAdvertisersOwnRoute(t *testing.T) {
	r := advertiseRunner()
	res, err := Advertise(context.Background(), r, r, wslEligibility(), true, nil)
	if err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	if res.RouteBefore != "eth0" || res.RouteAfter != "eth0" {
		t.Fatalf("route moved: %q -> %q", res.RouteBefore, res.RouteAfter)
	}
	if !res.RouteUnchanged() {
		t.Fatal("RouteUnchanged disagrees with the two measurements it is derived from")
	}
	// Nothing in the sequence may reach for the machinery that DOES move a
	// route. Advertising needs no dead-man's switch precisely because it
	// cannot strand the host, and a stray call here would quietly earn it one.
	for _, c := range r.calls {
		if strings.Contains(c, "--exit-node=") || strings.HasPrefix(c, "ip rule") {
			t.Fatalf("advertising touched the selection path: %q", c)
		}
	}
}

// Two measurements that never happened are not evidence of a change. A host
// with no `ip` at all must read as unknown, not as a broken invariant.
func TestRouteUnchangedTreatsAnUnmeasuredRouteAsUnknownNotAsAChange(t *testing.T) {
	if !(AdvertiseResult{}).RouteUnchanged() {
		t.Fatal("no measurement must not be reported as a moved route")
	}
	if !(AdvertiseResult{RouteBefore: "eth0"}).RouteUnchanged() {
		t.Fatal("one measurement is still not two")
	}
	if (AdvertiseResult{RouteBefore: "eth0", RouteAfter: "tailscale0"}).RouteUnchanged() {
		t.Fatal("two measurements that disagree ARE a change")
	}
}

// Order matters and it is not cosmetic: advertising before the kernel will
// forward publishes a route this host drops, and the control plane could
// approve a gate that cannot carry anything in that window.
func TestForwardingIsEnabledBeforeTheRouteIsAdvertised(t *testing.T) {
	r := advertiseRunner()
	if _, err := Advertise(context.Background(), r, r, wslEligibility(), true, nil); err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	forward, advertise := -1, -1
	for i, c := range r.calls {
		if c == "sysctl -w net.ipv4.ip_forward=1" && forward < 0 {
			forward = i
		}
		if strings.Contains(c, "--advertise-exit-node=true") {
			advertise = i
		}
	}
	if forward < 0 || advertise < 0 {
		t.Fatalf("missing a step: forward=%d advertise=%d in %v", forward, advertise, r.calls)
	}
	if forward > advertise {
		t.Fatal("the route was advertised before the kernel would forward it")
	}
}

// A kernel that accepts `sysctl -w` and changes nothing is the exact
// looks-armed-forwards-nothing failure this feature exists to remove, and a
// read-only /proc/sys in a container is where it really happens. Refusing
// BEFORE tailscale is told anything means there is nothing to undo.
func TestAKernelThatWillNotForwardIsRefusedBeforeAnythingIsAdvertised(t *testing.T) {
	r := advertiseRunner()
	r.answer("sysctl -n net.ipv4.ip_forward", "0\n", nil)

	res, err := Advertise(context.Background(), r, r, wslEligibility(), true, nil)
	if err != nil {
		t.Fatalf("an unforwardable kernel is a refusal, not an error: %v", err)
	}
	if !res.Refused {
		t.Fatal("a kernel that drops forwarded packets must not be advertised")
	}
	if !strings.Contains(res.Refusal, "ip_forward") {
		t.Fatalf("the refusal must name the sysctl to fix: %q", res.Refusal)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "advertise-exit-node") {
			t.Fatalf("advertised anyway: %q", c)
		}
	}
}

// Same shape vpn_bootstrap and vpn_use_exit use: a host that cannot do this
// answers with a refusal and a NIL error, so "not able to" and "could not be
// asked" never arrive looking identical.
func TestAnIneligibleHostRefusesWithItsOwnSentenceAndTouchesNothing(t *testing.T) {
	r := advertiseRunner()
	res, err := Advertise(context.Background(), r, r, Resolve(macHome()), true, nil)
	if err != nil {
		t.Fatalf("refusal must not be an error: %v", err)
	}
	if !res.Refused || res.Refusal == "" {
		t.Fatalf("expected a refusal with a reason, got %+v", res)
	}
	if res.Warning != "" {
		t.Fatalf("a refusal must not also carry a warning: %q", res.Warning)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "sysctl -w") || strings.Contains(c, "advertise-exit-node") {
			t.Fatalf("an ineligible host was changed anyway: %q", c)
		}
	}
}

// The permission and its price travel together, all the way out. A caller
// that got `advertising: true` with no warning would have no way to warn the
// person who later picks this gate.
func TestASuccessfulOfferStillCarriesTheWarning(t *testing.T) {
	r := advertiseRunner()
	res, err := Advertise(context.Background(), r, r, wslEligibility(), true, nil)
	if err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	if !res.Advertising {
		t.Fatal("prefs say 0.0.0.0/0 is advertised; the result must agree")
	}
	if !strings.Contains(res.Warning, "relay") {
		t.Fatalf("the cost must survive a successful call: %q", res.Warning)
	}
}

// `offers_exit` false right after advertising is the NORMAL answer — nobody
// has approved anything yet. Reporting it as true from a successful
// `tailscale set` is the single most tempting lie this file could tell.
func TestOffersExitIsReadFromTailscaleNotInferredFromTheSetSucceeding(t *testing.T) {
	r := advertiseRunner()
	res, err := Advertise(context.Background(), r, r, wslEligibility(), true, nil)
	if err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	if res.OffersExit {
		t.Fatal("nothing approved this route; OffersExit must stay false")
	}
	if res.NodeName != "aw-surface-wsl" {
		t.Fatalf("node_name = %q, want the name tailscale reports", res.NodeName)
	}
}

// Withdrawing is the undo and must not need the eligibility gate: a host that
// has BECOME ineligible (its kernel changed, it moved into WSL) is exactly the
// one that most needs to stop offering.
func TestWithdrawingNeedsNoEligibilityAndLeavesForwardingAlone(t *testing.T) {
	r := advertiseRunner()
	res, err := Advertise(context.Background(), r, r, Resolve(macHome()), false, nil)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if res.Refused {
		t.Fatal("an undo that can refuse fails exactly when it is most needed")
	}
	if res.Warning != "" {
		t.Fatalf("nothing is being offered, so there is no cost to state: %q", res.Warning)
	}
	var sawWithdraw bool
	for _, c := range r.calls {
		if strings.Contains(c, "--advertise-exit-node=false") {
			sawWithdraw = true
		}
		// install.sh owns that file, and ip_forward on a machine nobody
		// selects changes nothing about its own traffic.
		if strings.Contains(c, "sysctl -w") || strings.Contains(c, sysctlDropIn) {
			t.Fatalf("withdrawing edited forwarding state: %q", c)
		}
	}
	if !sawWithdraw {
		t.Fatalf("nothing withdrew the advertisement: %v", r.calls)
	}
}

// A `tailscale set` that genuinely fails is a real error, not a refusal: the
// host CAN do this and something went wrong, which needs a different reaction
// than "this machine is not able to".
func TestAFailingTailscaleSetIsAnErrorNotARefusal(t *testing.T) {
	r := advertiseRunner()
	r.answer("tailscale set --advertise-exit-node=true", "Access denied", errors.New("exit status 1"))

	_, err := Advertise(context.Background(), r, r, wslEligibility(), true, nil)
	if err == nil {
		t.Fatal("a daemon that rejected the preference must not read as success")
	}
	if !strings.Contains(err.Error(), "Access denied") {
		t.Fatalf("the daemon's own words must survive: %v", err)
	}
}
