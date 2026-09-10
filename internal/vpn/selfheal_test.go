package vpn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The seam these tests use is healTunnelPlan — the same seam reassertPlan is
// tested through, and for the same reason: it only ever talks to Runner, so a
// fixture is a table of command output and nothing on the machine running
// `go test` is read or written. The decision half (hysteresis, backoff) is
// tested separately through tunnelHealer.decide, because proving "one stale
// pass does not repair, two do" needs a SEQUENCE, and a test that had to run a
// real 30s ticker to see one would not be run.

// healthyTunnel is a machine where the tunnel really is working: the device is
// there, it carries the configured peer, the default is in table 200 and the
// peer handshaked seconds ago.
func healthyTunnel(peerKey string, handshakeAt int64) *tableRunner {
	return &tableRunner{answers: map[string]string{
		"wg show interfaces":             "wg0\n",
		"wg show wg0 peers":              peerKey + "\n",
		"wg show wg0 latest-handshakes":  fmt.Sprintf("%s\t%d\n", peerKey, handshakeAt),
		"ip route show table 200":        "default via 10.8.0.2 dev wg0 \n",
		"ip -o -4 route show table main": "default via 172.18.0.1 dev eth0 \n",
	}}
}

// healPlanOn builds the plan a recorded dial would rebuild, and makes its
// ConfPath look present without writing to /etc/wireguard.
func healPlanOn(t *testing.T) *ExternalUpPlan {
	t.Helper()
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))
	withConfPresent(t, true)
	return plan
}

// withConfPresent pins the on-disk config check. It is the one thing
// healTunnelPlan reads that is not a shellout, and it is indirected exactly so
// these tests do not need a real 0600 file in /etc/wireguard.
func withConfPresent(t *testing.T, present bool) {
	t.Helper()
	original := confPresent
	confPresent = func(string) bool { return present }
	t.Cleanup(func() { confPresent = original })
}

// A tunnel that is working is left completely alone. This is the fixture that
// matters most: the loop runs every 30s forever on every linked host, and a
// false positive here does not fail a test somewhere — it drops every
// connection on a healthy VPN, at 3am, unattended.
func TestHealLeavesAHealthyTunnelAlone(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	r := healthyTunnel(plan.PeerPublicKey, now.Add(-20*time.Second).Unix())

	got := healTunnelPlan(context.Background(), r, *plan, now)
	if got.verdict != healHealthy {
		t.Fatalf("verdict = %v (%s), want healHealthy", got.verdict, got.reason)
	}
	if got.handshakeAge != 20*time.Second {
		t.Fatalf("handshake age = %s, want 20s", got.handshakeAge)
	}
	if r.ran("wg-quick") || r.ran("ip route add") || r.ran("ip route replace") {
		t.Fatalf("a healthy tunnel was written to: %v", r.calls)
	}
}

// ONE STALE READING IS NOT ENOUGH. Re-dialling drops every connection in
// flight, so the threshold that can be a transient gets hysteresis while the
// unambiguous ones do not. The second consecutive stale pass repairs.
func TestStaleHandshakeRepairsOnlyOnTheSecondConsecutivePass(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	stale := healthyTunnel(plan.PeerPublicKey, now.Add(-10*time.Minute).Unix())

	assessment := healTunnelPlan(context.Background(), stale, *plan, now)
	if assessment.verdict != healStale {
		t.Fatalf("verdict = %v (%s), want healStale", assessment.verdict, assessment.reason)
	}

	h := &tunnelHealer{}
	if d := h.decide(assessment, now); d.repair {
		t.Fatalf("the FIRST stale pass must not re-dial: %s", d.note)
	}
	second := now.Add(SelfHealInterval)
	if d := h.decide(assessment, second); !d.repair {
		t.Fatalf("the SECOND consecutive stale pass must re-dial: %s", d.note)
	}
}

// A handshake just inside the threshold is not stale. The boundary is asserted
// because the whole value of 180s rests on a keepalive-configured peer
// renegotiating well under it — a check that fired at 120s would call every
// idle-but-healthy tunnel dead.
func TestHandshakeInsideTheThresholdIsHealthy(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)

	fresh := healthyTunnel(plan.PeerPublicKey, now.Add(-HandshakeStaleAfter).Unix())
	if got := healTunnelPlan(context.Background(), fresh, *plan, now); got.verdict != healHealthy {
		t.Fatalf("a handshake exactly %s old is not yet stale: %v (%s)", HandshakeStaleAfter, got.verdict, got.reason)
	}
	past := healthyTunnel(plan.PeerPublicKey, now.Add(-HandshakeStaleAfter-time.Second).Unix())
	if got := healTunnelPlan(context.Background(), past, *plan, now); got.verdict != healStale {
		t.Fatalf("a handshake past %s is stale: %v (%s)", HandshakeStaleAfter, got.verdict, got.reason)
	}
}

// A peer that has NEVER handshaked is stale, not broken — deliberately. The
// device, the peer and the default are all in place, which is exactly what a
// tunnel dialled seconds ago by an interactive `vpn external-up` looks like
// before its first handshake lands. Repairing that on the first pass would
// have this loop fighting a human at the console.
func TestHandshakeNeverIsStaleNotBroken(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	never := healthyTunnel(plan.PeerPublicKey, 0)

	got := healTunnelPlan(context.Background(), never, *plan, now)
	if got.verdict != healStale {
		t.Fatalf("verdict = %v (%s), want healStale", got.verdict, got.reason)
	}
	if !got.handshakeNever {
		t.Fatal("handshakeNever must be set — never and 'stale by some age' are different sentences on screen")
	}
	if d := (&tunnelHealer{}).decide(got, now); d.repair {
		t.Fatal("a never-handshaked tunnel must still wait one pass, like any other stale reading")
	}
}

// A missing device is unambiguous and gets repaired on the FIRST pass — the
// same rule Reassert applies to a flushed rule. There is nothing transient
// about an interface that is not there.
func TestMissingDeviceRepairsImmediately(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	gone := healthyTunnel(plan.PeerPublicKey, now.Unix())
	gone.answers["wg show interfaces"] = "\n"

	got := healTunnelPlan(context.Background(), gone, *plan, now)
	if got.verdict != healBroken {
		t.Fatalf("verdict = %v (%s), want healBroken", got.verdict, got.reason)
	}
	if d := (&tunnelHealer{}).decide(got, now); !d.repair {
		t.Fatalf("a missing device must repair on the first pass: %s", d.note)
	}
}

// The interface exists but belongs to a DIFFERENT profile — someone else's
// wg0, or the leftovers of a previous dial. Repairing converges it onto the
// config this host actually recorded, and it too is unambiguous.
func TestWrongPeerOnTheInterfaceRepairsImmediately(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	other := healthyTunnel(plan.PeerPublicKey, now.Unix())
	other.answers["wg show wg0 peers"] = "aDifferentPeersPublicKeyEntirely0000000000=\n"

	got := healTunnelPlan(context.Background(), other, *plan, now)
	if got.verdict != healBroken {
		t.Fatalf("verdict = %v (%s), want healBroken", got.verdict, got.reason)
	}
	if !strings.Contains(got.reason, "peer") {
		t.Fatalf("reason = %q, want it to name the peer as the problem", got.reason)
	}
}

// The tunnel is up and carrying the right peer, and the routing that is the
// entire point of it has been flushed out of table 200 — the same daily
// systemd-networkd restart Reassert exists for, hitting the tunnel's own
// default rather than the policy rule.
func TestMissingDefaultInTableRepairsImmediately(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	flushed := healthyTunnel(plan.PeerPublicKey, now.Unix())
	flushed.answers["ip route show table 200"] = "\n"

	got := healTunnelPlan(context.Background(), flushed, *plan, now)
	if got.verdict != healBroken {
		t.Fatalf("verdict = %v (%s), want healBroken", got.verdict, got.reason)
	}
	if d := (&tunnelHealer{}).decide(got, now); !d.repair {
		t.Fatalf("a missing default must repair on the first pass: %s", d.note)
	}
}

// THE ONE THAT WOULD HAVE BROKEN PRODUCTION. `sudo -n wg` being refused says
// NOTHING about the peer, and a loop that read it as "down" would tear down a
// perfectly healthy tunnel on every host where the daemon loses its privilege
// — turning a self-heal into the outage it was written to prevent. Every
// shellout in the pass is checked, because a refusal at any one of them is the
// same non-answer.
func TestARefusedShelloutIsUnknownAndNeverRepairs(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	refusal := fmt.Errorf("sudo: a password is required")

	for _, refused := range []string{
		"wg show interfaces",
		"wg show wg0 peers",
		"wg show wg0 latest-handshakes",
		"ip route show table 200",
	} {
		r := healthyTunnel(plan.PeerPublicKey, now.Unix())
		r.errs = map[string]error{refused: refusal}

		got := healTunnelPlan(context.Background(), r, *plan, now)
		if got.verdict != healUnknown {
			t.Fatalf("%q refused: verdict = %v (%s), want healUnknown", refused, got.verdict, got.reason)
		}
		// Two passes running, because a single skipped pass would also be the
		// answer if the hysteresis counter were merely being incremented.
		h := &tunnelHealer{}
		if d := h.decide(got, now); d.repair {
			t.Fatalf("%q refused: repaired on pass 1 — a refusal is not evidence", refused)
		}
		if d := h.decide(got, now.Add(SelfHealInterval)); d.repair {
			t.Fatalf("%q refused: repaired on pass 2 — a refusal never accumulates into a repair", refused)
		}
	}
}

// A refused pass must not RESET the stale counter either. Otherwise an
// intermittently-refused `wg` — one stale pass, one refusal, one stale pass —
// would postpone a real repair indefinitely, which is the same tunnel-stays-
// down outcome by a quieter route.
func TestARefusalDoesNotResetTheStaleCounter(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)

	stale := healTunnelPlan(context.Background(), healthyTunnel(plan.PeerPublicKey, now.Add(-10*time.Minute).Unix()), *plan, now)
	refusedRunner := healthyTunnel(plan.PeerPublicKey, now.Unix())
	refusedRunner.errs = map[string]error{"wg show wg0 latest-handshakes": fmt.Errorf("sudo: a password is required")}
	unknown := healTunnelPlan(context.Background(), refusedRunner, *plan, now)

	h := &tunnelHealer{}
	h.decide(stale, now)                              // pass 1: stale, waits
	h.decide(unknown, now.Add(SelfHealInterval))      // pass 2: could not measure
	d := h.decide(stale, now.Add(2*SelfHealInterval)) // pass 3: stale again
	if !d.repair {
		t.Fatalf("the second stale reading must still repair despite the refusal in between: %s", d.note)
	}
}

// A HEALTHY TUNNEL RESETS THE STALE COUNTER. One stale pass followed by a
// fresh handshake must not leave a half-armed trigger that the next single
// stale pass, minutes later, completes — that would repair on evidence
// gathered either side of a known-good measurement.
func TestAHealthyPassClearsTheStaleCounter(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	stale := healTunnelPlan(context.Background(), healthyTunnel(plan.PeerPublicKey, now.Add(-10*time.Minute).Unix()), *plan, now)
	healthy := healTunnelPlan(context.Background(), healthyTunnel(plan.PeerPublicKey, now.Unix()), *plan, now)

	h := &tunnelHealer{}
	h.decide(stale, now)
	h.decide(healthy, now.Add(SelfHealInterval))
	if d := h.decide(stale, now.Add(2*SelfHealInterval)); d.repair {
		t.Fatal("a fresh handshake in between must reset the counter — this repaired on one stale pass")
	}
}

// THE BACKOFF IS NOT OPTIONAL. `wg-quick up` returns 0 with an unreachable
// peer, and every cycle destroys and rebuilds table 200. Without this, a host
// whose uplink is genuinely down rebuilds its routing every 30s forever while
// achieving nothing.
func TestBackoffHoldsOffRepeatRepairsAndDoublesToACeiling(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	broken := healTunnelPlan(context.Background(), func() *tableRunner {
		r := healthyTunnel(plan.PeerPublicKey, now.Unix())
		r.answers["wg show interfaces"] = "\n"
		return r
	}(), *plan, now)

	h := &tunnelHealer{}
	if d := h.decide(broken, now); !d.repair {
		t.Fatal("the first broken pass repairs")
	}
	h.repaired(now)
	if h.backoff != healBackoffMin {
		t.Fatalf("backoff = %s, want the %s floor after one repair", h.backoff, healBackoffMin)
	}

	// The very next tick, and every tick inside the window, must decline.
	for _, at := range []time.Duration{SelfHealInterval, healBackoffMin - time.Second} {
		if d := h.decide(broken, now.Add(at)); d.repair {
			t.Fatalf("repaired again %s later, inside the %s backoff", at, healBackoffMin)
		}
	}
	// And the tick after the window is allowed through.
	after := now.Add(healBackoffMin + time.Second)
	if d := h.decide(broken, after); !d.repair {
		t.Fatalf("the backoff expired and this still declined: %s", d.note)
	}
	h.repaired(after)
	if h.backoff != 2*healBackoffMin {
		t.Fatalf("backoff = %s, want it doubled to %s", h.backoff, 2*healBackoffMin)
	}

	// It doubles to a ceiling and stops there rather than growing forever.
	at := after
	for i := 0; i < 10; i++ {
		at = at.Add(healBackoffMax + time.Second)
		h.decide(broken, at)
		h.repaired(at)
	}
	if h.backoff != healBackoffMax {
		t.Fatalf("backoff = %s, want it capped at %s", h.backoff, healBackoffMax)
	}
}

// A FRESH HANDSHAKE IS THE ONLY THING THAT CLEARS THE BACKOFF — not a
// `wg-quick up` that returned 0, which proves nothing about the peer.
func TestAFreshHandshakeClearsTheBackoff(t *testing.T) {
	plan := healPlanOn(t)
	now := time.Unix(1788318109, 0)
	healthy := healTunnelPlan(context.Background(), healthyTunnel(plan.PeerPublicKey, now.Unix()), *plan, now)

	h := &tunnelHealer{backoff: healBackoffMax, nextRepairAt: now.Add(healBackoffMax), consecutiveStale: 1}
	h.decide(healthy, now)
	if h.backoff != 0 || !h.nextRepairAt.IsZero() || h.consecutiveStale != 0 {
		t.Fatalf("a fresh handshake left backoff=%s nextRepairAt=%v stale=%d, want all cleared", h.backoff, h.nextRepairAt, h.consecutiveStale)
	}
}

// A CONFIG THAT IS GONE WITH A RECORD STILL PRESENT is a real anomaly, not
// something to re-dial: wg-quick has nothing to be pointed at. It is reported
// loudly and never repaired, so it cannot become a failure loop — the same
// shape as reassertPlan's `gone` branch.
func TestMissingConfigIsAnAnomalyAndNeverRepairs(t *testing.T) {
	plan := healPlanOn(t)
	withConfPresent(t, false)
	now := time.Unix(1788318109, 0)
	r := healthyTunnel(plan.PeerPublicKey, now.Unix())

	got := healTunnelPlan(context.Background(), r, *plan, now)
	if got.verdict != healConfGone {
		t.Fatalf("verdict = %v (%s), want healConfGone", got.verdict, got.reason)
	}
	if !strings.Contains(got.reason, plan.ConfPath) {
		t.Fatalf("reason = %q, want it to name the missing config path", got.reason)
	}
	if r.ran("wg") || r.ran("ip") {
		t.Fatalf("nothing should be measured once the config is known to be gone: %v", r.calls)
	}
	h := &tunnelHealer{}
	for i := 0; i < 3; i++ {
		if d := h.decide(got, now.Add(time.Duration(i)*SelfHealInterval)); d.repair {
			t.Fatal("a missing config must never be re-dialled — there is nothing to dial from")
		}
	}
}

// NO TUNNEL RECORDED IS A SILENT NO-OP, and it is the overwhelmingly common
// case: every host that has never dialled, and every non-Linux host, which
// cannot dial at all. A pass that shelled out — or narrated — here would run
// every 30s on every machine in the fleet.
func TestPassIsASilentNoOpWhenNoTunnelIsRecorded(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)

	r := &tableRunner{answers: map[string]string{}}
	restored, err := (&tunnelHealer{}).pass(context.Background(), r, time.Unix(1788318109, 0))
	if err != nil {
		t.Fatalf("a host with no recorded tunnel is normal, not an error: %v", err)
	}
	if len(restored) != 0 {
		t.Fatalf("restored = %v, want nothing", restored)
	}
	if len(r.calls) != 0 {
		t.Fatalf("a host with no recorded tunnel was shelled out to: %v", r.calls)
	}
}

// The end-to-end repair, through pass(): a recorded tunnel whose device is
// gone is re-dialled from its config on disk — and it is re-dialled with
// applyExternalUp's own writes, never through ExternalUp, which would arm the
// dead-man's switch and try to reach the network on a host that has none.
func TestPassRedialsABrokenTunnelFromItsRecordedConfig(t *testing.T) {
	plan := healPlanOn(t)
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save tunnel: %v", err)
	}
	now := time.Unix(1788318109, 0)
	r := healthyTunnel(plan.PeerPublicKey, now.Unix())
	r.answers["wg show interfaces"] = "\n"

	restored, err := (&tunnelHealer{}).pass(context.Background(), r, now)
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(restored) != 1 || !strings.Contains(restored[0], plan.Iface) {
		t.Fatalf("restored = %v, want one line naming %s", restored, plan.Iface)
	}
	if !r.ran("wg-quick up " + plan.ConfPath) {
		t.Fatalf("the tunnel was not brought up from its recorded config: %v", r.calls)
	}
	if callIndex(r, "ip route replace default") < 0 {
		t.Fatalf("table %d was not rebuilt: %v", plan.Table, r.calls)
	}
	// The three things ExternalUp does that applyExternalUp does not, all of
	// which need the internet on a host whose problem is that it has none.
	for _, forbidden := range []string{"docker pull", "podman pull", "curl", "sh -c"} {
		if r.ran(forbidden) {
			t.Fatalf("the heal ran %q — the repair must be applyExternalUp and nothing else: %v", forbidden, r.calls)
		}
	}
}

// A repair that FAILS is reported and still moves the backoff on. Reporting is
// the point — this is the line that would have existed on the night nobody
// could explain — and advancing the backoff is what stops a host with a dead
// uplink from rebuilding its routing table every 30s until morning.
func TestAFailedRepairIsReportedAndStillArmsTheBackoff(t *testing.T) {
	plan := healPlanOn(t)
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save tunnel: %v", err)
	}
	now := time.Unix(1788318109, 0)
	r := healthyTunnel(plan.PeerPublicKey, now.Unix())
	r.answers["wg show interfaces"] = "\n"
	r.errs = map[string]error{"wg-quick up": fmt.Errorf("Line unrecognized: `Table=off'")}

	h := &tunnelHealer{}
	restored, err := h.pass(context.Background(), r, now)
	if err == nil {
		t.Fatal("a failed re-dial must be reported, not swallowed")
	}
	if len(restored) != 0 {
		t.Fatalf("restored = %v, want nothing — nothing was restored", restored)
	}
	if h.backoff != healBackoffMin {
		t.Fatalf("backoff = %s, want the %s floor armed even though the repair failed", h.backoff, healBackoffMin)
	}
}

// A HEALTHY PASS SAYS NOTHING. This loop runs every 30s forever on every
// linked host; one narrating a healthy tunnel teaches everybody to filter its
// output, taking the one line that mattered with it.
func TestAHealthyPassReportsNothing(t *testing.T) {
	plan := healPlanOn(t)
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save tunnel: %v", err)
	}
	now := time.Unix(1788318109, 0)

	restored, err := (&tunnelHealer{}).pass(context.Background(), healthyTunnel(plan.PeerPublicKey, now.Unix()), *&now)
	if err != nil || len(restored) != 0 {
		t.Fatalf("restored = %v, err = %v — a healthy tunnel produces no report at all", restored, err)
	}
}

// --- the dead-man's switch: risk #2 from the design -----------------------------

// AN ARMED DEAD-MAN MEANS A DIAL IS IN FLIGHT, AND THE WHOLE PASS IS SKIPPED.
//
// This is the one branch that can make the self-heal actively destructive
// rather than merely unhelpful, which is why it gets a test of its own. During
// the seconds of an interactive `vpn external-up`, the routing is half-applied
// BY DESIGN: the interface may not be there yet, the default may not be in the
// table yet. Every predicate in healTunnelPlan would read that as "broken", and
// the loop would run applyExternalUp straight over the top of a dial a human is
// watching — racing it, and doing so under a dead-man armed against a tunnel
// state the loop is busy changing underneath it.
//
// The fixture is a BROKEN tunnel on purpose. A healthy one would be left alone
// whether the switch is honoured or not, so the test would pass either way and
// prove nothing — which is exactly how this branch shipped unproven the first
// time. Zero shellouts is the assertion, mirroring
// TestPassIsASilentNoOpWhenNoTunnelIsRecorded.
func TestAnArmedDeadmanSkipsTheWholePass(t *testing.T) {
	plan := healPlanOn(t) // sets HOME to a temp dir; the switch lands there too
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save tunnel: %v", err)
	}
	now := time.Unix(1788318109, 0)

	broken := healthyTunnel(plan.PeerPublicKey, now.Unix())
	broken.answers["wg show interfaces"] = "\n" // the device is GONE — repair-worthy

	// Control, first: with nothing armed this fixture unambiguously repairs. If
	// this half ever stops holding, the assertion below is vacuous and the test
	// is worthless — so it is proven here rather than assumed.
	control, err := (&tunnelHealer{}).pass(context.Background(), broken, now)
	if err != nil {
		t.Fatalf("control pass: %v", err)
	}
	if len(control) == 0 || !broken.ran("wg-quick up") {
		t.Fatalf("the fixture must repair when nothing is armed, or this test proves nothing: restored=%v calls=%v", control, broken.calls)
	}

	// Now arm a real detached switch — the same Arm/ArmSpec path a live
	// `vpn external-up` uses, not a hand-written state file — and try again
	// with a fresh runner.
	armForTest(t, time.Minute)
	if d, err := LoadDeadman(); err != nil || d == nil || d.Fired() {
		t.Fatalf("the fixture failed to arm a live switch: d=%+v err=%v", d, err)
	}

	guarded := healthyTunnel(plan.PeerPublicKey, now.Unix())
	guarded.answers["wg show interfaces"] = "\n"

	restored, err := (&tunnelHealer{}).pass(context.Background(), guarded, now)
	if err != nil {
		t.Fatalf("a skipped pass is not an error: %v", err)
	}
	if len(restored) != 0 {
		t.Fatalf("restored = %v, want nothing — a dial is in flight", restored)
	}
	if len(guarded.calls) != 0 {
		t.Fatalf("the pass shelled out while a dial was in flight: %v", guarded.calls)
	}
}

// THE OTHER HALF OF THE SAME BRANCH, and the reason the check is `!d.Fired()`
// rather than merely `d != nil`. A switch whose process is gone has ALREADY
// reverted; its record stays on disk because the revert is a detached POSIX sh
// that deliberately cannot call this binary to clean up after itself. Honouring
// that stale record would park the self-heal permanently — on precisely the
// host that just had a tunnel torn out from under it and most needs healing.
func TestAFiredDeadmanDoesNotParkTheLoopForever(t *testing.T) {
	plan := healPlanOn(t)
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save tunnel: %v", err)
	}
	now := time.Unix(1788318109, 0)

	// A one-second fuse, left to run out. Nothing removes the record.
	armForTest(t, time.Second)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if d, err := LoadDeadman(); err == nil && d != nil && d.Fired() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	d, err := LoadDeadman()
	if err != nil || d == nil {
		t.Fatalf("the record must still be on disk after firing: d=%+v err=%v", d, err)
	}
	if !d.Fired() {
		t.Fatal("the switch never fired, so this test is not exercising what it claims")
	}

	broken := healthyTunnel(plan.PeerPublicKey, now.Unix())
	broken.answers["wg show interfaces"] = "\n"

	restored, err := (&tunnelHealer{}).pass(context.Background(), broken, now)
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(restored) == 0 || !broken.ran("wg-quick up "+plan.ConfPath) {
		t.Fatalf("a FIRED switch must not block the heal — that is the host that needs it most: restored=%v calls=%v", restored, broken.calls)
	}
}
