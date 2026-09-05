package vpn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// THE GAP THIS CLOSES, stated as a test.
//
// After Layer 1 the exclusion list is only the control plane, and
// resolveControlPlaneIPs is best-effort by design — it returns an empty slice
// and says nothing. So an apply whose control plane failed to resolve produces
// ZERO exclusions and used to be byte-for-byte identical to a healthy apply:
// the kill switch simply absent, with nothing anywhere saying so. Core has to
// reach aw-backend to issue external-down, so that is precisely the case where
// a tunnel that is up-but-degraded blocks its own Disconnect.
//
// "Computed successfully and came back empty" and "the control plane could not
// be pinned" must not look identical.
func TestAnUnresolvableControlPlaneIsNotSilent(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)

	// A name that cannot resolve. RFC 6761 reserves .invalid precisely so it
	// can never be registered, so this is a deterministic failure rather than
	// a bet on someone's DNS.
	plan := planOnWithControlPlane(t, healthyHost(), "https://control-plane.invalid")

	if plan.Refusal != "" {
		t.Fatalf("an unresolvable control plane must WARN, not refuse — refusing would turn a transient DNS blip into 'the VPN cannot be switched on': %s", plan.Refusal)
	}
	if len(plan.Exclusions) != 0 {
		t.Fatalf("expected no exclusions from an unresolvable control plane: %v", plan.Exclusions)
	}
	if plan.KillSwitch {
		t.Fatal("kill_switch=true while nothing was pinned outside the tunnel — this is the exact false reassurance the field exists to remove")
	}
	if !containsString(plan.Warnings, KillSwitchMissingWarning) {
		t.Fatalf("the missing kill switch produced no warning; an empty exclusion list is silent by itself: %v", plan.Warnings)
	}
	// The sentence has to be usable by a person: what is wrong, what it costs,
	// and how to get out of it from the host.
	for _, phrase := range []string{"NO KILL SWITCH", "Disconnect", "external-unroute", "external-down"} {
		if !strings.Contains(KillSwitchMissingWarning, phrase) {
			t.Fatalf("the warning does not mention %q: %s", phrase, KillSwitchMissingWarning)
		}
	}
}

// The other direction, so the test above cannot pass by always answering
// "missing". A control plane that DOES resolve pins a /32 and reports the kill
// switch as present, with no kill-switch warning.
func TestAResolvableControlPlaneReportsTheKillSwitchPresent(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)

	plan := planOnWithControlPlane(t, healthyHost(), "https://198.51.100.7:8443")
	if !plan.KillSwitch {
		t.Fatalf("kill_switch=false while %v was pinned outside the tunnel", plan.Exclusions)
	}
	if containsString(plan.Warnings, KillSwitchMissingWarning) {
		t.Fatalf("a healthy apply carries the kill-switch warning: %v", plan.Warnings)
	}
	// The DNS warning is still there — that gap is real on every apply, and
	// pretending otherwise would be the same class of lie.
	if !containsString(plan.Warnings, DNSNotTunnelledWarning) {
		t.Fatalf("the DNS gap is not reported: %v", plan.Warnings)
	}
}

// warnings is `[]` and never null, on every path — including the refusals,
// which return before the guarantees are ever computed. A caller that has to
// handle both null and [] is a caller that will handle one of them wrong.
func TestWarningsAreAnEmptyArrayAndNeverNull(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)

	// A refusal: nothing wider than a /32 may be routed, so this returns long
	// before any guarantee is computed.
	r := healthyHost()
	r.answers["docker inspect -f"] = "someid 172.18.0.8 172.20.0.2 "
	refused := planOn(t, r)
	if refused.Refusal == "" {
		t.Fatal("expected a refusal from a multi-homed container")
	}
	blob, err := json.Marshal(refused)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"warnings":[]`) {
		t.Fatalf("a refused plan does not carry warnings:[] — it marshals null:\n%s", blob)
	}

	// And a plan rebuilt from state.json has never been through
	// newExternalGuarantees at all, so the payload builders have to cope.
	if got := OrEmptyStrings(nil); got == nil || len(got) != 0 {
		t.Fatalf("OrEmptyStrings(nil) = %#v", got)
	}
	blob, _ = json.Marshal(map[string]any{"warnings": OrEmptyStrings(nil)})
	if !strings.Contains(string(blob), `"warnings":[]`) {
		t.Fatalf("nil did not become []: %s", blob)
	}
}

// The dial reports the same guarantee BEFORE anything is routed. Finding out
// the kill switch will be missing before your egress moves is strictly better
// than finding out after.
func TestTheDialReportsTheKillSwitchBeforeAnythingIsRouted(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)

	spec := upSpec(upHost())
	spec.Profile = mustProfile(t)
	spec.ControlPlane = "https://control-plane.invalid"
	plan, err := PlanExternalUp(context.Background(), spec)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Refusal != "" {
		t.Fatalf("the dial must warn, not refuse: %s", plan.Refusal)
	}
	if plan.KillSwitch || !containsString(plan.Warnings, KillSwitchMissingWarning) {
		t.Fatalf("the dial did not report the missing kill switch: kill_switch=%v warnings=%v", plan.KillSwitch, plan.Warnings)
	}

	spec.ControlPlane = "https://198.51.100.7:8443"
	ok, err := PlanExternalUp(context.Background(), spec)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !ok.KillSwitch {
		t.Fatal("a resolvable control plane still reported no kill switch on the dial path")
	}
}

// external-status MEASURES the kill switch rather than trusting the record:
// the pins can be flushed out from under a healthy record by the same daily
// systemd-networkd restart Reassert exists for, and the record would never
// know.
func TestStatusMeasuresTheKillSwitchRatherThanTrustingTheRecord(t *testing.T) {
	isolateState(t)
	withFakeBinaries(t)

	// A record that claims a pin was installed.
	if err := saveExternalRouteState(ExternalRoutePlan{
		Container: "aw-remote-host-workspace", ContainerID: "abc123",
		SourceIP: "10.89.0.4", Table: 200, Priority: 5399, Runtime: "podman",
		Exclusions: []string{"198.51.100.7/32"},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The machine does NOT have it — flushed.
	flushed := liveHost()
	flushed.answers["ip route show table 200"] = "default dev wg0 \n"
	got := statusOn(t, flushed)
	if got.KillSwitch {
		t.Fatal("kill_switch=true while the pin is not in the table — the report trusted the record over the kernel")
	}
	if !containsString(got.Warnings, KillSwitchMissingWarning) {
		t.Fatalf("a flushed pin produced no warning: %v", got.Warnings)
	}

	// Same record, and now the machine agrees.
	present := liveHost()
	present.answers["ip route show table 200"] = "default dev wg0 \n198.51.100.7/32 via 172.18.0.1 dev eth0 onlink \n"
	if got := statusOn(t, present); !got.KillSwitch {
		t.Fatal("kill_switch=false while the pin IS in the table")
	}
}

// An idle host carries no warnings. A permanent scare on a disconnected
// screen is how a user learns these sentences are noise — and then misses the
// one that matters.
func TestAnIdleHostCarriesNoWarnings(t *testing.T) {
	isolateState(t)
	got := statusOn(t, deadHost())
	if len(got.Warnings) != 0 {
		t.Fatalf("an idle host warns about a connection it does not have: %v", got.Warnings)
	}
	blob, _ := json.Marshal(got)
	if !strings.Contains(string(blob), `"warnings":[]`) {
		t.Fatalf("idle warnings did not marshal as []: %s", blob)
	}
}
