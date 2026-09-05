package vpn

import (
	"os"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// THE BUG, as a fixture: a container already pinned to an external VPN
// tunnel (externalroute.go), on the same subnet a mesh exit gate is about to
// route. Reused across every test below so "inside" and "outside" differ by
// exactly the one field the check is about — the source address.
func recordedExternalRoute(t *testing.T, sourceIP string) {
	t.Helper()
	isolateState(t)
	if err := saveExternalRouteState(ExternalRoutePlan{
		Container:   "aw-remote-host",
		ContainerID: "e91aacf5a3a39a17",
		SourceIP:    sourceIP,
		Table:       ExternalRouteTable,
		Priority:    ExternalRoutePriority,
		Runtime:     "docker",
	}); err != nil {
		t.Fatalf("saveExternalRouteState: %v", err)
	}
}

// Trap #1: a host that has never dialled an external VPN — no state.json at
// all — must read as "nothing recorded", never as a refusal. A gate pick on
// such a host is legitimate and must not be blocked by a feature meant for
// hosts that HAVE a tunnel to shadow.
func TestExternalRouteShadowRefusal_NothingRecordedIsNotARefusal(t *testing.T) {
	isolateState(t) // fresh HOME, no state.json written at all
	if got := externalRouteShadowRefusal([]string{"172.18.0.0/16"}); got != "" {
		t.Fatalf("a host with no recorded external route must not be refused, got %q", got)
	}
}

// Same trap, the other half: a state.json that exists but cannot be parsed
// must also read as "nothing recorded" — loadExternalRouteState's own
// contract — not as an error that blocks every future gate pick.
func TestExternalRouteShadowRefusal_UnreadableStateIsNotARefusal(t *testing.T) {
	isolateState(t)
	path, err := state.DefaultPath()
	if err != nil {
		t.Fatalf("state path: %v", err)
	}
	if err := os.MkdirAll(path[:strings.LastIndex(path, "/")], 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	if got := externalRouteShadowRefusal([]string{"172.18.0.0/16"}); got != "" {
		t.Fatalf("an unreadable state file must not be refused, got %q", got)
	}
}

// THE REAL OVERLAP CHECK. The recorded source (172.18.0.4) sits inside the
// subnet (172.18.0.0/16) this gate would route — exactly the shape of the
// bug: the gate's own `from 172.18.0.0/16 lookup 52` at priority 5261 would
// be consulted before the dialer's `from 172.18.0.4/32 lookup 200` at 5399,
// so the VPN would be silently shadowed. This must refuse, and the sentence
// must name both the container and the tunnel it would shadow.
func TestExternalRouteShadowRefusal_RefusesOnRealOverlap(t *testing.T) {
	recordedExternalRoute(t, "172.18.0.4")
	got := externalRouteShadowRefusal([]string{"172.18.0.0/16"})
	if got == "" {
		t.Fatal("a subnet that contains the recorded external-route source must be refused")
	}
	for _, want := range []string{"aw-remote-host", "172.18.0.4", "172.18.0.0/16"} {
		if !strings.Contains(got, want) {
			t.Fatalf("refusal must name %q, got %q", want, got)
		}
	}
}

// THE MUTATED-FIXTURE PROOF. Same record, same subnet list, but the source
// address is moved OUTSIDE the subnet. If this test failed to fail here, the
// test above would be vacuous — passing merely because a route was recorded
// at all, not because it was proven to overlap the subnet being routed. A
// gate that would route some other, unrelated container must never be
// refused just because a completely different container happens to be on a
// VPN somewhere else.
func TestExternalRouteShadowRefusal_DoesNotRefuseWhenSourceIsOutsideTheSubnet(t *testing.T) {
	recordedExternalRoute(t, "192.0.2.9") // TEST-NET-1 (RFC 5737): never a container's real address
	if got := externalRouteShadowRefusal([]string{"172.18.0.0/16"}); got != "" {
		t.Fatalf("a recorded route on an unrelated address must not refuse a gate for a different subnet, got %q", got)
	}
}

// Multiple container networks are routed together in the real plan (one
// entry per ContainerSubnets result); the overlap check has to look at all
// of them, not just the first, and must not false-positive on the ones that
// do not overlap.
func TestExternalRouteShadowRefusal_ChecksEverySubnetInThePlan(t *testing.T) {
	recordedExternalRoute(t, "10.89.0.5")
	got := externalRouteShadowRefusal([]string{"172.18.0.0/16", "10.89.0.0/24"})
	if got == "" {
		t.Fatal("the second subnet in the plan contains the recorded source and must refuse")
	}
	if !strings.Contains(got, "10.89.0.0/24") {
		t.Fatalf("refusal must name the actual overlapping subnet, got %q", got)
	}
}
