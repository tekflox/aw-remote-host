package vpn

import (
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// THE SECONDARY FIX. Before this, container_egress_ip rendered as a bare,
// unverified address — the exact gap that let a mesh exit gate steal a
// routed container's traffic while the VPN screen had nothing to contradict
// the number it was showing. expectedEgressMismatch is the decision kept
// pure and separate from ExternalStatus's own network round trips, the same
// way externalRouteShadowRefusal (usexit.go) is kept separate from
// PlanUseExit's live probes — both are testable without a runner.

// No route recorded at all: nothing to compare, nothing to say.
func TestExpectedEgressMismatch_NoRouteIsSilent(t *testing.T) {
	if got := expectedEgressMismatch(nil, strPtr("203.0.113.9")); got != "" {
		t.Fatalf("no recorded route must produce no warning, got %q", got)
	}
}

// ExpectEgress is optional (ExternalRouteSpec.ExpectEgress) — a route applied
// without it recorded nothing to compare against, and must stay silent
// rather than manufacturing a mismatch out of an empty expectation.
func TestExpectedEgressMismatch_NoExpectationIsSilent(t *testing.T) {
	route := &state.ExternalRouteState{Container: "aw-remote-host", SourceIP: "10.89.0.4"}
	if got := expectedEgressMismatch(route, strPtr("198.51.100.7")); got != "" {
		t.Fatalf("a route with no recorded expectation must produce no warning, got %q", got)
	}
}

// No container measurement yet (SkipEgress, or the probe failed) — silent
// rather than comparing against a hole.
func TestExpectedEgressMismatch_NoMeasurementIsSilent(t *testing.T) {
	route := &state.ExternalRouteState{Container: "aw-remote-host", ExpectEgress: "203.0.113.9"}
	if got := expectedEgressMismatch(route, nil); got != "" {
		t.Fatalf("no container measurement must produce no warning, got %q", got)
	}
}

// The healthy case: measured matches expected. Silence here is the point —
// a warning on every healthy poll is exactly how a person learns to ignore
// this screen.
func TestExpectedEgressMismatch_AgreementIsSilent(t *testing.T) {
	route := &state.ExternalRouteState{Container: "aw-remote-host", ExpectEgress: "203.0.113.9"}
	if got := expectedEgressMismatch(route, strPtr("203.0.113.9")); got != "" {
		t.Fatalf("measured egress matching the expectation must produce no warning, got %q", got)
	}
}

// THE SHAPE OF THE ACTUAL BUG: the container is measured leaving via the
// GATE's address, not the tunnel it was told to expect. This is precisely
// what a mesh exit gate silently taking the rule looks like from this
// status verb's side, and it must render as a real warning rather than a
// bare, unverified IP.
func TestExpectedEgressMismatch_WarnsOnRealMismatch(t *testing.T) {
	route := &state.ExternalRouteState{Container: "aw-remote-host", ExpectEgress: "203.0.113.9"}
	got := expectedEgressMismatch(route, strPtr("198.51.100.42"))
	if got == "" {
		t.Fatal("a container egress that disagrees with the recorded expectation must warn")
	}
	for _, want := range []string{"203.0.113.9", "198.51.100.42", "mesh exit gate"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warning must mention %q, got %q", want, got)
		}
	}
}

func strPtr(s string) *string { return &s }
