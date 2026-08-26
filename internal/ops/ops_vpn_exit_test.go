package ops

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// eligibleGateHost is a host that CAN be asked to select an exit gate: Linux,
// root, and tailscale actually installed. `eligible()` in
// ops_vpn_bootstrap_test.go stops short of the last one, because enrolling is
// what INSTALLS tailscale — selecting a gate requires it to be there already.
func eligibleGateHost() vpn.Eligibility {
	e := eligible()
	e.Host.TailscalePath = tailscaleBin
	return e
}

// withUseExit swaps internal/vpn's sequence for a stub, so these tests
// exercise the verb's argument handling and reply shape without moving the
// default route of whatever machine runs `go test`. The sequence itself is
// covered in internal/vpn.
func withUseExit(t *testing.T, fn func(context.Context, vpn.UseExitSpec, vpn.Progress) (vpn.UseExitResult, error)) {
	t.Helper()
	prev := useExit
	useExit = fn
	t.Cleanup(func() { useExit = prev })
}

func withClearExit(t *testing.T, fn func(context.Context, vpn.ClearExitSpec, vpn.Progress) (vpn.ClearExitResult, error)) {
	t.Helper()
	prev := clearExit
	clearExit = fn
	t.Cleanup(func() { clearExit = prev })
}

// Same guarantee vpn_status and the firewall verbs carry: a lean-linked
// laptop has no podman, and it is exactly the kind of machine someone wants
// to route out through a gate.
func TestVPNExitVerbsAreNotWorkspaceLifecycleVerbs(t *testing.T) {
	for _, verb := range []string{"vpn_use_exit", "vpn_clear_exit"} {
		if workspaceLifecycleVerbs[verb] {
			t.Fatalf("%s must not be in workspaceLifecycleVerbs — it needs tailscale and `ip`, never podman", verb)
		}
	}
}

// THE PROPERTY THIS VERB EXISTS FOR. A switch that could not be confirmed has
// already been reverted by the time UseExit returns — that is a safe, normal
// outcome, and the two measured addresses are the evidence for why it did not
// stick. Collapsing it into a bare verb error would throw away the only part
// a human can act on, and would read to the control plane exactly like a host
// that could not be reached at all.
func TestUnconfirmedSwitchComesBackAsEvidenceNotAsAnError(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	withUseExit(t, func(context.Context, vpn.UseExitSpec, vpn.Progress) (vpn.UseExitResult, error) {
		return vpn.UseExitResult{
			Gate:         "aw-lab",
			GateIP:       "100.64.0.9",
			EgressBefore: "188.250.165.236",
			EgressAfter:  "188.250.165.236",
			Reverted:     true,
			Reason:       "egress is still 188.250.165.236, the same address as before the switch",
		}, errors.New("exit node aw-lab was NOT confirmed and has been reverted: egress is still 188.250.165.236")
	})

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}
	data, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{"node": "aw-lab"}, noopEmit)
	if err != nil {
		t.Fatalf("a reverted switch must not surface as a verb error: %v", err)
	}
	out := data.(map[string]any)

	if out["applied"] != false || out["confirmed"] != false || out["reverted"] != true {
		t.Fatalf("applied/confirmed/reverted = %v/%v/%v", out["applied"], out["confirmed"], out["reverted"])
	}
	if out["egress_before"] != "188.250.165.236" || out["egress_after"] != "188.250.165.236" {
		t.Fatalf("the before/after pair is the evidence and must survive the failure path: %v / %v", out["egress_before"], out["egress_after"])
	}
	if out["error"] == nil || out["reason"] == "" {
		t.Fatalf("a failed switch must carry both the error and the reason: %v / %v", out["error"], out["reason"])
	}
}

// `applied` must track CONFIRMED egress, not "the tailscale call returned".
// The interface being up has never been enough here.
func TestAppliedTracksConfirmedEgress(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	withUseExit(t, func(context.Context, vpn.UseExitSpec, vpn.Progress) (vpn.UseExitResult, error) {
		return vpn.UseExitResult{
			Gate: "aw-lab", GateIP: "100.64.0.9",
			EgressBefore: "188.250.165.236", EgressAfter: "65.109.66.88",
			DefaultDevice: "tailscale0", ControlPlaneOK: true, Confirmed: true,
		}, nil
	})

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}
	data, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{"node": "aw-lab"}, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)
	if out["applied"] != true || out["egress_after"] != "65.109.66.88" {
		t.Fatalf("applied = %v, egress_after = %v", out["applied"], out["egress_after"])
	}
	if out["refused"] != false {
		t.Fatalf("refused = %v on a successful switch", out["refused"])
	}
}

// A host that cannot do this at all answers with a refusal and a nil error —
// the same shape vpn_bootstrap uses, so a screen can tell "this machine is
// not able to" apart from "this machine could not be asked".
func TestIneligibleHostRefusesInsteadOfErroring(t *testing.T) {
	e := eligibleGateHost()
	e.CanEnroll = false
	e.EnrollRefusal = "/dev/net/tun is not present on this host."
	withVerdict(t, e)
	withUseExit(t, func(context.Context, vpn.UseExitSpec, vpn.Progress) (vpn.UseExitResult, error) {
		t.Fatal("the sequence must not run on a host that was already refused")
		return vpn.UseExitResult{}, nil
	})

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}
	data, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{"node": "aw-lab"}, noopEmit)
	if err != nil {
		t.Fatalf("a refusal is a successful reply: %v", err)
	}
	out := data.(map[string]any)
	if out["refused"] != true || out["refusal"] != e.EnrollRefusal {
		t.Fatalf("refused/refusal = %v/%v", out["refused"], out["refusal"])
	}
	if out["applied"] != false || out["changed"] != false {
		t.Fatal("a refusal must still carry applied/changed=false, so one field answers the question either way")
	}
}

// A non-Linux host is refused for a different reason and it has to say which:
// `ip rule` is what implements the exclusions, and a macOS box being told
// "not eligible" with no sentence sends its owner hunting for the wrong fix.
func TestNonLinuxHostIsRefusedWithTheRouteExclusionReason(t *testing.T) {
	e := eligibleGateHost()
	e.Host.OS = "darwin"
	withVerdict(t, e)

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}
	data, _ := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{"node": "aw-lab"}, noopEmit)
	out := data.(map[string]any)
	refusal, _ := out["refusal"].(string)
	if out["refused"] != true || refusal == "" {
		t.Fatalf("refused/refusal = %v/%q", out["refused"], refusal)
	}
	if want := "ip rule"; !strings.Contains(refusal, want) {
		t.Fatalf("refusal must name what is missing (%q), got %q", want, refusal)
	}
}

// Naming no gate is a CALLER error, not a host refusal — the two have
// different fixes and only one of them is about this machine.
func TestMissingNodeIsAnError(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}
	if _, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{}, noopEmit); err == nil {
		t.Fatal("a missing node must be an error, not a refusal")
	}
}

// The control plane defaults to the one this daemon actually answers to. It
// is the management path that has to survive the route move, so letting it
// default to anything else — or to empty — would pin the wrong address
// outside the tunnel.
func TestControlPlaneDefaultsToTheOneThisDaemonAnswersTo(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	var got vpn.UseExitSpec
	withUseExit(t, func(_ context.Context, spec vpn.UseExitSpec, _ vpn.Progress) (vpn.UseExitResult, error) {
		got = spec
		return vpn.UseExitResult{Confirmed: true}, nil
	})

	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}
	if _, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{"node": "aw-lab"}, noopEmit); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got.ControlPlane != "https://api.aw.tekflox.com" {
		t.Fatalf("control plane = %q", got.ControlPlane)
	}
}

// The timeouts arrive as JSON numbers from a web UI. Omitted, they must land
// on the proven pair, not on zero.
func TestTimeoutArgsAreSecondsAndDefaultToTheProvenWindow(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	var got vpn.UseExitSpec
	withUseExit(t, func(_ context.Context, spec vpn.UseExitSpec, _ vpn.Progress) (vpn.UseExitResult, error) {
		got = spec
		return vpn.UseExitResult{Confirmed: true}, nil
	})
	h := &Handler{Runner: newFakeRunner(), Opts: BootstrapOpts{ControlPlane: "https://api.aw.tekflox.com"}}

	if _, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{"node": "aw-lab"}, noopEmit); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got.Deadman != vpn.DefaultDeadmanTimeout || got.ConfirmTimeout != vpn.DefaultConfirmTimeout {
		t.Fatalf("defaults = %s/%s", got.Deadman, got.ConfirmTimeout)
	}

	if _, err := h.Dispatch(context.Background(), "vpn_use_exit", map[string]any{
		"node": "aw-lab", "deadman_s": float64(300), "confirm_s": float64(90),
		"exclude": []any{"10.8.0.0/24", ""},
	}, noopEmit); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got.Deadman != 300*time.Second || got.ConfirmTimeout != 90*time.Second {
		t.Fatalf("explicit = %s/%s", got.Deadman, got.ConfirmTimeout)
	}
	if len(got.Exclude) != 1 || got.Exclude[0] != "10.8.0.0/24" {
		t.Fatalf("exclude = %v — blanks must be dropped, not passed through as an empty prefix", got.Exclude)
	}
}

// clear-exit is the undo path and reports where traffic goes NOW, measured.
// An unknown address must come back empty rather than as a stale one.
func TestClearExitReportsTheResultingEgress(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	withClearExit(t, func(context.Context, vpn.ClearExitSpec, vpn.Progress) (vpn.ClearExitResult, error) {
		return vpn.ClearExitResult{ExclusionsRemoved: 4, DeadmanStoodDown: true, Egress: "188.250.165.236", EgressVia: "https://api.ipify.org"}, nil
	})

	h := &Handler{Runner: newFakeRunner()}
	data, err := h.Dispatch(context.Background(), "vpn_clear_exit", nil, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)
	if out["cleared"] != true || out["egress"] != "188.250.165.236" || out["exclusions_removed"] != 4 {
		t.Fatalf("out = %v", out)
	}
}

// A clear that leaves the host with no internet must say so rather than
// reporting a clean undo — "cleared, and still broken" is the state someone
// has to act on.
func TestClearExitSurfacesAnEgressItCouldNotMeasure(t *testing.T) {
	withVerdict(t, eligibleGateHost())
	withClearExit(t, func(context.Context, vpn.ClearExitSpec, vpn.Progress) (vpn.ClearExitResult, error) {
		return vpn.ClearExitResult{EgressError: "no endpoint answered"}, nil
	})

	h := &Handler{Runner: newFakeRunner()}
	data, _ := h.Dispatch(context.Background(), "vpn_clear_exit", nil, noopEmit)
	out := data.(map[string]any)
	if out["egress"] != "" || out["egress_error"] != "no endpoint answered" {
		t.Fatalf("out = %v", out)
	}
}
