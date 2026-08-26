package ops

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// withAdvertise swaps internal/vpn's sequence for a stub, so these tests
// exercise the verb's argument handling and reply shape without touching the
// sysctls or the tailscale prefs of whatever machine runs `go test`. The
// sequence itself is covered in internal/vpn.
func withAdvertise(t *testing.T, fn func(context.Context, vpn.Runner, vpn.Runner, vpn.Eligibility, bool, vpn.Progress) (vpn.AdvertiseResult, error)) {
	t.Helper()
	original := advertiseExit
	advertiseExit = fn
	t.Cleanup(func() { advertiseExit = original })
}

func okAdvertise(res vpn.AdvertiseResult) func(context.Context, vpn.Runner, vpn.Runner, vpn.Eligibility, bool, vpn.Progress) (vpn.AdvertiseResult, error) {
	return func(context.Context, vpn.Runner, vpn.Runner, vpn.Eligibility, bool, vpn.Progress) (vpn.AdvertiseResult, error) {
		return res, nil
	}
}

// Same guarantee every other vpn verb carries: a lean-linked laptop has no
// podman, and it is exactly the kind of machine somebody wants to turn into a
// gate for the rest of their mesh.
func TestVPNAdvertiseExitIsNotAWorkspaceLifecycleVerb(t *testing.T) {
	if workspaceLifecycleVerbs["vpn_advertise_exit"] {
		t.Fatal("vpn_advertise_exit must not be in workspaceLifecycleVerbs")
	}
}

// The default is the direction a caller almost always wants, and getting it
// backwards would silently withdraw a gate other hosts are routing through.
func TestAdvertiseDefaultsToOfferingNotWithdrawing(t *testing.T) {
	withTailscale(t, tailscaleBin)
	var asked *bool
	withAdvertise(t, func(_ context.Context, _ vpn.Runner, _ vpn.Runner, _ vpn.Eligibility, on bool, _ vpn.Progress) (vpn.AdvertiseResult, error) {
		asked = &on
		return vpn.AdvertiseResult{Advertising: on}, nil
	})
	h := &Handler{Runner: meshRunner()}

	if _, err := h.Dispatch(context.Background(), "vpn_advertise_exit", nil, noopEmit); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if asked == nil || !*asked {
		t.Fatalf("advertise defaulted to %v, want true", asked)
	}

	if _, err := h.Dispatch(context.Background(), "vpn_advertise_exit", map[string]any{"advertise": false}, noopEmit); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if asked == nil || *asked {
		t.Fatal("advertise:false must withdraw")
	}
}

// THE distinction this verb's reply exists to carry. Advertised and approved
// are two different states owned by two different people, and a verb that
// reported one boolean would leave the control plane unable to tell "I did my
// half" from "the gate is live".
func TestAdvertisingReportsBothHalvesSeparately(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withAdvertise(t, okAdvertise(vpn.AdvertiseResult{
		Advertising: true,
		OffersExit:  false, // nobody has approved it yet — the NORMAL answer
		NodeName:    "aw-surface-wsl",
		LoginServer: "https://headscale.aw.tekflox.com",
		RouteBefore: "eth0", RouteAfter: "eth0",
		Forwarding: map[string]bool{"net.ipv4.ip_forward": true},
		Warning:    "this is a WSL2 distro …",
	}))
	h := &Handler{Runner: meshRunner()}

	data, err := h.Dispatch(context.Background(), "vpn_advertise_exit", nil, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)

	if out["advertising"] != true {
		t.Fatalf("advertising = %v, want true", out["advertising"])
	}
	if out["offers_exit"] != false {
		t.Fatal("offers_exit must stay false until the control plane approves the route")
	}
	if out["node_name"] != "aw-surface-wsl" {
		t.Fatalf("node_name = %v", out["node_name"])
	}
	if out["default_route_unchanged"] != true {
		t.Fatalf("default_route_unchanged = %v — offering is not using", out["default_route_unchanged"])
	}
	if w, _ := out["warning"].(string); !strings.Contains(w, "WSL2") {
		t.Fatalf("warning = %q, want the host's own sentence", w)
	}
}

// A refusal is a successful answer with a nil error — the same shape
// vpn_bootstrap and vpn_use_exit use, so a screen can tell "this machine is
// not able to" apart from "this machine could not be asked".
func TestAnIneligibleHostRefusesInsteadOfErroring(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withAdvertise(t, okAdvertise(vpn.AdvertiseResult{
		Refused: true,
		Refusal: "this host cannot forward another node's packets: net.ipv4.ip_forward is still not 1",
	}))
	h := &Handler{Runner: meshRunner()}

	data, err := h.Dispatch(context.Background(), "vpn_advertise_exit", nil, noopEmit)
	if err != nil {
		t.Fatalf("a refusal must not be an error: %v", err)
	}
	out := data.(map[string]any)
	if out["refused"] != true {
		t.Fatalf("refused = %v", out["refused"])
	}
	if r, _ := out["refusal"].(string); !strings.Contains(r, "ip_forward") {
		t.Fatalf("the refusal must name what to fix: %q", r)
	}
}

// "Cannot be a gate" and "is not on the mesh at all" need different things
// done about them. Collapsing the second into the first sends somebody to fix
// a kernel when what they need is to enrol.
func TestAHostWithoutTailscaleIsToldToEnrolNotToFixItsKernel(t *testing.T) {
	withTailscale(t, "")
	withAdvertise(t, func(context.Context, vpn.Runner, vpn.Runner, vpn.Eligibility, bool, vpn.Progress) (vpn.AdvertiseResult, error) {
		t.Fatal("the sequence must not run on a host with no tailscale")
		return vpn.AdvertiseResult{}, nil
	})
	h := &Handler{Runner: newFakeRunner()}

	data, err := h.Dispatch(context.Background(), "vpn_advertise_exit", nil, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)
	if out["refused"] != true {
		t.Fatal("a host with no tailscale cannot advertise anything")
	}
	if r, _ := out["refusal"].(string); !strings.Contains(r, "Enrol") {
		t.Fatalf("refusal = %q, want the enrol instruction", r)
	}
}

// Every path out of this verb publishes the eligibility verdict, including
// the refusals — a host that cannot be a gate is exactly the one whose reader
// wants to know what it COULD do.
func TestEveryReplyCarriesTheEligibilityVerdict(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withAdvertise(t, okAdvertise(vpn.AdvertiseResult{Advertising: true}))
	h := &Handler{Runner: meshRunner()}

	for _, args := range []map[string]any{nil, {"advertise": false}} {
		data, err := h.Dispatch(context.Background(), "vpn_advertise_exit", args, noopEmit)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		el, ok := data.(map[string]any)["eligibility"].(map[string]any)
		if !ok {
			t.Fatalf("eligibility is missing from %v", data)
		}
		if _, ok := el["exit_warning"]; !ok {
			t.Fatal("exit_warning must be on the wire — a screen cannot warn about what it is not told")
		}
	}
}

// A real failure in the sequence stays a real failure. Folding it into
// {"refused": true} would report a daemon that rejected the change as a
// machine that is not capable of it.
func TestARealFailurePropagatesAsAnError(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withAdvertise(t, func(context.Context, vpn.Runner, vpn.Runner, vpn.Eligibility, bool, vpn.Progress) (vpn.AdvertiseResult, error) {
		return vpn.AdvertiseResult{}, errors.New("tailscale set --advertise-exit-node=true: exit status 1: Access denied")
	})
	h := &Handler{Runner: meshRunner()}

	if _, err := h.Dispatch(context.Background(), "vpn_advertise_exit", nil, noopEmit); err == nil {
		t.Fatal("a daemon that rejected the preference must not read as success")
	}
}
