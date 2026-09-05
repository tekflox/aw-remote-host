package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// Synthetic key material — 32 bytes of 'A'/'B', which is what `wg` accepts and
// nothing else. See internal/vpn/externalup_test.go for why no fixture in this
// feature ever looks like a real key.
const (
	upPrivateKey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	upPeerKey    = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
)

func upProfileArg() map[string]any {
	return map[string]any{
		"type":        "wireguard",
		"iface":       "wg0",
		"private_key": upPrivateKey,
		"address":     []any{"10.5.0.2/32"},
		"dns":         []any{"1.1.1.1"},
		"mtu":         float64(1420),
		"peer": map[string]any{
			"public_key":           upPeerKey,
			"preshared_key":        "",
			"endpoint":             "1.2.3.4:51820",
			"allowed_ips":          []any{"0.0.0.0/0"},
			"persistent_keepalive": float64(25),
		},
	}
}

// withExternalUp swaps the dialler for one that records the spec it was handed
// and changes nothing. Without it this verb's tests would bring a WireGuard
// tunnel up on whatever machine runs `go test` — the same discipline
// externalRoute is indirected for.
func withExternalUp(t *testing.T, res vpn.ExternalUpResult, err error) *vpn.ExternalUpSpec {
	t.Helper()
	var got vpn.ExternalUpSpec
	original := externalUp
	externalUp = func(_ context.Context, spec vpn.ExternalUpSpec, _ vpn.Progress) (vpn.ExternalUpResult, error) {
		got = spec
		return res, err
	}
	t.Cleanup(func() { externalUp = original })
	return &got
}

func upHandler() *Handler { return &Handler{Runner: newFakeRunner()} }

// The profile arrives as typed fields and is validated by the SAME parser the
// CLI uses — not re-decoded here, because a second decode path is exactly how
// the unknown-key refusal would quietly stop applying on one of the two
// surfaces.
func TestExternalUpPassesAValidatedProfileThrough(t *testing.T) {
	spec := withExternalUp(t, vpn.ExternalUpResult{Confirmed: true}, nil)
	out, err := (&Handler{Runner: newFakeRunner()}).VPNExternalUp(context.Background(), map[string]any{
		"profile":   upProfileArg(),
		"table":     float64(201),
		"iface":     "wg7",
		"deadman_s": float64(90),
	}, nil)
	if err != nil {
		t.Fatalf("VPNExternalUp: %v", err)
	}
	if spec.Profile.Peer.Endpoint != "1.2.3.4:51820" || spec.Profile.Type != "wireguard" {
		t.Fatalf("profile did not survive the verb: %+v", spec.Profile)
	}
	if spec.Table != 201 || spec.Iface != "wg7" || spec.Deadman.Seconds() != 90 {
		t.Fatalf("arguments were dropped: table=%d iface=%q deadman=%s", spec.Table, spec.Iface, spec.Deadman)
	}
	if out["confirmed"] != true {
		t.Fatalf("reply = %v", out)
	}
}

// The RCE closure, at the verb. wg-quick runs PostUp as root, so a link
// message that carries one has to be refused by the argument reader and never
// reach the dialler.
func TestExternalUpRefusesAProfileCarryingAnUnknownKey(t *testing.T) {
	called := false
	original := externalUp
	externalUp = func(context.Context, vpn.ExternalUpSpec, vpn.Progress) (vpn.ExternalUpResult, error) {
		called = true
		return vpn.ExternalUpResult{}, nil
	}
	t.Cleanup(func() { externalUp = original })

	for _, key := range []string{"post_up", "PostUp", "table", "fwmark", "conf"} {
		profile := upProfileArg()
		profile[key] = "id > /tmp/pwned"
		if _, err := upHandler().VPNExternalUp(context.Background(), map[string]any{"profile": profile}, nil); err == nil {
			t.Fatalf("a profile carrying %q was accepted", key)
		}
	}
	if called {
		t.Fatal("a rejected profile still reached the dialler")
	}
}

// A verb with no profile at all has to say what it wants, and say why it will
// never take a config as text.
func TestExternalUpNeedsAProfile(t *testing.T) {
	_, err := upHandler().VPNExternalUp(context.Background(), map[string]any{}, nil)
	if err == nil || !strings.Contains(err.Error(), "profile_path") {
		t.Fatalf("err = %v", err)
	}
}

// profile_path is the shape a caller uses to keep a private key out of a link
// message. It goes through the same parser, and a mode that leaves the key
// readable is REPORTED rather than made fatal — a dial refused because a
// control plane wrote 0644 fails in the direction that leaves the operator
// with no VPN and no explanation.
func TestExternalUpReadsAProfileFromDiskAndFlagsALooseMode(t *testing.T) {
	spec := withExternalUp(t, vpn.ExternalUpResult{Confirmed: true}, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	raw, _ := json.Marshal(upProfileArg())
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := upHandler().VPNExternalUp(context.Background(), map[string]any{"profile_path": path}, nil)
	if err != nil {
		t.Fatalf("VPNExternalUp: %v", err)
	}
	if spec.Profile.Peer.PublicKey != upPeerKey {
		t.Fatalf("the profile was not read from disk: %+v", spec.Profile)
	}
	warning, _ := out["warning"].(string)
	if !strings.Contains(warning, "0600") {
		t.Fatalf("a world-readable profile holding a private key was not flagged: %v", out["warning"])
	}
}

// "This machine is not able to" and "this machine could not be asked" must not
// arrive in the same shape, or a screen cannot tell them apart. A scope
// refusal is {"refused": true, "refusal": "<sentence>"} with a NIL error, the
// same posture vpn_use_exit and vpn_external_route already take.
func TestExternalUpRefusalIsARefusalAndNotAnError(t *testing.T) {
	const sentence = "this host has no usable `wg-quick` command, so it cannot bring a WireGuard tunnel up"
	withExternalUp(t, vpn.ExternalUpResult{Reason: sentence}, fmt.Errorf("%w: %s", vpn.ErrScopeRefused, sentence))

	out, err := upHandler().VPNExternalUp(context.Background(), map[string]any{"profile": upProfileArg()}, nil)
	if err != nil {
		t.Fatalf("a refusal must not surface as an error: %v", err)
	}
	if out["refused"] != true || out["refusal"] != sentence {
		t.Fatalf("reply = %v", out)
	}

	// Anything that is NOT a scope refusal stays an error, with the evidence
	// attached: "it did not work" is worth much more next to the addresses
	// that prove it.
	withExternalUp(t, vpn.ExternalUpResult{HostBefore: "65.109.66.88", Reverted: true}, fmt.Errorf("the tunnel was NOT confirmed and has been torn back down"))
	out, err = upHandler().VPNExternalUp(context.Background(), map[string]any{"profile": upProfileArg()}, nil)
	if err == nil {
		t.Fatal("a failed dial was reported as success")
	}
	if out["host_before"] != "65.109.66.88" || out["reverted"] != true {
		t.Fatalf("the failure path dropped its evidence: %v", out)
	}
}

// Nothing this verb replies with may carry key material — the reply is stored
// by a control plane and rendered on a screen.
func TestExternalUpReplyCarriesNoKeyMaterial(t *testing.T) {
	withExternalUp(t, vpn.ExternalUpResult{Confirmed: true, Plan: vpn.ExternalUpPlan{
		Iface: "wg0", Table: 200, PeerPublicKey: upPeerKey, ProfileSHA256: "abc123",
	}}, nil)
	out, err := upHandler().VPNExternalUp(context.Background(), map[string]any{"profile": upProfileArg()}, nil)
	if err != nil {
		t.Fatalf("VPNExternalUp: %v", err)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), upPrivateKey) {
		t.Fatalf("the reply carries the private key: %s", blob)
	}
}

// --plan resolves and reports, and must never reach the dialler.
func TestExternalUpPlanChangesNothing(t *testing.T) {
	called := false
	originalUp := externalUp
	externalUp = func(context.Context, vpn.ExternalUpSpec, vpn.Progress) (vpn.ExternalUpResult, error) {
		called = true
		return vpn.ExternalUpResult{}, nil
	}
	t.Cleanup(func() { externalUp = originalUp })

	originalPlan := planExternalUp
	planExternalUp = func(context.Context, vpn.ExternalUpSpec) (*vpn.ExternalUpPlan, error) {
		return &vpn.ExternalUpPlan{Iface: "wg0", Table: 200}, nil
	}
	t.Cleanup(func() { planExternalUp = originalPlan })

	out, err := upHandler().VPNExternalUp(context.Background(), map[string]any{"profile": upProfileArg(), "plan": true}, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if out["planned"] != true || called {
		t.Fatalf("plan reached the dialler or did not report itself: out=%v called=%v", out, called)
	}
}

// The teardown undoes what was RECORDED. iface/table are forwarded as the
// fallback for a tunnel this tool lost track of, and nothing else is required
// — the same reason vpn_external_unroute takes no container argument.
func TestExternalDownNeedsNoProfile(t *testing.T) {
	var got vpn.ExternalUpSpec
	original := externalDown
	externalDown = func(_ context.Context, spec vpn.ExternalUpSpec, _ vpn.Progress) (vpn.ExternalUpResult, error) {
		got = spec
		return vpn.ExternalUpResult{Reverted: true}, nil
	}
	t.Cleanup(func() { externalDown = original })

	out, err := upHandler().VPNExternalDown(context.Background(), map[string]any{"iface": "wg3", "table": float64(202)}, nil)
	if err != nil {
		t.Fatalf("VPNExternalDown: %v", err)
	}
	if got.Iface != "wg3" || got.Table != 202 {
		t.Fatalf("fallback arguments were dropped: %+v", got)
	}
	if out["reverted"] != true {
		t.Fatalf("reply = %v", out)
	}
}

// Both verbs have to be reachable by name. A verb registered in this file but
// not in ops.go's switch is a feature the control plane cannot call, which is
// indistinguishable from one that was never written.
func TestExternalUpAndDownAreRegisteredVerbs(t *testing.T) {
	withExternalUp(t, vpn.ExternalUpResult{Confirmed: true}, nil)
	originalDown := externalDown
	externalDown = func(context.Context, vpn.ExternalUpSpec, vpn.Progress) (vpn.ExternalUpResult, error) {
		return vpn.ExternalUpResult{Reverted: true}, nil
	}
	t.Cleanup(func() { externalDown = originalDown })

	h := upHandler()
	if _, err := h.Dispatch(context.Background(), "vpn_external_up", map[string]any{"profile": upProfileArg()}, nil); err != nil {
		t.Fatalf("vpn_external_up is not routed: %v", err)
	}
	if _, err := h.Dispatch(context.Background(), "vpn_external_down", map[string]any{}, nil); err != nil {
		t.Fatalf("vpn_external_down is not routed: %v", err)
	}
}

// withExternalStatus swaps the live query for a fixed answer, so this verb's
// reply shape is tested without measuring the machine running `go test`.
func withExternalStatus(t *testing.T, report vpn.ExternalStatusReport, err error) *vpn.ExternalStatusSpec {
	t.Helper()
	var got vpn.ExternalStatusSpec
	original := externalStatus
	externalStatus = func(_ context.Context, spec vpn.ExternalStatusSpec) (vpn.ExternalStatusReport, error) {
		got = spec
		return report, err
	}
	t.Cleanup(func() { externalStatus = original })
	return &got
}

func strPtr(s string) *string { return &s }

// The workspace core is ALREADY BUILT against this exact shape and currently
// degrades to state "unknown" because the verb did not exist. A key spelled
// differently here would leave it degrading forever against a verb that now
// answers — a worse failure than the one being fixed, because it looks fixed.
func TestExternalStatusReplyMatchesTheContractedShape(t *testing.T) {
	withExternalStatus(t, vpn.ExternalStatusReport{
		Iface: "wg0", Up: true, Table: 200, RuleInstalled: true,
		Container:         strPtr("aw-remote-host-workspace"),
		ContainerEgressIP: strPtr("203.0.113.9"),
		HostEgressIP:      strPtr("65.109.66.88"),
		DeadmanArmed:      false,
		Since:             strPtr("2026-09-05T17:30:00Z"),
	}, nil)

	out, err := upHandler().VPNExternalStatus(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("VPNExternalStatus: %v", err)
	}
	for key, want := range map[string]any{
		"iface": "wg0", "up": true, "table": 200, "rule_installed": true,
		"container":           "aw-remote-host-workspace",
		"container_egress_ip": "203.0.113.9", "host_egress_ip": "65.109.66.88",
		"deadman_armed": false, "since": "2026-09-05T17:30:00Z",
	} {
		if out[key] != want {
			t.Fatalf("%s = %#v, want %#v", key, out[key], want)
		}
	}
	// Present-and-null, not absent: the contract spells these `"<v>"|null`.
	v, ok := out["deadman_expires_at"]
	if !ok || v != nil {
		t.Fatalf("deadman_expires_at = %#v (present=%v), want present and null", v, ok)
	}
}

// An unset pointer has to reach the wire as JSON null, never as "". A caller
// that has to treat "" as a second kind of "nothing" is a caller that will get
// it wrong once.
func TestExternalStatusNullsMarshalAsNull(t *testing.T) {
	withExternalStatus(t, vpn.ExternalStatusReport{Iface: "wg0", Table: 200}, nil)
	out, err := upHandler().VPNExternalStatus(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("VPNExternalStatus: %v", err)
	}
	blob, _ := json.Marshal(out)
	for _, want := range []string{`"container":null`, `"since":null`, `"host_egress_ip":null`} {
		if !strings.Contains(string(blob), want) {
			t.Fatalf("missing %s in %s", want, blob)
		}
	}
}

// The optional arguments have to reach internal/vpn, or --skip-egress on a
// polled screen would silently still pay for two network round trips.
func TestExternalStatusForwardsItsArguments(t *testing.T) {
	spec := withExternalStatus(t, vpn.ExternalStatusReport{}, nil)
	if _, err := upHandler().VPNExternalStatus(context.Background(), map[string]any{
		"iface": "wg7", "table": float64(202), "skip_egress": true,
	}); err != nil {
		t.Fatalf("VPNExternalStatus: %v", err)
	}
	if spec.Iface != "wg7" || spec.Table != 202 || !spec.SkipEgress {
		t.Fatalf("arguments were dropped: %+v", spec)
	}
}

// "Nothing is up" is a true ANSWER, not a refusal and not an error. A status
// verb that errored on an unconfigured host would make every such host look
// broken on the screen.
func TestExternalStatusOnAnIdleHostIsNotAnError(t *testing.T) {
	withExternalStatus(t, vpn.ExternalStatusReport{Iface: "wg0", Table: 200}, nil)
	out, err := upHandler().VPNExternalStatus(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("an idle host must not error: %v", err)
	}
	if out["up"] != false || out["refused"] != nil {
		t.Fatalf("idle host reply = %v", out)
	}
}

func TestExternalStatusIsARegisteredVerb(t *testing.T) {
	withExternalStatus(t, vpn.ExternalStatusReport{Iface: "wg0", Table: 200}, nil)
	if _, err := upHandler().Dispatch(context.Background(), "vpn_external_status", map[string]any{}, nil); err != nil {
		t.Fatalf("vpn_external_status is not routed: %v", err)
	}
}
