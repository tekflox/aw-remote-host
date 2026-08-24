package ops

import (
	"context"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/firewall"
)

// Firewall verbs must never be gated behind podman — the whole point (Card
// B instructions) is that they work on a lean host that has no local
// workspace runtime at all, which is exactly the host most worth
// firewalling.
func TestFirewallVerbsAreNotWorkspaceLifecycleVerbs(t *testing.T) {
	if workspaceLifecycleVerbs["firewall_apply"] {
		t.Fatal("firewall_apply must not be in workspaceLifecycleVerbs")
	}
	if workspaceLifecycleVerbs["firewall_status"] {
		t.Fatal("firewall_status must not be in workspaceLifecycleVerbs")
	}
}

// fakeBackend stands in for internal/firewall's real backends — this
// package can't reach their unexported types directly, and doesn't need
// to: Dispatch's job is wiring args in and the response shape out, which is
// exactly what a scripted firewall.Backend exercises without needing a real
// iptables/nft binary on whatever machine runs `go test`.
type fakeBackend struct {
	name       string
	privileged bool
	reason     string
	applyErr   error
	applyCalls int
}

func (b *fakeBackend) Probe(context.Context) (string, bool, string, error) {
	return b.name, b.privileged, b.reason, nil
}

func (b *fakeBackend) Apply(context.Context, []firewall.Rule, bool) error {
	b.applyCalls++
	return b.applyErr
}

func (b *fakeBackend) Status(context.Context) (firewall.State, error) {
	return firewall.State{Backend: b.name, Privileged: b.privileged, PrivilegedReason: b.reason}, nil
}

func withFirewallBackend(t *testing.T, b firewall.Backend) {
	t.Helper()
	orig := detectFirewallBackend
	detectFirewallBackend = func(firewall.Runner) firewall.Backend { return b }
	t.Cleanup(func() { detectFirewallBackend = orig })
}

func TestDispatchFirewallApplyUnprivileged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fb := &fakeBackend{name: "iptables", privileged: false, reason: "no NOPASSWD sudoers entry"}
	withFirewallBackend(t, fb)

	h := &Handler{Runner: newFakeRunner()}
	emit, lines := collectEmits()

	args := map[string]any{"rules": []any{}, "lockdown": true, "revision": float64(1)}
	data, err := h.Dispatch(context.Background(), "firewall_apply", args, emit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := data.(map[string]any)
	if out["privileged"] != false {
		t.Fatalf("privileged = %v, want false", out["privileged"])
	}
	if out["privileged_reason"] != "no NOPASSWD sudoers entry" {
		t.Fatalf("privileged_reason = %v, want the probe's reason passed through", out["privileged_reason"])
	}
	if out["backend"] != "iptables" {
		t.Fatalf("backend = %v, want iptables", out["backend"])
	}
	if fb.applyCalls != 0 {
		t.Fatalf("must not attempt Apply when unprivileged, got %d call(s)", fb.applyCalls)
	}
	found := false
	for _, l := range *lines {
		if l != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one emit explaining why nothing was applied")
	}
}

func TestDispatchFirewallApplyPrivilegedPersistsSelfHealCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fb := &fakeBackend{name: "nft", privileged: true}
	withFirewallBackend(t, fb)

	h := &Handler{Runner: newFakeRunner()}
	emit, _ := collectEmits()

	args := map[string]any{
		"rules": []any{
			map[string]any{"action": "allow", "protocol": "tcp", "port_from": float64(8080), "port_to": float64(8080), "priority": float64(100)},
		},
		"lockdown": true,
		"revision": float64(7),
	}
	data, err := h.Dispatch(context.Background(), "firewall_apply", args, emit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := data.(map[string]any)
	if out["privileged"] != true || out["applied_revision"] != 7 {
		t.Fatalf("unexpected response: %+v", out)
	}
	if fb.applyCalls != 1 {
		t.Fatalf("expected exactly one Apply call, got %d", fb.applyCalls)
	}
	if _, hasReason := out["privileged_reason"]; hasReason {
		t.Fatalf("privileged_reason must be absent when privileged=true, got %+v", out)
	}

	path, err := firewall.StatePath()
	if err != nil {
		t.Fatalf("StatePath: %v", err)
	}
	p, err := firewall.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p == nil || p.Revision != 7 || !p.Lockdown || len(p.Rules) != 1 {
		t.Fatalf("self-heal cache did not persist correctly: %+v", p)
	}
	if p.Rules[0].PortFrom != 8080 {
		t.Fatalf("persisted rule mismatch: %+v", p.Rules[0])
	}
}

func TestDispatchFirewallApplyPropagatesApplyFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fb := &fakeBackend{name: "iptables", privileged: true, applyErr: context.DeadlineExceeded}
	withFirewallBackend(t, fb)

	h := &Handler{Runner: newFakeRunner()}
	emit, _ := collectEmits()

	_, err := h.Dispatch(context.Background(), "firewall_apply", map[string]any{}, emit)
	if err == nil {
		t.Fatal("expected Dispatch to surface the backend's Apply error (so it reaches aw-backend as CommandFailed)")
	}
}

func TestDispatchFirewallStatus(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fb := &fakeBackend{name: "nft", privileged: false, reason: "unsupported OS"}
	withFirewallBackend(t, fb)

	h := &Handler{Runner: newFakeRunner()}
	emit, _ := collectEmits()

	data, err := h.Dispatch(context.Background(), "firewall_status", nil, emit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := data.(map[string]any)
	if out["backend"] != "nft" || out["privileged"] != false || out["privileged_reason"] != "unsupported OS" {
		t.Fatalf("unexpected status response: %+v", out)
	}
}
