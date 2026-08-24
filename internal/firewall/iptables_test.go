package firewall

import (
	"context"
	"errors"
	"testing"
)

func TestIptablesApply_FreshHost(t *testing.T) {
	r := newFakeRunner()
	// Fresh host: chains don't exist yet, jumps aren't installed, DOCKER-USER exists.
	r.fail(errors.New("chain already exists"), "iptables", "-C", "INPUT", "-j", ChainIn)
	r.fail(errors.New("no jump"), "iptables", "-C", "DOCKER-USER", "-j", ChainFWD)
	b := iptablesBackend{runner: r}

	rules := []Rule{{Action: "allow", Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Priority: 100}}
	if err := b.Apply(context.Background(), rules, true); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if calls := r.callsWithPrefix("-N", ChainIn); len(calls) != 1 {
		t.Fatalf("expected one chain-create call for %s, got %v", ChainIn, calls)
	}
	if calls := r.callsWithPrefix("-I", "INPUT"); len(calls) != 1 {
		t.Fatalf("expected the INPUT jump to be inserted once, got %v", calls)
	}
	if calls := r.callsWithPrefix("-I", "DOCKER-USER", "1"); len(calls) != 1 {
		t.Fatalf("expected the DOCKER-USER jump to be inserted at position 1, got %v", calls)
	}
	// The 8080 user rule and the trailing lockdown DROP must both land in
	// BOTH chains (Card B: same rule set, no native-vs-container split).
	for _, chain := range []string{ChainIn, ChainFWD} {
		userRule := r.callsWithPrefix("-A", chain, "-p", "tcp", "--dport", "8080", "-j", "ACCEPT")
		if len(userRule) != 1 {
			t.Fatalf("expected the user rule in %s, got calls: %v", chain, r.calls)
		}
		catchAll := r.callsWithPrefix("-A", chain, "-j", "DROP")
		if len(catchAll) != 1 {
			t.Fatalf("expected the trailing lockdown DROP in %s, got calls: %v", chain, r.calls)
		}
	}
}

func TestIptablesApply_AlreadyConfiguredIsIdempotent(t *testing.T) {
	r := newFakeRunner()
	// Chain already exists (-N fails) and jump already installed (-C succeeds).
	r.fail(errors.New("Chain already exists"), "iptables", "-N", ChainIn)
	r.fail(errors.New("Chain already exists"), "iptables", "-N", ChainFWD)
	b := iptablesBackend{runner: r}

	if err := b.Apply(context.Background(), nil, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if calls := r.callsWithPrefix("-I", "INPUT"); len(calls) != 0 {
		t.Fatalf("jump already present — must not be re-inserted, got %v", calls)
	}
	if calls := r.callsWithPrefix("-I", "DOCKER-USER"); len(calls) != 0 {
		t.Fatalf("DOCKER-USER jump already present — must not be re-inserted, got %v", calls)
	}
	// Still full-state: the chain gets flushed and rebuilt every call.
	if calls := r.callsWithPrefix("-F", ChainIn); len(calls) != 1 {
		t.Fatalf("expected exactly one flush of %s (full-state re-apply), got %v", ChainIn, calls)
	}
	if calls := r.callsWithPrefix("-A", ChainIn); len(calls) == 0 {
		t.Fatalf("expected baseline rules to be re-added to %s even though nothing changed", ChainIn)
	}
}

func TestIptablesApply_NoDockerUserFallsBackToForward(t *testing.T) {
	r := newFakeRunner()
	r.fail(errors.New("No chain/target/match by that name"), "iptables", "-nL", "DOCKER-USER")
	r.fail(errors.New("no jump"), "iptables", "-C", "FORWARD", "-j", ChainFWD)
	b := iptablesBackend{runner: r}

	if err := b.Apply(context.Background(), nil, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if calls := r.callsWithPrefix("-I", "FORWARD", "1"); len(calls) != 1 {
		t.Fatalf("expected fallback jump into FORWARD when DOCKER-USER is absent, got calls: %v", r.calls)
	}
	if calls := r.callsWithPrefix("-I", "DOCKER-USER"); len(calls) != 0 {
		t.Fatalf("must not target a DOCKER-USER chain that doesn't exist, got %v", calls)
	}
}

func TestIptablesProbeUnprivileged(t *testing.T) {
	r := newFakeRunner()
	r.fail(errors.New("exit status 4"), "iptables", "-S", "-t", "filter")
	r.on("iptables v1.8.9 (legacy): Permission denied (you must be root)", "iptables", "-S", "-t", "filter")
	b := iptablesBackend{runner: r}

	name, privileged, reason, err := b.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe returned an error, want a clean privileged=false verdict: %v", err)
	}
	if name != "iptables" {
		t.Fatalf("name = %q, want iptables", name)
	}
	if privileged {
		t.Fatalf("privileged = true, want false (probe was scripted to fail with EPERM)")
	}
	if reason == "" {
		t.Fatalf("reason must not be empty when privileged=false")
	}
}

func TestIptablesStatusReflectsPrivilege(t *testing.T) {
	r := newFakeRunner()
	r.fail(errors.New("Operation not permitted"), "iptables", "-S", "-t", "filter")
	b := iptablesBackend{runner: r}

	st, err := b.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Backend != "iptables" || st.Privileged {
		t.Fatalf("Status = %+v, want backend=iptables privileged=false", st)
	}
	if st.PrivilegedReason == "" {
		t.Fatalf("PrivilegedReason must be set when privileged=false")
	}
	if st.Chain != nil {
		t.Fatalf("Chain dump must be skipped when unprivileged, got %v", st.Chain)
	}
}
