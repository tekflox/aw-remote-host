package firewall

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firewall.json")

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load (missing file): %v", err)
	}
	if p != nil {
		t.Fatalf("Load on a missing file must return (nil, nil), got %+v", p)
	}

	rules := []Rule{{Action: "allow", Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Priority: 100}}
	if err := Save(path, rules, true, 3); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load (after save): %v", err)
	}
	if reloaded == nil {
		t.Fatalf("Load after Save returned nil")
	}
	if !reloaded.Lockdown || reloaded.Revision != 3 || len(reloaded.Rules) != 1 {
		t.Fatalf("round-trip mismatch: %+v", reloaded)
	}
	if reloaded.Rules[0].PortFrom != 8080 {
		t.Fatalf("rule did not round-trip: %+v", reloaded.Rules[0])
	}
}

func TestSelfHealNoopWithoutPriorState(t *testing.T) {
	origGoos, origLookPath := goos, lookPath
	goos, lookPath = "linux", func(string) (string, error) { return "", errors.New("not found") }
	defer func() { goos, lookPath = origGoos, origLookPath }()

	r := newFakeRunner()
	// A fresh host with nothing in ~/.aw-remote-host/firewall.json must not
	// shell out to any firewall backend at all.
	origStatePath := statePathOverride
	statePathOverride = func() (string, error) { return filepath.Join(t.TempDir(), "firewall.json"), nil }
	defer func() { statePathOverride = origStatePath }()

	if err := SelfHeal(context.Background(), r); err != nil {
		t.Fatalf("SelfHeal on a never-configured host must be a no-op, got: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("SelfHeal must not shell out when there is no persisted state, got calls: %v", r.calls)
	}
}

func TestSelfHealReappliesPersistedState(t *testing.T) {
	origGoos, origLookPath := goos, lookPath
	goos, lookPath = "linux", func(name string) (string, error) {
		if name == "nft" {
			return "", errors.New("not found")
		}
		return "/usr/sbin/" + name, nil
	}
	defer func() { goos, lookPath = origGoos, origLookPath }()

	path := filepath.Join(t.TempDir(), "firewall.json")
	origStatePath := statePathOverride
	statePathOverride = func() (string, error) { return path, nil }
	defer func() { statePathOverride = origStatePath }()

	rules := []Rule{{Action: "allow", Protocol: "tcp", PortFrom: 22, PortTo: 22, Priority: 100}}
	if err := Save(path, rules, true, 5); err != nil {
		t.Fatalf("Save: %v", err)
	}

	r := newFakeRunner() // unprivileged-by-default (Probe succeeds => privileged=true)
	if err := SelfHeal(context.Background(), r); err != nil {
		t.Fatalf("SelfHeal: %v", err)
	}
	if calls := r.callsWithPrefix("-A", ChainIn); len(calls) == 0 {
		t.Fatalf("expected SelfHeal to reapply the persisted rules to %s, got calls: %v", ChainIn, r.calls)
	}
}

func TestSelfHealSkipsWhenUnprivileged(t *testing.T) {
	origGoos, origLookPath := goos, lookPath
	goos, lookPath = "linux", func(name string) (string, error) {
		if name == "nft" {
			return "", errors.New("not found")
		}
		return "/usr/sbin/" + name, nil
	}
	defer func() { goos, lookPath = origGoos, origLookPath }()

	path := filepath.Join(t.TempDir(), "firewall.json")
	origStatePath := statePathOverride
	statePathOverride = func() (string, error) { return path, nil }
	defer func() { statePathOverride = origStatePath }()

	if err := Save(path, nil, false, 1); err != nil {
		t.Fatalf("Save: %v", err)
	}

	r := newFakeRunner()
	r.fail(errors.New("Operation not permitted"), "iptables", "-S", "-t", "filter")

	if err := SelfHeal(context.Background(), r); err != nil {
		t.Fatalf("SelfHeal must not error just because the host is unprivileged: %v", err)
	}
	if calls := r.callsWithPrefix("-N"); len(calls) != 0 {
		t.Fatalf("an unprivileged self-heal must not attempt to apply anything, got calls: %v", r.calls)
	}
}
