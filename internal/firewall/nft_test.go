package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNftApply_TableAndHookedChains(t *testing.T) {
	r := newFakeRunner()
	b := nftBackend{runner: r}

	rules := []Rule{{Action: "allow", Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Priority: 100}}
	if err := b.Apply(context.Background(), rules, true); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if calls := r.callsWithPrefix("add", "table", nftFamily, nftTable); len(calls) != 1 {
		t.Fatalf("expected the aw_fw table to be created once, got %v", calls)
	}
	for _, spec := range []struct{ name, hook string }{{ChainIn, "input"}, {ChainFWD, "forward"}} {
		if calls := r.callsWithPrefix("add", "chain", nftFamily, nftTable, spec.name); len(calls) != 1 {
			t.Fatalf("expected chain %s to be created once, got %v", spec.name, calls)
		}
		if calls := r.callsWithPrefix("flush", "chain", nftFamily, nftTable, spec.name); len(calls) != 1 {
			t.Fatalf("expected chain %s to be flushed exactly once (full-state apply), got %v", spec.name, calls)
		}
		userRule := r.callsWithPrefix("add", "rule", nftFamily, nftTable, spec.name, "tcp", "dport", "8080", "accept")
		if len(userRule) != 1 {
			t.Fatalf("expected the user rule in %s, got calls: %v", spec.name, r.calls)
		}
		catchAll := r.callsWithPrefix("add", "rule", nftFamily, nftTable, spec.name, "drop")
		if len(catchAll) != 1 {
			t.Fatalf("expected the trailing lockdown drop verdict in %s, got calls: %v", spec.name, r.calls)
		}
	}
}

func TestNftApply_StillFlushesWhenChainAlreadyExists(t *testing.T) {
	r := newFakeRunner()
	spec := "{ type filter hook input priority -1; policy accept; }"
	r.fail(errors.New("Object already exists"), "nft", "add", "chain", nftFamily, nftTable, ChainIn, spec)
	b := nftBackend{runner: r}

	if err := b.Apply(context.Background(), nil, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if calls := r.callsWithPrefix("flush", "chain", nftFamily, nftTable, ChainIn); len(calls) != 1 {
		t.Fatalf("an 'already exists' add-chain error must not skip the flush (full-state, not incremental): got %v", calls)
	}
}

func TestNftApply_PropagatesFlushFailure(t *testing.T) {
	r := newFakeRunner()
	r.fail(errors.New("no such file or directory"), "nft", "flush", "chain", nftFamily, nftTable, ChainIn)
	b := nftBackend{runner: r}

	if err := b.Apply(context.Background(), nil, false); err == nil {
		t.Fatalf("expected Apply to fail when the chain flush itself fails")
	}
}

func TestNftApply_LoadsConntrackModuleFirst(t *testing.T) {
	r := newFakeRunner()
	b := nftBackend{runner: r}

	if err := b.Apply(context.Background(), nil, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if calls := r.callsWithPrefix("nft_ct"); len(calls) != 1 {
		t.Fatalf("expected modprobe nft_ct to run exactly once, got %v", r.calls)
	}
	if len(r.calls) == 0 || r.calls[0][0] != "modprobe" || r.calls[0][1] != "nft_ct" {
		t.Fatalf("expected modprobe nft_ct to be the FIRST command run, got %v", r.calls)
	}
}

func TestNftApply_PropagatesModprobeFailure(t *testing.T) {
	r := newFakeRunner()
	r.on("modprobe: FATAL: Module nft_ct not found in directory /lib/modules/7.0.0-22-generic", "modprobe", "nft_ct")
	r.fail(errors.New("exit status 1"), "modprobe", "nft_ct")
	b := nftBackend{runner: r}

	err := b.Apply(context.Background(), nil, false)
	if err == nil {
		t.Fatalf("expected Apply to fail when modprobe nft_ct fails")
	}
	if !strings.Contains(err.Error(), "nft_ct") || !strings.Contains(err.Error(), "not found in directory") {
		t.Fatalf("expected the real modprobe stderr in the error, got: %v", err)
	}
	if calls := r.callsWithPrefix("add", "table"); len(calls) != 0 {
		t.Fatalf("expected Apply to bail out before touching nft state when modprobe fails, got %v", calls)
	}
}

func TestNftApply_PropagatesRuleApplyStderr(t *testing.T) {
	r := newFakeRunner()
	stderr := "Error: Could not process rule: No such file or directory\nadd rule inet aw_fw AW-FW-IN ct state established,related accept\n                             ^^^^^^^^"
	r.on(stderr, "nft", "add", "rule", nftFamily, nftTable, ChainIn, "ct", "state", "established,related", "accept")
	r.fail(errors.New("exit status 1"), "nft", "add", "rule", nftFamily, nftTable, ChainIn, "ct", "state", "established,related", "accept")
	b := nftBackend{runner: r}

	err := b.Apply(context.Background(), nil, false)
	if err == nil {
		t.Fatalf("expected Apply to fail when nft add rule fails")
	}
	if !strings.Contains(err.Error(), "No such file or directory") {
		t.Fatalf("expected the real nft stderr (not just the exit code) in the error, got: %v", err)
	}
}

func TestNftProbeUnprivileged(t *testing.T) {
	r := newFakeRunner()
	r.fail(errors.New("exit status 1"), "nft", "list", "ruleset")
	r.on("Error: Could not process rule: Operation not permitted", "nft", "list", "ruleset")
	b := nftBackend{runner: r}

	name, privileged, reason, err := b.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe returned an error, want a clean privileged=false verdict: %v", err)
	}
	if name != "nft" || privileged || reason == "" {
		t.Fatalf("Probe = (%q, %v, %q), want (nft, false, non-empty reason)", name, privileged, reason)
	}
}
