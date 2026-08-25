package firewall

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// nftFamily/nftTable are OUR OWN nftables table — deliberately NOT the "ip
// filter" table iptables/iptables-nft/docker manage. A base chain's hook +
// priority (not its table) is what decides evaluation order in nftables, so
// a chain hooked here at priority nftPriority runs regardless of whatever
// docker/podman installed in a completely different table, with no jump
// insertion into DOCKER-USER/INPUT required at all — which sidesteps
// whether DOCKER-USER even exists (rootless podman may never create it;
// see RISK 1 in the delivery report) and the -C/-I ordering games the
// iptables backend needs.
const (
	nftFamily = "inet"
	nftTable  = "aw_fw"
	// nftPriority runs before the default (0) priority most iptables-nft
	// and docker/podman-installed rules use, so our DROP is terminal for a
	// packet before any permissive rule elsewhere gets a chance to ACCEPT
	// it first.
	nftPriority = "-1"
)

// nftBackend is preferred over iptables whenever the nft binary exists
// (Card B instructions) — RISK 2 there explains why: on an iptables-nft
// host, iptables' own -C existence checks can misreport against state nft
// itself owns.
type nftBackend struct {
	runner Runner
}

func (b nftBackend) Probe(ctx context.Context) (string, bool, string, error) {
	out, err := b.runner.Run(ctx, "nft", "list", "ruleset")
	privileged, reason := classifyPrivilege(out, err)
	return "nft", privileged, reason, nil
}

func (b nftBackend) Apply(ctx context.Context, rules []Rule, lockdown bool) error {
	// buildRuleset's baseline always opens with a `ct state
	// ESTABLISHED,RELATED` match, so nft_ct has to be loaded before the
	// very first rule of the very first Apply on a host — see
	// ensureConntrackModule's own comment for why this can't be skipped.
	if err := b.ensureConntrackModule(ctx); err != nil {
		return err
	}

	ruleset := buildRuleset(rules, lockdown)

	if out, err := b.runner.Run(ctx, "nft", "add", "table", nftFamily, nftTable); err != nil {
		return fmt.Errorf("create table %s %s: %w (%s)", nftFamily, nftTable, err, strings.TrimSpace(out))
	}

	for _, chainSpec := range []struct{ name, hook string }{
		{ChainIn, "input"},
		{ChainFWD, "forward"},
	} {
		if err := b.ensureChain(ctx, chainSpec.name, chainSpec.hook); err != nil {
			return err
		}
		for _, r := range ruleset {
			if out, err := b.runner.Run(ctx, "nft", nftRuleArgs(chainSpec.name, r)...); err != nil {
				return fmt.Errorf("apply rule to %s: %w (%s)", chainSpec.name, err, strings.TrimSpace(out))
			}
		}
	}
	return nil
}

// ensureConntrackModule loads nft_ct — the kernel module nftables' native
// `ct` expression needs, distinct from nf_conntrack/xt_conntrack (which
// iptables-legacy/docker already load, and which do NOT satisfy nft's own
// `ct` expression). On a fresh/minimal host that has never used nftables
// conntrack matching before, nft_ct is simply not loaded, and every rule
// using `ct state` — including the baseline — fails with a bare "exit
// status 1" that gives no hint a kernel module is missing (2026-08-25 card:
// reproduced on a real host, fixed instantly by a manual `modprobe nft_ct`).
//
// modprobe is idempotent — loading an already-loaded or kernel-builtin
// module is a no-op success — so this call is safe on every Apply, not just
// the first one on a given host, and never disrupts a host that already has
// nft_ct loaded. A genuine failure (module not present for this kernel,
// needs a different package, no permission to load kernel modules) is
// propagated with its real output instead of being swallowed, so the next
// person to hit this doesn't have to rediscover it over SSH.
func (b nftBackend) ensureConntrackModule(ctx context.Context) error {
	if out, err := b.runner.Run(ctx, "modprobe", "nft_ct"); err != nil {
		return fmt.Errorf("load kernel module nft_ct: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (b nftBackend) Status(ctx context.Context) (State, error) {
	_, privileged, reason, _ := b.Probe(ctx)
	st := State{Backend: "nft", Privileged: privileged, PrivilegedReason: reason}
	if privileged {
		if out, err := b.runner.Run(ctx, "nft", "-a", "list", "chain", nftFamily, nftTable, ChainIn); err == nil {
			st.Chain = splitLines(out)
		}
	}
	return st, nil
}

// ensureChain creates chain as a hooked base chain (policy accept — the
// same "fall through to accept unless a rule says otherwise" behaviour
// buildRuleset's lockdown=false case relies on) if it doesn't exist yet,
// tolerating an error either way (an identical spec on an already-existing
// chain is a no-op on real nft; anything else surfaces on the flush right
// after), then flushes it — full-state, never incremental, same as the
// iptables backend.
func (b nftBackend) ensureChain(ctx context.Context, name, hook string) error {
	spec := fmt.Sprintf("{ type filter hook %s priority %s; policy accept; }", hook, nftPriority)
	_, _ = b.runner.Run(ctx, "nft", "add", "chain", nftFamily, nftTable, name, spec)
	if out, err := b.runner.Run(ctx, "nft", "flush", "chain", nftFamily, nftTable, name); err != nil {
		return fmt.Errorf("flush chain %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	return nil
}

func nftRuleArgs(chain string, r chainRule) []string {
	args := []string{"add", "rule", nftFamily, nftTable, chain}
	if r.Interface != "" {
		args = append(args, "iifname", r.Interface)
	}
	if r.StateMatch != "" {
		args = append(args, "ct", "state", strings.ToLower(r.StateMatch))
	}
	if r.SourceCIDR != "" {
		args = append(args, "ip", "saddr", r.SourceCIDR)
	}
	if r.Protocol != "" && r.PortFrom != 0 {
		port := strconv.Itoa(r.PortFrom)
		if r.PortTo != r.PortFrom {
			port = fmt.Sprintf("%d-%d", r.PortFrom, r.PortTo)
		}
		args = append(args, r.Protocol, "dport", port)
	}
	verdict := "accept"
	if r.Action == "DROP" {
		verdict = "drop"
	}
	return append(args, verdict)
}
