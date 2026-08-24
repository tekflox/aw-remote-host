package firewall

import (
	"context"
	"fmt"
	"strconv"
)

// iptablesBackend is the fallback used when the nft binary isn't on PATH.
// RISK 2 (Card B instructions): on an iptables-nft host, -C existence
// checks can misreport and tables end up mixed with native nft state — nft
// is preferred whenever it's available for exactly this reason.
type iptablesBackend struct {
	runner Runner
}

func (b iptablesBackend) Probe(ctx context.Context) (string, bool, string, error) {
	out, err := b.runner.Run(ctx, "iptables", "-S", "-t", "filter")
	privileged, reason := classifyPrivilege(out, err)
	return "iptables", privileged, reason, nil
}

// Apply rebuilds AW-FW-IN (jumped from INPUT) and AW-FW-FWD (jumped from
// DOCKER-USER when it exists, else FORWARD directly — see forwardHook)
// from scratch every call: -N-or-F makes chain creation idempotent, -C-or-I
// makes the jump insertion idempotent, and flushing before re-adding rules
// is what makes the whole thing full-state rather than incremental (Card B
// instructions — "NUNCA INCREMENTAL").
func (b iptablesBackend) Apply(ctx context.Context, rules []Rule, lockdown bool) error {
	ruleset := buildRuleset(rules, lockdown)

	if err := b.ensureChain(ctx, ChainIn); err != nil {
		return err
	}
	if err := b.ensureJump(ctx, "INPUT", ChainIn, false); err != nil {
		return err
	}
	if err := b.applyRules(ctx, ChainIn, ruleset); err != nil {
		return err
	}

	fwdHook := b.forwardHook(ctx)
	if err := b.ensureChain(ctx, ChainFWD); err != nil {
		return err
	}
	if err := b.ensureJump(ctx, fwdHook, ChainFWD, true); err != nil {
		return err
	}
	return b.applyRules(ctx, ChainFWD, ruleset)
}

func (b iptablesBackend) Status(ctx context.Context) (State, error) {
	_, privileged, reason, _ := b.Probe(ctx)
	st := State{Backend: "iptables", Privileged: privileged, PrivilegedReason: reason}
	if privileged {
		if out, err := b.runner.Run(ctx, "iptables", "-S", ChainIn); err == nil {
			st.Chain = splitLines(out)
		}
	}
	return st, nil
}

// ensureChain creates chain if missing, or flushes it if it already exists
// — the same "-N or -F" idempotent pattern aw-firewall-apply.sh uses.
func (b iptablesBackend) ensureChain(ctx context.Context, chain string) error {
	if _, err := b.runner.Run(ctx, "iptables", "-N", chain); err != nil {
		if _, err := b.runner.Run(ctx, "iptables", "-F", chain); err != nil {
			return fmt.Errorf("flush chain %s: %w", chain, err)
		}
	}
	return nil
}

// ensureJump inserts a jump into hook -> chain exactly once ("-C or -I",
// same idempotent pattern as ensureChain). insertHead mirrors
// aw-firewall-apply.sh's DOCKER-USER insertion at explicit position 1 —
// Docker/podman guarantee that chain is never flushed/rewritten by the
// container runtime, so being first there matters; INPUT gets a plain -I
// (head) since nothing else owns position 1 there the same way.
func (b iptablesBackend) ensureJump(ctx context.Context, hook, chain string, insertHead bool) error {
	if _, err := b.runner.Run(ctx, "iptables", "-C", hook, "-j", chain); err == nil {
		return nil
	}
	args := []string{"-I", hook}
	if insertHead {
		args = append(args, "1")
	}
	args = append(args, "-j", chain)
	if _, err := b.runner.Run(ctx, "iptables", args...); err != nil {
		return fmt.Errorf("insert jump %s -> %s: %w", hook, chain, err)
	}
	return nil
}

// forwardHook targets DOCKER-USER when it exists (Docker's own guarantee
// that the chain survives daemon restarts/rule reloads) and falls back to
// FORWARD directly otherwise — a rootless podman host, in particular, may
// never create DOCKER-USER at all (RISK 1, Card B instructions: rootless
// port publishing can go through a userspace proxy instead of iptables NAT,
// so DOCKER-USER may not even be the right — or only — place traffic is
// ever seen; unverified without a real host, see the delivery report).
func (b iptablesBackend) forwardHook(ctx context.Context) string {
	if _, err := b.runner.Run(ctx, "iptables", "-nL", "DOCKER-USER"); err == nil {
		return "DOCKER-USER"
	}
	return "FORWARD"
}

func (b iptablesBackend) applyRules(ctx context.Context, chain string, ruleset []chainRule) error {
	for _, r := range ruleset {
		if _, err := b.runner.Run(ctx, "iptables", iptablesRuleArgs(chain, r)...); err != nil {
			return fmt.Errorf("apply rule to %s: %w", chain, err)
		}
	}
	return nil
}

func iptablesRuleArgs(chain string, r chainRule) []string {
	args := []string{"-A", chain}
	if r.Interface != "" {
		args = append(args, "-i", r.Interface)
	}
	if r.StateMatch != "" {
		args = append(args, "-m", "state", "--state", r.StateMatch)
	}
	if r.Protocol != "" {
		args = append(args, "-p", r.Protocol)
	}
	if r.SourceCIDR != "" {
		args = append(args, "-s", r.SourceCIDR)
	}
	if r.PortFrom != 0 {
		port := strconv.Itoa(r.PortFrom)
		if r.PortTo != r.PortFrom {
			port = fmt.Sprintf("%d:%d", r.PortFrom, r.PortTo)
		}
		args = append(args, "--dport", port)
	}
	return append(args, "-j", r.Action)
}
