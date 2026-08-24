package firewall

import (
	"context"
	"fmt"
)

// unsupportedBackend is what DetectBackend returns on macOS/Windows, or on
// a Linux host with neither nft nor iptables on PATH. v1 is Linux-only on
// purpose (Card B PO refinement, 2026-08-24) — this reports honestly
// instead of guessing at a pf/netsh implementation, which is scoped as a
// future card, not something to improvise here.
type unsupportedBackend struct {
	reason string
}

func (b unsupportedBackend) Probe(ctx context.Context) (string, bool, string, error) {
	return "unsupported", false, b.reason, nil
}

func (b unsupportedBackend) Apply(ctx context.Context, rules []Rule, lockdown bool) error {
	return fmt.Errorf("firewall management is not supported on this host: %s", b.reason)
}

func (b unsupportedBackend) Status(ctx context.Context) (State, error) {
	return State{Backend: "unsupported", Privileged: false, PrivilegedReason: b.reason}, nil
}
