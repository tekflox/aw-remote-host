package main

import (
	"strings"
	"testing"
)

// Go's flag package stops parsing at the first non-flag argument, so
// `vpn use-exit aw-baremetal --plan` — the way a human actually types it —
// would parse ZERO flags and treat --plan as a second positional. On a
// command that moves the default route, "your --plan was silently ignored and
// it ran for real" is not an acceptable way to discover that.
//
// Caught on the live lab node on 2026-08-25, where the first --plan run
// failed with the usage message instead of printing a plan.
func TestSplitLeadingArgLetsFlagsFollowTheNode(t *testing.T) {
	node, rest := splitLeadingArg([]string{"aw-baremetal", "--plan", "--deadman=90s"})
	if node != "aw-baremetal" {
		t.Fatalf("node = %q", node)
	}
	if strings.Join(rest, " ") != "--plan --deadman=90s" {
		t.Fatalf("rest = %v", rest)
	}
}

func TestSplitLeadingArgLeavesFlagsFirstFormAlone(t *testing.T) {
	// `use-exit --plan aw-baremetal` still has to work; there the node is
	// picked up by flag.Parse as the trailing positional.
	node, rest := splitLeadingArg([]string{"--plan", "aw-baremetal"})
	if node != "" {
		t.Fatalf("a leading flag must not be mistaken for the node, got %q", node)
	}
	if len(rest) != 2 {
		t.Fatalf("rest = %v", rest)
	}
}

func TestSplitLeadingArgOnNoArgs(t *testing.T) {
	node, rest := splitLeadingArg(nil)
	if node != "" || len(rest) != 0 {
		t.Fatalf("node = %q rest = %v", node, rest)
	}
}
