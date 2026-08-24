package firewall

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestBuildRulesetBaselineAlwaysFirst(t *testing.T) {
	out := buildRuleset(nil, false)
	if len(out) != 6 {
		t.Fatalf("baseline-only ruleset length = %d, want 6 (established, lo, ssh, 3x rfc1918 lanfastpath)", len(out))
	}
	if out[0].StateMatch != "ESTABLISHED,RELATED" || out[0].Action != "ACCEPT" {
		t.Fatalf("out[0] = %+v, want the ESTABLISHED,RELATED baseline entry first", out[0])
	}
	if out[1].Interface != "lo" || out[1].Action != "ACCEPT" {
		t.Fatalf("out[1] = %+v, want the loopback baseline entry second", out[1])
	}
	if out[2].PortFrom != 22 || out[2].PortTo != 22 || out[2].Protocol != "tcp" {
		t.Fatalf("out[2] = %+v, want the ssh baseline entry third", out[2])
	}
	for i, cidr := range rfc1918 {
		r := out[3+i]
		if r.PortFrom != 8443 || r.SourceCIDR != cidr || r.Action != "ACCEPT" {
			t.Fatalf("out[%d] = %+v, want lanfastpath baseline entry for %s", 3+i, r, cidr)
		}
	}
	// No lockdown => no trailing catch-all.
	if out[len(out)-1].StateMatch != "" && out[len(out)-1].SourceCIDR == "" && out[len(out)-1].PortFrom == 0 && out[len(out)-1].Interface == "" {
		// this would only be the trailing catch-all shape; make sure it's actually the RFC1918 entry, not an extra DROP.
		if out[len(out)-1].Action == "DROP" {
			t.Fatalf("lockdown=false must not append a trailing catch-all DROP, got %+v", out[len(out)-1])
		}
	}
}

func TestBuildRulesetPriorityOrderAndLockdown(t *testing.T) {
	rules := []Rule{
		{Action: "allow", Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Priority: 200},
		{Action: "deny", Protocol: "tcp", PortFrom: 9090, PortTo: 9090, Priority: 100},
	}
	out := buildRuleset(rules, true)
	// 6 baseline + 2 user rules + 1 trailing catch-all.
	if len(out) != 9 {
		t.Fatalf("ruleset length = %d, want 9", len(out))
	}
	deny := out[6]
	if deny.PortFrom != 9090 || deny.Action != "DROP" {
		t.Fatalf("lower-priority rule (100) should sort before the 200 one: got %+v", deny)
	}
	allow := out[7]
	if allow.PortFrom != 8080 || allow.Action != "ACCEPT" {
		t.Fatalf("higher-priority rule (200) should sort after the 100 one: got %+v", allow)
	}
	catchAll := out[8]
	if catchAll.Action != "DROP" || catchAll.PortFrom != 0 || catchAll.SourceCIDR != "" {
		t.Fatalf("lockdown=true must append an unconditional trailing DROP, got %+v", catchAll)
	}
}

func TestBuildRulesetStablePriorityTies(t *testing.T) {
	rules := []Rule{
		{Action: "allow", Protocol: "tcp", PortFrom: 1, PortTo: 1, Priority: 100},
		{Action: "allow", Protocol: "tcp", PortFrom: 2, PortTo: 2, Priority: 100},
	}
	out := buildRuleset(rules, false)
	if out[len(out)-2].PortFrom != 1 || out[len(out)-1].PortFrom != 2 {
		t.Fatalf("equal-priority rules must keep arrival order, got %+v then %+v", out[len(out)-2], out[len(out)-1])
	}
}

func TestClassifyPrivilege(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		err       error
		wantPriv  bool
		wantMatch string
	}{
		{"success", "-A INPUT ...", nil, true, ""},
		{"eperm-in-stderr", "iptables: Permission denied (you must be root)", errors.New("exit status 4"), false, defaultPrivilegedReason},
		{"operation-not-permitted", "", errors.New("Operation not permitted"), false, defaultPrivilegedReason},
		{"other-failure", "", errors.New("exec: \"iptables\": executable file not found in $PATH"), false, "could not determine firewall privilege"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, reason := classifyPrivilege(tc.out, tc.err)
			if priv != tc.wantPriv {
				t.Fatalf("privileged = %v, want %v", priv, tc.wantPriv)
			}
			if tc.wantMatch != "" && !strings.Contains(reason, tc.wantMatch) {
				t.Fatalf("reason = %q, want it to contain %q", reason, tc.wantMatch)
			}
			if tc.wantPriv && reason != "" {
				t.Fatalf("privileged=true must carry no reason, got %q", reason)
			}
		})
	}
}

func TestDetectBackend(t *testing.T) {
	origGoos, origLookPath := goos, lookPath
	defer func() { goos, lookPath = origGoos, origLookPath }()

	t.Run("non-linux is always unsupported", func(t *testing.T) {
		goos = "darwin"
		lookPath = func(string) (string, error) { return "/usr/bin/nft", nil }
		b := DetectBackend(newFakeRunner())
		if _, ok := b.(unsupportedBackend); !ok {
			t.Fatalf("DetectBackend on darwin = %T, want unsupportedBackend", b)
		}
	})

	t.Run("linux prefers nft when present", func(t *testing.T) {
		goos = "linux"
		lookPath = func(name string) (string, error) { return "/usr/sbin/" + name, nil }
		b := DetectBackend(newFakeRunner())
		if _, ok := b.(nftBackend); !ok {
			t.Fatalf("DetectBackend with nft present = %T, want nftBackend", b)
		}
	})

	t.Run("linux falls back to iptables without nft", func(t *testing.T) {
		goos = "linux"
		lookPath = func(name string) (string, error) {
			if name == "nft" {
				return "", fmt.Errorf("not found")
			}
			return "/usr/sbin/" + name, nil
		}
		b := DetectBackend(newFakeRunner())
		if _, ok := b.(iptablesBackend); !ok {
			t.Fatalf("DetectBackend with only iptables present = %T, want iptablesBackend", b)
		}
	})

	t.Run("linux with neither binary is unsupported", func(t *testing.T) {
		goos = "linux"
		lookPath = func(string) (string, error) { return "", fmt.Errorf("not found") }
		b := DetectBackend(newFakeRunner())
		if _, ok := b.(unsupportedBackend); !ok {
			t.Fatalf("DetectBackend with neither binary = %T, want unsupportedBackend", b)
		}
	})
}
