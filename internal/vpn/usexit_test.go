package vpn

import (
	"context"
	"strings"
	"testing"
)

// A dead-man's switch that fires while the selection is still being confirmed
// would revert a gate that was about to work and report a confusing failure.
// The two defaults must not be able to drift into that shape.
func TestDeadmanWindowIsWiderThanTheConfirmationWindow(t *testing.T) {
	if DefaultDeadmanTimeout <= DefaultConfirmTimeout {
		t.Fatalf("deadman %s must outlast confirm %s", DefaultDeadmanTimeout, DefaultConfirmTimeout)
	}
	if confirmPollInterval >= DefaultConfirmTimeout {
		t.Fatalf("poll interval %s leaves no room inside the confirm window %s", confirmPollInterval, DefaultConfirmTimeout)
	}
}

// withDefaults must not let a caller that supplied neither value land in the
// shape above — the /link verb reaches UseExitSpec with whatever JSON gave it,
// which is routinely nothing at all.
func TestSpecDefaultsAreTheSafeWindow(t *testing.T) {
	s := UseExitSpec{}.withDefaults()
	if s.Deadman != DefaultDeadmanTimeout || s.ConfirmTimeout != DefaultConfirmTimeout {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if s.Deadman <= s.ConfirmTimeout {
		t.Fatal("defaulted spec must leave the confirmation inside the dead-man's window")
	}
}

// On a host without root every privileged step has to go through `sudo -n`,
// including the ones spelled out as text inside the dead-man's switch script
// and the boot-guard unit, where there is no Runner to wrap them.
func TestPrivilegedRunnerCommandPrefixMatchesHowItRuns(t *testing.T) {
	if got := (PrivilegedRunner{Sudo: true}).CommandPrefix("/usr/bin/tailscale"); got != "sudo -n /usr/bin/tailscale" {
		t.Fatalf("got %q", got)
	}
	if got := (PrivilegedRunner{Sudo: false}).CommandPrefix("/usr/bin/tailscale"); got != "/usr/bin/tailscale" {
		t.Fatalf("got %q", got)
	}
}

// PlanUseExit is the gate every caller goes through, and these two refusals
// are the ones a remote caller can trigger by sending nothing at all. Both
// have to fail BEFORE the probe touches the machine.
func TestPlanRefusesAConfirmWindowWiderThanTheDeadman(t *testing.T) {
	_, err := PlanUseExit(context.Background(), UseExitSpec{
		Runner:         stubRunner{},
		ControlPlane:   "https://api.example.com",
		Node:           "gate",
		Deadman:        DefaultConfirmTimeout,
		ConfirmTimeout: DefaultDeadmanTimeout,
	})
	if err == nil || !strings.Contains(err.Error(), "must be longer") {
		t.Fatalf("err = %v", err)
	}
}

// The control plane is not an optional exclusion: without it the machine can
// end up on a gate that does not forward, with no path left to say stop. An
// empty value has to be refused here rather than quietly resolving to "".
func TestPlanRefusesAnEmptyControlPlane(t *testing.T) {
	_, err := PlanUseExit(context.Background(), UseExitSpec{
		Runner: stubRunner{},
		Node:   "gate",
	})
	if err == nil || !strings.Contains(err.Error(), "not an optional exclusion") {
		t.Fatalf("err = %v", err)
	}
}

type stubRunner struct{}

func (stubRunner) Run(context.Context, string, ...string) (string, error) { return "", nil }
