package vpn

import (
	"context"
	"errors"
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

// THE SCOPE REFUSAL AS A VALUE, not as a flag. What is refused is no longer
// "every host" but "every host where the only thing that could move is the
// machine itself" — and both halves of that verdict have to be reachable from
// a test on a build machine that has no container runtime and no Mac.
//
// A refusal is decided by ScopeRefusal before UseExit measures, arms or moves
// anything, and PlanUseExit stays read-only either way, which is what lets
// --plan keep working on a refused host.
func TestScopeRefusalRefusesAHostWithNoContainerRuntime(t *testing.T) {
	// A runner that fails every command is a host with neither docker nor
	// podman — the lean-linked laptop, which is exactly the kind of machine
	// someone reaches for a gate on.
	refusal := ScopeRefusal(context.Background(), failingRunner{})
	if refusal == "" {
		t.Fatal("a host with no container runtime must be REFUSED: the only thing left to route is the machine, and that is the bug this feature removed")
	}
	if !strings.Contains(refusal, "refusal, not a reason to fall back") {
		t.Fatalf("the refusal must say it is not a fallback, got %q", refusal)
	}
}

// The darwin answer the card asked for, and it is a refusal WITH A REASON
// rather than a fallback to routing the whole Mac.
func TestDarwinRefusesContainerScopeWithItsReason(t *testing.T) {
	if got := (darwinExit{}).containerScopeRefusal(); got != DarwinContainerScopeRefusal {
		t.Fatalf("darwin must refuse: %q", got)
	}
	// The reason has to be checkable, not just present: it names the VM, and
	// it names the alternative, or a reader is left thinking it is a gap to be
	// filled rather than a property of the platform.
	for _, want := range []string{"VM", "ip rule", "INSIDE the VM"} {
		if !strings.Contains(DarwinContainerScopeRefusal, want) {
			t.Fatalf("%q missing from the darwin refusal: %q", want, DarwinContainerScopeRefusal)
		}
	}
	if (linuxExit{}).containerScopeRefusal() != "" {
		t.Fatal("linux can route container networks; refusing it statically would refuse every host")
	}
}

// A refused host is refused BEFORE anything is armed, moved or even measured,
// and the refusal comes back on the result rather than only as an error.
func TestUseExitRefusesBeforeItTouchesAnything(t *testing.T) {
	var narrated []string
	res, err := UseExit(context.Background(), UseExitSpec{
		Runner:       failingRunner{},
		ControlPlane: "https://api.example.com",
		Node:         "gate",
	}, func(level, message string) { narrated = append(narrated, level+": "+message) })

	// On a build machine with no tailscale this stops even earlier, at
	// eligibility — which is itself the property under test: nothing is armed
	// or measured before a host is judged.
	if err == nil {
		t.Fatal("a host that cannot be routed container-scoped must not reach the sequence")
	}
	if res.DeadmanExpiresAt != "" || res.DeadmanStillArmed {
		t.Fatalf("a refusal must not arm the dead-man's switch: %+v", res)
	}
	if res.EgressBefore != "" || res.EgressAfter != "" || res.Confirmed || res.Reverted {
		t.Fatalf("a refusal must not measure or change anything: %+v", res)
	}
	if errors.Is(err, ErrScopeRefused) && len(narrated) != 1 {
		t.Fatalf("a scope refusal must be narrated exactly once: %v", narrated)
	}
}

type stubRunner struct{}

func (stubRunner) Run(context.Context, string, ...string) (string, error) { return "", nil }

// failingRunner is a host where nothing this module shells out to exists.
type failingRunner struct{}

func (failingRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	return "", errors.New("exec: \"" + name + "\": executable file not found in $PATH")
}
