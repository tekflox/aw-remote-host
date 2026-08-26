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

// withHostRouteScopeAllowed lets a test reach the sequence beneath the scope
// refusal. Nothing in this package exercises the real sequence yet — it needs
// a machine with tailscale — but the hatch is what stops "turn the refusal
// off" meaning "edit the source", when the container-scoped rewrite starts.
func withHostRouteScopeAllowed(t *testing.T) {
	t.Helper()
	prev := hostRouteScopeRefused
	hostRouteScopeRefused = false
	t.Cleanup(func() { hostRouteScopeRefused = prev })
}

// THE INNERMOST LAYER. UseExit is the one function every path — CLI, /link
// verb, and anything added later — has to go through to move a route, so the
// refusal lives here too and not only in the callers that are easier to read.
//
// It must refuse BEFORE the plan: no DNS lookup, no tailscale call, and above
// all nothing armed or moved. A spec that is otherwise complete and valid is
// used deliberately — the refusal is about what this tool does, not about
// whether the request was well formed.
func TestUseExitRefusesBeforeItTouchesAnything(t *testing.T) {
	var narrated []string
	res, err := UseExit(context.Background(), UseExitSpec{
		Runner:       stubRunner{},
		ControlPlane: "https://api.example.com",
		Node:         "gate",
	}, func(level, message string) { narrated = append(narrated, level+": "+message) })

	if !errors.Is(err, ErrHostRouteScope) {
		t.Fatalf("err = %v, want ErrHostRouteScope", err)
	}
	if res.Reason != HostRouteScopeRefusal {
		t.Fatalf("the result must carry the reason: %q", res.Reason)
	}
	// Nothing may have been armed, moved or even measured.
	if res.DeadmanExpiresAt != "" || res.DeadmanStillArmed {
		t.Fatalf("a refusal must not arm the dead-man's switch: %+v", res)
	}
	if res.EgressBefore != "" || res.EgressAfter != "" || res.Confirmed || res.Reverted {
		t.Fatalf("a refusal must not measure or change anything: %+v", res)
	}
	if len(narrated) != 1 || !strings.Contains(narrated[0], "error: ") {
		t.Fatalf("the refusal must be narrated once, as an error: %v", narrated)
	}
}

// The hatch has to actually reopen the path, or every test that relies on it
// is passing for the wrong reason.
func TestTheScopeHatchReopensTheSequence(t *testing.T) {
	if !HostScopeRefused() {
		t.Fatal("host-scoped routing must be refused by default")
	}
	withHostRouteScopeAllowed(t)
	if HostScopeRefused() {
		t.Fatal("the hatch must turn the refusal off")
	}
	// Past the refusal, the ordinary refusals resume — proving the sequence
	// was really entered rather than short-circuited a second time.
	_, err := UseExit(context.Background(), UseExitSpec{Runner: stubRunner{}}, nil)
	if err == nil || errors.Is(err, ErrHostRouteScope) {
		t.Fatalf("err = %v, want the empty-control-plane refusal from PlanUseExit", err)
	}
	if !strings.Contains(err.Error(), "not an optional exclusion") {
		t.Fatalf("err = %v", err)
	}
}

type stubRunner struct{}

func (stubRunner) Run(context.Context, string, ...string) (string, error) { return "", nil }
