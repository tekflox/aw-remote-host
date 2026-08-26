package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// These tests exist because the darwin half of the exit-gate sequence cannot
// be exercised where this project is built. Dispatching on Host.OS instead of
// on a build tag is what makes them possible at all — see
// usexit_platform.go's header.

// THE VERDICT THE WHOLE CARD TURNS ON. Mac.Home can never ENROL: /opt/homebrew
// belongs to another account, so `brew install tailscale` fails on
// permissions and CanEnroll is false forever. It can still SELECT a gate —
// tailscale is already installed there by hand and tailscaled runs as a root
// LaunchDaemon. Deciding the second question with the first one's answer sent
// the machine's owner to fix Homebrew, which would have changed nothing.
func TestMacThatCannotEnrolCanStillSelectAGate(t *testing.T) {
	e := Resolve(macHome())
	if e.CanEnroll {
		t.Fatal("Mac.Home cannot enrol — the brew prefix belongs to someone else")
	}
	if !e.CanSelectExit {
		t.Fatalf("but it CAN be pointed at a gate: %s", e.SelectExitRefusal)
	}
	if e.CanAdvertiseExit {
		t.Fatal("selecting a gate must not imply offering one — forwarding needs a sysctl nobody here has exercised")
	}
}

// Privilege on a Mac is a tailscale grant (`tailscale set --operator=`), not a
// uid, and it is invisible from the outside. Refusing here on uid would
// refuse a Mac that works; the live probe in darwinExit.preflight is what
// answers it, one step before anything moves.
func TestDarwinSelectVerdictDoesNotGuessAtPrivilege(t *testing.T) {
	h := macHome()
	h.UID, h.PasswordlessSudo = 503, false
	if ok, refusal := resolveSelectExit(h); !ok {
		t.Fatalf("a non-root Mac must not be refused statically: %s", refusal)
	}
}

// Linux is the opposite: the module does the route surgery itself, and both
// `ip rule` and `tailscale set` need root.
func TestLinuxWithoutRootCannotSelectAGate(t *testing.T) {
	h := bareMetal()
	h.UID, h.PasswordlessSudo = 1000, false
	h.TailscalePath = "/usr/bin/tailscale"
	ok, refusal := resolveSelectExit(h)
	if ok {
		t.Fatal("moving the default route without root would leave the exclusions uninstalled")
	}
	if !strings.Contains(refusal, "ip rule") || !strings.Contains(refusal, "NOPASSWD") {
		t.Fatalf("the refusal must name what is missing and how to fix it: %q", refusal)
	}
}

// "enrol it first" beats every other sentence, on every platform: a host with
// no tailscale has no mesh to route through, and saying anything about
// privilege there sends the reader somewhere useless.
func TestNoTailscaleIsTheFirstRefusalOnEveryPlatform(t *testing.T) {
	for _, h := range []Host{bareMetal(), macHome()} {
		h.TailscalePath = ""
		ok, refusal := resolveSelectExit(h)
		if ok || !strings.Contains(refusal, "enrol it first") {
			t.Fatalf("%s: ok=%v refusal=%q", h.OS, ok, refusal)
		}
	}
}

func TestWindowsIsRefusedTowardsItsDistro(t *testing.T) {
	h := Host{OS: "windows", TailscalePath: `C:\tailscale.exe`}
	ok, refusal := resolveSelectExit(h)
	if ok || !strings.Contains(refusal, "distro") {
		t.Fatalf("ok=%v refusal=%q", ok, refusal)
	}
}

// The refusal the agent's own user hits on Mac.Home today, and the reason
// preflight is a WRITE rather than a guess. It must name the one-time command
// that fixes it — "access denied" alone leaves a human with nowhere to go.
func TestDarwinPreflightRefusesADeniedPrefsWriteWithTheOperatorFix(t *testing.T) {
	r := newRecordingRunner()
	r.answer("tailscale set --accept-dns=false",
		"Access denied: checkprefs access denied\n\nUse 'sudo tailscale set --accept-dns=false'.",
		errors.New("exit status 1"))

	_, err := darwinExit{}.preflight(context.Background(), macHome(), r)
	if err == nil {
		t.Fatal("a Mac that cannot write prefs must be refused BEFORE the dead-man's switch is armed")
	}
	if !strings.Contains(err.Error(), "--operator=") {
		t.Fatalf("the refusal must carry the one-time fix: %q", err)
	}
	// Nothing beyond the probe: no route touched, no sudo attempted on a host
	// that has none.
	if len(r.calls) != 1 {
		t.Fatalf("preflight must change nothing, calls: %v", r.calls)
	}
}

// The probe is a write that changes nothing on purpose: --accept-dns=false is
// what SetExitNode passes on every call anyway, and this module forces
// MagicDNS off at enrolment. Picking any other flag would make the preflight
// a real configuration change.
func TestDarwinPreflightProbesWithTheFlagTheSequenceWouldSetAnyway(t *testing.T) {
	r := newRecordingRunner()
	if _, err := (darwinExit{}).preflight(context.Background(), macHome(), r); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != "tailscale set --accept-dns=false" {
		t.Fatalf("calls = %v", r.calls)
	}
}

// A Mac whose user holds the operator grant needs NO sudo, and wrapping it in
// one would swap a working call for "sudo: a password is required" — the
// wrong blocker reported on a machine that is fine. The unprivileged runner
// is tried first and kept.
func TestDarwinPreflightKeepsTheUnprivilegedRunnerWhenItWorks(t *testing.T) {
	r := newRecordingRunner()
	runner, err := darwinExit{}.preflight(context.Background(), macHome(), r)
	if err != nil {
		t.Fatal(err)
	}
	if runner.Sudo {
		t.Fatal("the operator grant makes sudo unnecessary; using it anyway would fail on a Mac with no sudo")
	}
	if got := runner.CommandPrefix("/opt/homebrew/bin/tailscale"); got != "/opt/homebrew/bin/tailscale" {
		t.Fatalf("the dead-man's switch would be armed with the wrong command: %q", got)
	}
}

// An administrator's Mac — no operator grant, but passwordless sudo — is the
// other working shape, and it must not be refused just because the plain call
// failed first.
func TestDarwinPreflightFallsBackToSudoWhenItIsAvailable(t *testing.T) {
	r := newRecordingRunner()
	r.answer("tailscale set --accept-dns=false", "Access denied: checkprefs access denied", errors.New("exit status 1"))
	h := macHome()
	h.PasswordlessSudo = true

	runner, err := darwinExit{}.preflight(context.Background(), h, r)
	if err != nil {
		t.Fatalf("a Mac with passwordless sudo can write prefs: %v", err)
	}
	if !runner.Sudo {
		t.Fatal("the sequence has to keep using the runner that actually worked")
	}
}

// The finding the card asked for, pinned as a test: darwin installs no route
// exclusions. Not "none yet" — none, because the only macOS mechanism is a
// static host route naming a gateway, and a laptop that changes networks
// turns a leftover one into a black hole for exactly the address it was
// protecting. See darwinExit.planExclusions.
func TestDarwinPlansNoExclusionsButStillLocatesTheControlPlane(t *testing.T) {
	plan, err := darwinExit{}.planExclusions("https://api.aw.tekflox.com", nil, func(string) ([]string, error) {
		return []string{"65.109.66.88"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Exclusions) != 0 {
		t.Fatalf("darwin must not claim exclusions it cannot install: %+v", plan.Exclusions)
	}
	if plan.ControlPlaneHost != "api.aw.tekflox.com" || len(plan.ControlPlaneIPs) != 1 {
		t.Fatalf("the control plane still has to be located — its reachability is CONFIRMED here rather than pinned: %+v", plan)
	}
}

// Confirming the management path requires knowing where it is, so an
// unresolvable control plane is still a refusal on darwin — the precondition
// survives even though the pin does not.
func TestDarwinStillRefusesAnUnresolvableControlPlane(t *testing.T) {
	_, err := darwinExit{}.planExclusions("https://api.aw.tekflox.com", nil, func(string) ([]string, error) {
		return nil, errors.New("no such host")
	})
	if err == nil {
		t.Fatal("a control plane that cannot be located cannot be confirmed either")
	}
}

// Silently dropping --exclude would be the worst outcome available: the
// operator believes a prefix is outside the tunnel and nothing is holding it
// there.
func TestDarwinRefusesAnExcludeItCannotHonour(t *testing.T) {
	_, err := darwinExit{}.planExclusions("https://api.aw.tekflox.com", []string{"10.0.0.0/8"}, func(string) ([]string, error) {
		return []string{"65.109.66.88"}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("err = %v", err)
	}
}

// The weaker guarantee has to be SAID, not inferred from an empty list. A
// control plane that stores the reply and a human reading the terminal both
// need the sentence.
func TestOnlyDarwinCarriesAManageabilityWarning(t *testing.T) {
	if w := (darwinExit{}).manageability("api.aw.tekflox.com"); !strings.Contains(w, "api.aw.tekflox.com") || !strings.Contains(w, "clear-exit") {
		t.Fatalf("darwin's warning must name the host and the way out: %q", w)
	}
	if w := (linuxExit{}).manageability("api.aw.tekflox.com"); w != "" {
		t.Fatalf("Linux DOES pin the management path, so it must stay silent: %q", w)
	}
}

// `route -n get` prints "key: value" lines, not ip's single flat line. A
// confirmed selection turns the interface into a utun; parsing the wrong
// field would report every Mac as unconfirmed.
func TestParseDarwinRouteInterface(t *testing.T) {
	before := `   route to: 1.1.1.1
destination: default
       mask: default
    gateway: 192.168.1.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	after := "   route to: 1.1.1.1\ndestination: 1.1.1.1\n  interface: utun4\n"
	if got := parseDarwinRouteInterface(before); got != "en0" {
		t.Fatalf("got %q", got)
	}
	if got := parseDarwinRouteInterface(after); got != "utun4" {
		t.Fatalf("got %q", got)
	}
	if got := parseDarwinRouteInterface("route: writing to routing socket: not in table\n"); got != "" {
		t.Fatalf("an unroutable destination must report nothing, not a guess: %q", got)
	}
}

// The dead-man's switch is the one thing that has to work on a machine whose
// network has just gone, so what it runs must match the platform exactly. A
// Mac has nothing to unpin, and a script that reached for `ip rule` there
// would fail every revert.
func TestDeadmanScriptMatchesThePlatform(t *testing.T) {
	darwinScript := ArmSpec{
		After:           120,
		TailscalePath:   "/opt/homebrew/bin/tailscale",
		ExclusionRevert: darwinExit{}.revertExclusionsScript(PrivilegedRunner{}),
	}.revertScript()
	if strings.Contains(darwinScript, "rule del") {
		t.Fatalf("no `ip rule` on a Mac:\n%s", darwinScript)
	}
	if !strings.Contains(darwinScript, "/opt/homebrew/bin/tailscale set --exit-node=") {
		t.Fatalf("the revert still has to clear the selection:\n%s", darwinScript)
	}

	linuxScript := ArmSpec{
		After:           120,
		TailscalePath:   "/usr/bin/tailscale",
		ExclusionRevert: linuxExit{ipPath: "/usr/sbin/ip"}.revertExclusionsScript(PrivilegedRunner{Sudo: true}),
	}.revertScript()
	if !strings.Contains(linuxScript, "sudo -n /usr/sbin/ip rule del priority 5260") {
		t.Fatalf("Linux must still drop its exclusions, with the privilege prefix baked in:\n%s", linuxScript)
	}
}

// A user LaunchAgent is what makes the escape hatch possible without root:
// ~/Library/LaunchAgents is writable by the same account aw-remote-host
// installs its own service into.
func TestLaunchdBootGuardClearsTheSelectionAtLogin(t *testing.T) {
	plist := launchdBootGuardPlist("/opt/homebrew/bin/tailscale")
	for _, want := range []string{
		"<string>" + launchdBootGuardLabel + "</string>",
		"<string>/opt/homebrew/bin/tailscale</string>",
		"<string>--exit-node=</string>",
		"<key>RunAtLoad</key><true/>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("missing %q in:\n%s", want, plist)
		}
	}
}

// Idempotence, and the shape of it: launchctl refuses to bootstrap a label
// already in the domain, so a second use-exit would fail on the guard the
// first one installed if the agent were not booted out first.
func TestInstallLaunchdBootGuardIsIdempotent(t *testing.T) {
	r := newRecordingRunner()
	if err := installLaunchdBootGuard(context.Background(), PrivilegedRunner{Inner: r}, "/opt/homebrew/bin/tailscale"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "launchctl bootout gui/") {
		t.Fatalf("the agent must be booted out before it is bootstrapped:\n%s", joined)
	}
	if !strings.Contains(joined, "launchctl bootstrap gui/") {
		t.Fatalf("a plist written but never loaded never runs:\n%s", joined)
	}
	if !strings.Contains(r.calls[0], "Library/LaunchAgents/"+launchdBootGuardLabel+".plist") {
		t.Fatalf("first call = %q", r.calls[0])
	}
}

// Linux behaviour must be byte-for-byte what it was before the platform seam
// existed. This is the regression that would matter: the production
// bare-metal and every linked Linux host go through this path.
func TestLinuxPlatformStillInstallsTheSameIPRules(t *testing.T) {
	r := newRecordingRunner()
	r.answer("ip rule del priority 5260", noRule, errors.New("exit status 2"))
	err := linuxExit{ipPath: "/usr/sbin/ip"}.applyExclusions(context.Background(), r, []Exclusion{
		{Prefix: "65.109.66.88/32", Reason: "control plane"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "ip rule add to 65.109.66.88/32 lookup main priority 5260") {
		t.Fatalf("calls = %v", r.calls)
	}
}

// platformFor resolves `ip` to an absolute path and refuses without it, but
// only for Linux — requiring it on a Mac would refuse every Mac, since macOS
// has no `ip` at all.
func TestPlatformForDoesNotAskDarwinForIP(t *testing.T) {
	prev := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { lookPath = prev })

	if _, err := platformFor(Host{OS: "linux"}); err == nil {
		t.Fatal("Linux without `ip` cannot install its exclusions and must refuse")
	}
	plat, err := platformFor(macHome())
	if err != nil {
		t.Fatalf("darwin needs no `ip`: %v", err)
	}
	if plat.name() != "darwin" {
		t.Fatalf("name = %q", plat.name())
	}
}
