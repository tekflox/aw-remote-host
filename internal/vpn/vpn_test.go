package vpn

import (
	"strings"
	"testing"
)

// The three hosts below are not invented. Every field was read off a real
// linked machine on 2026-08-25 (via `aw-workspace-cli remote-hosts run`), and
// they are the three shapes this module has to get right: the Linux exit
// gate, the WSL2 client, and the macOS host that must be refused.

// bareMetal — `Ubuntu-resolute…` / 2d5d56ef, the production bare-metal.
// Measured: uname Linux 7.0.0-22-generic, id -u 0, /dev/net/tun present,
// /run/systemd/system present, /proc/sys/net/ipv4/ip_forward = 1.
func bareMetal() Host {
	return Host{
		OS: "linux", Arch: "amd64",
		UID: 0, HasTUN: true, HasSystemd: true, IPForward: true,
		TailscalePath: "/usr/bin/tailscale",
	}
}

// surfaceWSL — DESKTOP-DRMKFBT / caf475b7, a WSL2 distro.
// Measured: uname 6.18.33.2-microsoft-standard-WSL2, id -u 0, `sudo -n true`
// exit 0, /dev/net/tun present, /run/systemd/system present.
func surfaceWSL() Host {
	h := bareMetal()
	h.WSL = true
	h.PasswordlessSudo = true
	h.IPForward = false
	return h
}

// macHome — Mac.Home / 824decc7, as it really is. Measured 2026-09-01:
// macOS 26.5.1 arm64, id -u 503, `sudo -n -l` -> "sudo: a password is
// required", brew at /opt/homebrew/bin/brew owned by another account (uid 503
// cannot write to it), tailscale 1.102.3 at /opt/homebrew/bin/tailscale,
// BackendState Running at 100.64.0.3 against headscale.aw.tekflox.com,
// OperatorUser "aw", net.inet.ip.forwarding = 0.
//
// Enrolled is the field this fixture existed without for a week, and its
// absence is what the 2026-09-01 card was about: every test here agreed the
// Mac "could not enrol" while the Mac was on the mesh.
func macHome() Host {
	h := macHomeBeforeEnrolment()
	h.Enrolled = true
	return h
}

// macHomeBeforeEnrolment is the same machine on the day it was NOT yet on the
// mesh — the shape the installer-side refusals are really about. Kept
// separate because those refusals are still correct for it, and folding the
// two would have exactly the effect this card had to undo: an answer about
// installing tailscale, given to a machine that already runs it.
func macHomeBeforeEnrolment() Host {
	return Host{
		OS: "darwin", Arch: "arm64",
		UID: 503, PasswordlessSudo: false,
		BrewPrefix: "/opt/homebrew", BrewWritable: false,
		TailscalePath: "/opt/homebrew/bin/tailscale",
	}
}

func TestResolveLinuxRootIsFullyEligible(t *testing.T) {
	e := Resolve(bareMetal())
	if !e.CanEnroll {
		t.Fatalf("bare-metal should enrol: %s", e.EnrollRefusal)
	}
	if !e.CanAdvertiseExit {
		t.Fatalf("bare-metal should be exit-node eligible: %s", e.ExitRefusal)
	}
	if e.Installer != InstallerUpstreamScript {
		t.Fatalf("installer = %q", e.Installer)
	}
}

// CHANGED 2026-08-26. This used to assert WSL2 could not be a gate at all.
// That refusal was the wrong shape of answer: it is the only machine this
// account has that could be a SECOND gate, "never measured" is not "does not
// work", and refusing left the mesh's owner with no way to find out either.
//
// So WSL2 is now a warned yes, and the warning is the test — a permission
// with no price attached would offer a relayed, doubly-NATed gate silently,
// which is worse than either a plain yes or a plain no.
func TestResolveWSLMayBeAGateAndSaysWhatThatCosts(t *testing.T) {
	e := Resolve(surfaceWSL())
	if !e.CanEnroll {
		t.Fatalf("WSL2 with root should enrol: %s", e.EnrollRefusal)
	}
	if !e.CanAdvertiseExit {
		t.Fatalf("WSL2 may serve as a gate: %s", e.ExitRefusal)
	}
	if e.ExitRefusal != "" {
		t.Fatalf("an allowed host must carry no refusal, got %q", e.ExitRefusal)
	}
	if !strings.Contains(e.ExitWarning, "WSL2") {
		t.Fatalf("the cost must be stated, and must say what it is: %q", e.ExitWarning)
	}
	// The two consequences the card demanded reach the user: everything
	// leaves through the Windows host, and it cannot hole-punch so a public
	// relay carries it.
	if !strings.Contains(e.ExitWarning, "relay") {
		t.Fatalf("the warning must name the relay — that is the part nobody would guess: %q", e.ExitWarning)
	}
	if !strings.Contains(e.Describe(), e.ExitWarning) {
		t.Fatalf("`status` must print the price beside the permission, got %q", e.Describe())
	}
}

// A host refused outright still has no warning: the two fields answer
// different questions, and a refusal that also carried advice about relays
// would read as a soft no.
func TestResolveRefusalsCarryNoWarning(t *testing.T) {
	for name, h := range map[string]Host{"darwin": macHome(), "windows": {OS: "windows"}} {
		e := Resolve(h)
		if e.CanAdvertiseExit {
			t.Fatalf("%s must not be offered as a gate", name)
		}
		if e.ExitWarning != "" {
			t.Fatalf("%s: refusal carried a warning too: %q", name, e.ExitWarning)
		}
		if e.ExitRefusal == "" {
			t.Fatalf("%s: refused with no reason", name)
		}
	}
}

// The case the whole probe exists for. Refusing here is the feature: without
// root, tailscaled falls back to userspace networking, which is a SOCKS5
// proxy and NOT an interface — so a "successful" install would carry none of
// the machine's traffic while reporting that it had joined.
func TestResolveMacWithoutSudoIsRefused(t *testing.T) {
	e := Resolve(macHomeBeforeEnrolment())
	if e.CanEnroll {
		t.Fatal("Mac.Home has no passwordless sudo and an unwritable brew prefix — it must be refused")
	}
	if e.CanAdvertiseExit {
		t.Fatal("a host that cannot enrol cannot be an exit node either")
	}
	if e.EnrollRefusal == "" {
		t.Fatal("a refusal with no reason is the thing this package exists to prevent")
	}
	// The reason is shown verbatim to a human asking why their machine is not
	// in the list, so it has to name the actual obstacle.
	if !strings.Contains(e.EnrollRefusal, "/opt/homebrew") {
		t.Fatalf("refusal should name the brew prefix it cannot write to: %q", e.EnrollRefusal)
	}
	if !strings.Contains(e.ExitRefusal, e.EnrollRefusal) {
		t.Fatalf("exit refusal should carry the enrol reason: %q", e.ExitRefusal)
	}
}

// Same Mac, but imagine it had sudo: the brew prefix is still someone else's,
// so `brew install` still fails on permissions. Ordering matters — reporting
// "no sudo" when the real blocker is the prefix sends the user to fix the
// wrong thing.
func TestResolveMacUnwritableBrewIsReportedBeforeSudo(t *testing.T) {
	h := macHomeBeforeEnrolment()
	h.PasswordlessSudo = true
	e := Resolve(h)
	if e.CanEnroll {
		t.Fatal("an unwritable brew prefix must still refuse")
	}
	if !strings.Contains(e.EnrollRefusal, "cannot write") {
		t.Fatalf("got %q", e.EnrollRefusal)
	}
}

func TestResolveMacWithSudoAndOwnBrewIsEligible(t *testing.T) {
	h := macHomeBeforeEnrolment()
	h.PasswordlessSudo = true
	h.BrewWritable = true
	e := Resolve(h)
	if !e.CanEnroll {
		t.Fatalf("should enrol: %s", e.EnrollRefusal)
	}
	if e.Installer != InstallerHomebrew {
		t.Fatalf("installer = %q", e.Installer)
	}
	// CHANGED 2026-09-01. This used to assert "macOS exit nodes are
	// deliberately not claimed", which was the honest answer while nothing
	// here knew how to enable net.inet forwarding. The way to retire a
	// refusal like that is to implement it, so a Mac with root may now be a
	// gate — and, like WSL2, it says what that costs.
	if !e.CanAdvertiseExit {
		t.Fatalf("a Mac that can elevate may serve as a gate: %s", e.ExitRefusal)
	}
	if !strings.Contains(e.ExitWarning, "sysctl.conf") {
		t.Fatalf("the persistence caveat is the price and must travel with the permission: %q", e.ExitWarning)
	}
}

// BUG 1, and the reason this card existed. The Mac is on the mesh, Running at
// 100.64.0.3, and every refusal in the darwin enrolment branch is about the
// INSTALLER — a Homebrew prefix owned by another account. Asking "could I
// install tailscale" about a machine that already runs it produced "NOT
// eligible to enrol", and that verdict then short-circuited the ADVERTISE
// decision before the darwin branch was ever evaluated.
func TestResolveMacAlreadyOnTheMeshIsNotJudgedByItsInstaller(t *testing.T) {
	e := Resolve(macHome())
	if !e.CanEnroll {
		t.Fatalf("a node with BackendState=Running is enrolled, whatever brew would have said: %s", e.EnrollRefusal)
	}
	if !e.AlreadyEnrolled {
		t.Fatal("CanEnroll on an already-enrolled host must say WHY, or `status` reports a week-old decision as a future one")
	}
	if e.Installer != InstallerNone {
		t.Fatalf("nothing needs installing here, installer = %q", e.Installer)
	}
	if strings.Contains(e.ExitRefusal, "cannot join the mesh at all") {
		t.Fatalf("an installation verdict is still short-circuiting the advertise decision: %q", e.ExitRefusal)
	}
	if !strings.HasPrefix(e.Describe(), "already enrolled") {
		t.Fatalf("got %q", e.Describe())
	}
}

// The counterpart, and the reason this is darwin-only. Without root, Linux
// tailscaled falls back to --tun=userspace-networking: it reports
// BackendState=Running, provides a SOCKS5 proxy, and carries none of the
// machine's traffic. "Running" is precisely the claim that must not be
// trusted there, so it does not get to overrule the check that catches it.
func TestEnrolledDoesNotExcuseALinuxHostWithoutRoot(t *testing.T) {
	h := bareMetal()
	h.UID, h.PasswordlessSudo, h.Enrolled = 1000, false, true
	e := Resolve(h)
	if e.CanEnroll {
		t.Fatal("a Running Linux node without root may be userspace-networking — that must still refuse")
	}
	if !strings.Contains(e.EnrollRefusal, "userspace-networking") {
		t.Fatalf("got %q", e.EnrollRefusal)
	}
}

// BUG 2. The Mac cannot elevate, so it cannot set the sysctl, so it must NOT
// advertise — and the refusal is only useful if it hands over the exact
// command that fixes it. Half of this (advertised, not forwarding) is worse
// than none: the control plane can approve it, a peer can select it, and the
// traffic dies silently.
func TestResolveMacWithoutForwardingRefusesWithTheCommandThatFixesIt(t *testing.T) {
	e := Resolve(macHome())
	if e.CanAdvertiseExit {
		t.Fatal("net.inet.ip.forwarding is 0 and this process cannot set it — advertising anyway is the silent failure")
	}
	for _, want := range []string{
		"net.inet.ip.forwarding",   // the actual knob, by its macOS name
		"sudo /usr/sbin/sysctl -w", // the literal command, absolute path
		"/etc/sysctl.conf",         // and how it survives a reboot
		"uid 503",                  // why this process cannot do it itself
	} {
		if !strings.Contains(e.ExitRefusal, want) {
			t.Fatalf("the refusal must carry %q, got %q", want, e.ExitRefusal)
		}
	}
	if e.ExitWarning != "" {
		t.Fatalf("a refusal must not also carry a warning: %q", e.ExitWarning)
	}
}

// A Mac whose administrator has already enabled forwarding may advertise as
// an ORDINARY USER. Refusing it on uid would refuse a machine that works: the
// prefs write is granted per-user by `tailscale set --operator=`, which needs
// no root, and the sysctl is already done. What this process cannot promise —
// keeping it across a reboot — travels out as the warning rather than being
// assumed either way.
func TestResolveMacWithForwardingAlreadyOnMayAdvertiseWithoutRoot(t *testing.T) {
	h := macHome()
	h.IPForward = true
	e := Resolve(h)
	if !e.CanAdvertiseExit {
		t.Fatalf("forwarding is on; the only other step needs no root: %s", e.ExitRefusal)
	}
	if !strings.Contains(e.ExitWarning, "reboot") || !strings.Contains(e.ExitWarning, "/etc/sysctl.conf") {
		t.Fatalf("what this process cannot guarantee has to be said: %q", e.ExitWarning)
	}
}

func TestResolveLinuxWithoutRootIsRefusedWithTheUserspaceReason(t *testing.T) {
	h := bareMetal()
	h.UID = 1000
	h.PasswordlessSudo = false
	e := Resolve(h)
	if e.CanEnroll {
		t.Fatal("no root and no passwordless sudo must refuse")
	}
	if !strings.Contains(e.EnrollRefusal, "userspace-networking") {
		t.Fatalf("the refusal has to explain the userspace trap: %q", e.EnrollRefusal)
	}
}

func TestResolveLinuxWithoutTUNIsRefused(t *testing.T) {
	h := bareMetal()
	h.HasTUN = false
	e := Resolve(h)
	if e.CanEnroll {
		t.Fatal("no /dev/net/tun must refuse")
	}
	if !strings.Contains(e.EnrollRefusal, "/dev/net/tun") {
		t.Fatalf("got %q", e.EnrollRefusal)
	}
}

// A WSL2 distro without systemd enabled in /etc/wsl.conf has nothing to keep
// tailscaled alive, and that is invisible from uname — so the refusal has to
// point at wsl.conf rather than at systemd in the abstract.
func TestResolveWSLWithoutSystemdPointsAtWSLConf(t *testing.T) {
	h := surfaceWSL()
	h.HasSystemd = false
	e := Resolve(h)
	if e.CanEnroll {
		t.Fatal("no systemd must refuse")
	}
	if !strings.Contains(e.EnrollRefusal, "wsl.conf") {
		t.Fatalf("got %q", e.EnrollRefusal)
	}
}

// A Windows host runs its workspace inside the WSL2 distro internal/wsl
// provisions, and that distro joins as an ordinary Linux node. Enrolling the
// Windows side too would put one machine in the mesh twice.
func TestResolveWindowsPointsAtItsWSLDistro(t *testing.T) {
	e := Resolve(Host{OS: "windows", Arch: "amd64", UID: 0})
	if e.CanEnroll {
		t.Fatal("the Windows side must not enrol")
	}
	if !strings.Contains(e.EnrollRefusal, "WSL2") {
		t.Fatalf("got %q", e.EnrollRefusal)
	}
}

func TestDescribeSaysWhichOfTheTwoVerdictsFailed(t *testing.T) {
	if got := Resolve(bareMetal()).Describe(); !strings.Contains(got, "exit node") {
		t.Fatalf("got %q", got)
	}
	// The WSL2 host moved from the middle branch to the first one on
	// 2026-08-26 — it is now eligible AND warned, which is a different
	// sentence, not a softer version of the old one.
	if got := Resolve(surfaceWSL()).Describe(); !strings.Contains(got, "can be advertised as an exit node") || !strings.Contains(got, "but ") {
		t.Fatalf("got %q", got)
	}
	// The middle branch still exists and still says which verdict failed. A
	// Linux host with no systemd cannot enrol, so it cannot be a gate either.
	noSystemd := bareMetal()
	noSystemd.HasSystemd = false
	if got := Resolve(noSystemd).Describe(); !strings.Contains(got, "NOT eligible") {
		t.Fatalf("got %q", got)
	}
	if got := Resolve(macHomeBeforeEnrolment()).Describe(); !strings.HasPrefix(got, "NOT eligible to enrol") {
		t.Fatalf("got %q", got)
	}
}

func TestTruthy(t *testing.T) {
	for _, yes := range []string{"1", "true", "TRUE", "yes", " on "} {
		if !Truthy(yes) {
			t.Fatalf("%q should be true", yes)
		}
	}
	for _, no := range []string{"", "0", "false", "no", "maybe"} {
		if Truthy(no) {
			t.Fatalf("%q should be false", no)
		}
	}
}

func TestPrivileged(t *testing.T) {
	if !bareMetal().Privileged() {
		t.Fatal("uid 0 is privileged")
	}
	if !surfaceWSL().Privileged() {
		t.Fatal("passwordless sudo is privileged")
	}
	if macHome().Privileged() {
		t.Fatal("uid 503 with no passwordless sudo is not privileged")
	}
}

// Probe touches only read-only things (stat, a sysctl read, `sudo -n`), so it
// is safe to call anywhere — including from `status` on a host it will
// refuse. This guards that it stays that way.
func TestProbeIsSafeToCallAnywhere(t *testing.T) {
	h := Probe()
	if h.OS == "" || h.Arch == "" {
		t.Fatalf("probe returned nothing useful: %+v", h)
	}
	// Whatever this machine is, Resolve must produce a verdict with a reason
	// rather than an empty one.
	e := Resolve(h)
	if !e.CanEnroll && e.EnrollRefusal == "" {
		t.Fatal("refused with no reason")
	}
}
