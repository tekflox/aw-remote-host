package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

// lookPath is exec.LookPath, indirected so a test can build a linux platform
// on a machine whose PATH has no `ip` — the container this project is built
// in is exactly that machine when it is slim.
var lookPath = exec.LookPath

// The per-OS half of the use-exit sequence.
//
// usexit.go owns the ORDER — measure egress, arm the dead-man's switch, pin
// the exclusions, move the route, confirm through the new route, revert
// anything unconfirmed — and that order is the safety mechanism, so there is
// exactly one copy of it and every platform runs it. This file is the other
// half: the steps whose IMPLEMENTATION differs between a Linux server and a
// Mac, expressed as one interface so a second sequence never has to exist.
//
// The two implementations are deliberately dispatched on Host.OS, a measured
// field, rather than split across build tags. Same bargain Resolve() makes:
// the darwin behaviour has to be testable from the Linux container this
// project builds in, and a build-tagged darwin file is code nobody here can
// run a test against until it is already on somebody's laptop.
//
// WHAT DARWIN ACTUALLY NEEDS, measured on Mac.Home (Darwin 25.5.0, arm64,
// tailscale 1.102.3) on 2026-08-26 — the question the card asked before any
// of this was designed:
//
//   - tailscaled runs as a ROOT LaunchDaemon
//     (/Library/LaunchDaemons/com.tailscale.tailscaled.plist, state=running)
//     and owns the utun itself. There is no `ip rule`, no table 52, and
//     nothing for this module to route by hand.
//   - The LAN half of the exclusions is native:
//     --exit-node-allow-lan-access=true, which SetExitNode already passes on
//     every selection, and which tailscaled tears down together with the
//     selection that justified it.
//   - The one thing that is NOT native is privilege. `tailscale set` from an
//     ordinary user answers "Access denied: checkprefs access denied" and
//     names its own remedy: `sudo tailscale set --operator=$USER`, once. That
//     is a one-time human action, and after it no further privilege is needed
//     here — which is why darwinExit.preflight is a live probe and not
//     something Resolve() can answer from uid and `sudo -n`.
//
// So the honest answer to "what route surgery does darwin need" is: none.
// See darwinExit.planExclusions for why inventing some would be worse than
// none, rather than merely unnecessary.

// exitPlatform is one OS's implementation of the non-portable steps.
type exitPlatform interface {
	// name is the GOOS this implementation is for.
	name() string

	// preflight refuses whatever this OS can only find out by trying, BEFORE
	// the sequence has changed anything — a refusal here costs nothing, and
	// the same discovery made one step later would arrive with the dead-man's
	// switch armed and the route already moving.
	//
	// It also settles which runner the rest of the sequence uses, because
	// "does this user need sudo" has a different answer per platform and
	// guessing it from uid alone is what produces the wrong error message.
	preflight(ctx context.Context, h Host, base Runner) (PrivilegedRunner, error)

	// planExclusions decides what stays outside the tunnel. An empty set is
	// a legitimate answer; manageability is what says so out loud.
	planExclusions(controlPlane string, extra []string, resolve Resolver) (ExclusionPlan, error)

	// manageability is the warning to carry when the management path is NOT
	// pinned outside the tunnel, and "" when it is. Never silent: a caller
	// that cannot tell the two apart would report the weaker guarantee as
	// the stronger one.
	manageability(controlPlaneHost string) string

	applyExclusions(ctx context.Context, r Runner, ex []Exclusion) error
	clearExclusions(ctx context.Context, r Runner) (int, error)
	listExclusions(ctx context.Context, r Runner) ([]string, error)

	// routeDevice reports which interface a packet for dst leaves by.
	routeDevice(ctx context.Context, r Runner, dst string) (string, error)

	// revertExclusionsScript is the extra shell the dead-man's switch runs
	// after it clears the selection. "" when there is nothing to undo, which
	// is itself the point on darwin: a switch that has nothing to clean up
	// cannot fail to clean it up.
	revertExclusionsScript(r PrivilegedRunner) string

	bootGuardName() string
	bootGuardInstalled() bool
	installBootGuard(ctx context.Context, r PrivilegedRunner, tailscalePath string) error
	removeBootGuard(ctx context.Context, r PrivilegedRunner) error

	// planNarration is what --plan prints between the gate and the
	// confirmation: the commands this platform would really run.
	planNarration(gateIP string) []string
}

// platformFor picks the implementation for a measured host, and refuses the
// platforms that have none. Resolve() has usually refused those already; this
// is the backstop that keeps a future caller from reaching the sequence with
// a nil platform.
func platformFor(h Host) (exitPlatform, error) {
	plat, err := platformForOS(h.OS)
	if err != nil {
		return nil, err
	}
	if l, ok := plat.(linuxExit); ok {
		// Absolute, and resolved HERE rather than at use: the dead-man's
		// switch bakes this path into a shell script that runs on a machine
		// whose network has just gone, which is the worst possible moment to
		// discover a binary is not where it was assumed to be. No `ip`, no
		// plan.
		ipPath, err := lookPath("ip")
		if err != nil {
			return nil, fmt.Errorf("`ip` is not on PATH, and the route exclusions cannot be installed without it: %w", err)
		}
		l.ipPath = ipPath
		return l, nil
	}
	return plat, nil
}

// platformForOS picks the implementation from a GOOS alone, leaving `ip` as a
// bare command name. That is all the read-only callers need — only the plan
// requires an absolute path, and platformFor is where it is resolved and
// refused.
func platformForOS(goos string) (exitPlatform, error) {
	switch goos {
	case "linux":
		return linuxExit{ipPath: "ip"}, nil
	case "darwin":
		return darwinExit{}, nil
	default:
		return nil, fmt.Errorf("%s has no exit-gate implementation in this module — only linux and darwin are supported", goos)
	}
}

// currentPlatform is for the exported helpers that are called outside the
// sequence (`status`, mostly) and have no plan to read it off. Dispatching on
// runtime.GOOS is exact there: everything in this package runs on the machine
// it is describing, so Host.OS and runtime.GOOS are the same value.
func currentPlatform() exitPlatform {
	p, err := platformForOS(runtime.GOOS)
	if err != nil {
		return unsupportedExit{}
	}
	return p
}

// unsupportedExit is what the read-only helpers get on a platform with no
// implementation — Windows, where `status` still has to render something. It
// answers "nothing here" instead of reaching for a tool that does not exist,
// and it can never reach the use-exit sequence, which platformFor refuses for
// that OS outright. Darwin's no-op exclusion methods are exactly right to
// inherit; only the four that would say something untrue are overridden.
type unsupportedExit struct{ darwinExit }

func (unsupportedExit) name() string { return runtime.GOOS }

func (unsupportedExit) routeDevice(context.Context, Runner, string) (string, error) {
	return "", nil
}

func (unsupportedExit) bootGuardName() string    { return "(no boot guard on " + runtime.GOOS + ")" }
func (unsupportedExit) bootGuardInstalled() bool { return false }

// ---------------------------------------------------------------- linux ---

// linuxExit is the original implementation, unchanged in behaviour: `ip rule`
// exclusions at priority 5260 and a systemd boot guard.
type linuxExit struct {
	// ipPath is resolved at plan time because the dead-man's switch has to
	// bake it into a shell script that runs when the network is broken.
	ipPath string
}

func (linuxExit) name() string { return "linux" }

// preflight has nothing to discover on Linux: Resolve() already refused a
// host without root, and root is the whole of what `ip rule` and `tailscale
// set` need here.
func (linuxExit) preflight(_ context.Context, h Host, base Runner) (PrivilegedRunner, error) {
	return PrivilegedRunner{Inner: base, Sudo: h.UID != 0}, nil
}

func (linuxExit) planExclusions(controlPlane string, extra []string, resolve Resolver) (ExclusionPlan, error) {
	return PlanExclusions(controlPlane, LocalPrefixes(), extra, resolve)
}

func (linuxExit) manageability(string) string { return "" }

func (linuxExit) applyExclusions(ctx context.Context, r Runner, ex []Exclusion) error {
	return ApplyExclusions(ctx, r, ex)
}

func (linuxExit) clearExclusions(ctx context.Context, r Runner) (int, error) {
	return clearIPRuleExclusions(ctx, r)
}

func (linuxExit) listExclusions(ctx context.Context, r Runner) ([]string, error) {
	return listIPRuleExclusions(ctx, r)
}

func (linuxExit) routeDevice(ctx context.Context, r Runner, dst string) (string, error) {
	out, err := r.Run(ctx, "ip", "route", "get", dst)
	if err != nil {
		return "", fmt.Errorf("ip route get %s: %w: %s", dst, err, strings.TrimSpace(out))
	}
	return parseRouteDevice(out), nil
}

func (l linuxExit) revertExclusionsScript(r PrivilegedRunner) string {
	return fmt.Sprintf("while %s rule del priority %d 2>/dev/null; do :; done", r.CommandPrefix(l.ipPath), exclusionPriority)
}

func (linuxExit) bootGuardName() string    { return systemdBootGuardUnit }
func (linuxExit) bootGuardInstalled() bool { return fileExists(systemdBootGuardPath) }

func (l linuxExit) installBootGuard(ctx context.Context, r PrivilegedRunner, tailscalePath string) error {
	return installSystemdBootGuard(ctx, r, tailscalePath, l.ipPath)
}

func (linuxExit) removeBootGuard(ctx context.Context, r PrivilegedRunner) error {
	return removeSystemdBootGuard(ctx, r)
}

func (linuxExit) planNarration(gateIP string) []string {
	return []string{
		fmt.Sprintf("would run: ip rule add to <each prefix above> lookup main priority %d", exclusionPriority),
		fmt.Sprintf("would run: tailscale set --exit-node=%s --exit-node-allow-lan-access=true --accept-dns=false", gateIP),
	}
}

// --------------------------------------------------------------- darwin ---

// darwinExit is the Mac as a CLIENT of a gate — selecting one, never offering
// one. Advertising still refuses (Resolve's ExitRefusal): forwarding needs a
// sysctl nobody here has exercised on real hardware, and that is a separate
// claim from routing this machine's own traffic out.
type darwinExit struct{}

func (darwinExit) name() string { return "darwin" }

// checkprefsDenied is the string tailscaled answers an unprivileged prefs
// write with. Matched rather than merely reported so the refusal below can be
// the ACTIONABLE sentence (which one-time command fixes it) instead of a
// verbatim dump of somebody else's error.
const checkprefsDenied = "checkprefs access denied"

// preflight answers the one thing about a Mac that cannot be read off it:
// may THIS user write tailscale's preferences?
//
// uid and `sudo -n` — the two privilege facts Probe() measures — answer the
// wrong question here. tailscaled on macOS runs as a root LaunchDaemon and
// gates every write on the CALLING user, so a non-root user who has been
// granted `tailscale set --operator=<user>` may write, and a user with
// passwordless sudo who never ran it is refused all the same. Neither is
// visible from the outside; the only honest probe is a write.
//
// So the probe is a write that changes nothing. --accept-dns=false is what
// SetExitNode passes on every single call anyway, and this module forces
// MagicDNS off at enrolment for the lockout reason in vpn.go's header — so
// issuing it here either succeeds as a genuine no-op or fails with the exact
// error the real call would fail with, one step earlier, before the
// dead-man's switch is armed and the route starts moving. Measured on
// Mac.Home as uid 503 with no sudo: "Access denied: checkprefs access denied
// / Use 'sudo tailscale set --accept-dns=false'. / To not require root, use
// 'sudo tailscale set --operator=$USER' once."
//
// The unprivileged runner is tried FIRST and kept when it works, which is the
// opposite of Linux. Wrapping in `sudo -n` on a Mac whose user has the
// operator grant would swap a working call for "sudo: a password is
// required", i.e. report the wrong blocker on a machine that is fine.
func (darwinExit) preflight(ctx context.Context, h Host, base Runner) (PrivilegedRunner, error) {
	plain := PrivilegedRunner{Inner: base, Sudo: false}
	out, err := plain.Run(ctx, "tailscale", "set", "--accept-dns=false")
	if err == nil {
		return plain, nil
	}
	denied := strings.Contains(strings.ToLower(out), checkprefsDenied)

	if h.PasswordlessSudo || h.UID == 0 {
		elevated := PrivilegedRunner{Inner: base, Sudo: h.UID != 0}
		if sudoOut, sudoErr := elevated.Run(ctx, "tailscale", "set", "--accept-dns=false"); sudoErr == nil {
			return elevated, nil
		} else if !denied {
			return PrivilegedRunner{}, fmt.Errorf("tailscale would not accept a preference write on this Mac, as this user (%v: %s) or through sudo (%v: %s) — nothing has been changed", err, strings.TrimSpace(out), sudoErr, strings.TrimSpace(sudoOut))
		}
	}

	if denied {
		return PrivilegedRunner{}, fmt.Errorf("tailscaled on macOS runs as a root LaunchDaemon and refused a preference write from this user: %q. Nothing has been changed, and no route was touched. Grant this user the tailscale operator role ONCE, from an administrator account on this Mac:\n\n    sudo tailscale set --operator=%s\n\nAfter that no further privilege is needed to select a gate from here, because on macOS tailscaled owns the routing and this module installs no routes of its own", strings.TrimSpace(out), currentUserName())
	}
	return PrivilegedRunner{}, fmt.Errorf("tailscale would not accept a preference write on this Mac (%w: %s) — refusing to touch the default route when the command that would undo it may not run either", err, strings.TrimSpace(out))
}

// planExclusions on darwin installs NOTHING, and that is the measured answer
// rather than a gap left for later.
//
// On Linux the exclusions are `ip rule ... lookup main`, and the mechanism
// was chosen for one property: a leftover rule is INERT. "Send this prefix to
// the main table" is what an unconfigured machine already does, so failing to
// clean up cannot strand anything (exit.go's header, and the container that
// lost the internet for two days).
//
// macOS has no equivalent with that property. There is no `ip rule` and no
// table 52; tailscaled owns the utun and installs the split default itself.
// The only way to hold one address outside it is a static host route —
// `route -n add -host <ip> <gateway>` — and that mechanism is the exact
// inverse of inert: it names a gateway. A laptop that leaves the network that
// gateway belonged to comes back with a black hole for precisely the address
// the exclusion existed to protect, and a laptop is the one machine that
// changes networks every day. A pin whose failure mode is "the control plane
// specifically becomes unreachable, silently, later" is worse than no pin, not
// a weaker version of one. It also needs root, which the operator grant
// deliberately does not confer.
//
// What macOS does natively is the half that mattered most:
// --exit-node-allow-lan-access=true, passed by SetExitNode on every
// selection, keeps this host's own LAN outside the tunnel — and tailscaled
// removes it together with the selection, so it is an exclusion that cannot
// outlive its justification.
//
// The control plane is still RESOLVED here, and an unresolvable one is still
// a refusal. On darwin its reachability stops being something this module
// INSTALLS and becomes something the confirmation step MEASURES: a gate that
// breaks the management path fails ConfirmEgress and is reverted, rather than
// being routed around. Measuring it requires knowing where it is, so the
// precondition survives even though the pin does not.
func (darwinExit) planExclusions(controlPlane string, extra []string, resolve Resolver) (ExclusionPlan, error) {
	host, ips, err := resolveControlPlane(controlPlane, resolve)
	if err != nil {
		return ExclusionPlan{}, err
	}
	plan := ExclusionPlan{ControlPlaneHost: host, ControlPlaneIPs: ips}
	// An --exclude list cannot be honoured here, and silently dropping it
	// would be the worst of both: the operator believes a prefix is pinned
	// and it is not.
	for _, raw := range extra {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		return ExclusionPlan{}, fmt.Errorf("--exclude %q cannot be honoured on macOS: this module installs no routes here (see the exit gate's darwin notes), so accepting the flag would tell you a prefix is outside the tunnel when nothing is holding it there. Re-run without --exclude, or select the gate from a Linux host", strings.TrimSpace(raw))
	}
	return plan, nil
}

func (darwinExit) manageability(controlPlaneHost string) string {
	return fmt.Sprintf("the control plane (%s) is INSIDE the tunnel while this gate is in force. macOS offers no exclusion mechanism that is safe to leave behind, so the management path is CONFIRMED rather than pinned: this run proves it still works through the gate and reverts if it does not. What that does not cover is the gate breaking LATER — then this Mac loses its internet and its /link tunnel together, and the way back is somebody at the keyboard running `aw-remote-host vpn clear-exit`, or a reboot, which the boot guard turns into a clean slate.", controlPlaneHost)
}

func (darwinExit) applyExclusions(context.Context, Runner, []Exclusion) error { return nil }
func (darwinExit) clearExclusions(context.Context, Runner) (int, error)       { return 0, nil }
func (darwinExit) listExclusions(context.Context, Runner) ([]string, error)   { return nil, nil }

// routeDevice reads `route -n get <dst>`, macOS's answer to `ip route get`.
// It needs no privilege, which matters: this is the cheap local half of the
// confirmation and it runs while the route is already moved.
func (darwinExit) routeDevice(ctx context.Context, r Runner, dst string) (string, error) {
	out, err := r.Run(ctx, "route", "-n", "get", dst)
	if err != nil {
		return "", fmt.Errorf("route -n get %s: %w: %s", dst, err, strings.TrimSpace(out))
	}
	return parseDarwinRouteInterface(out), nil
}

// parseDarwinRouteInterface picks the interface out of `route -n get`, whose
// output is "key: value" lines rather than ip's single flat line:
//
//	   route to: 1.1.1.1
//	destination: default
//	    gateway: 192.168.1.254
//	  interface: en0
//
// A confirmed selection turns that last line into a utun.
func parseDarwinRouteInterface(out string) string {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "interface" {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

// revertExclusionsScript is empty because there is nothing to revert, and
// that is a property worth naming rather than an omission: the dead-man's
// switch on a Mac is one `tailscale set --exit-node=` and cannot half-fail.
func (darwinExit) revertExclusionsScript(PrivilegedRunner) string { return "" }

func (darwinExit) bootGuardName() string { return launchdBootGuardLabel }

func (darwinExit) bootGuardInstalled() bool {
	path, err := launchdBootGuardPath()
	return err == nil && fileExists(path)
}

func (darwinExit) installBootGuard(ctx context.Context, r PrivilegedRunner, tailscalePath string) error {
	return installLaunchdBootGuard(ctx, r, tailscalePath)
}

func (darwinExit) removeBootGuard(ctx context.Context, r PrivilegedRunner) error {
	return removeLaunchdBootGuard(ctx, r)
}

func (darwinExit) planNarration(gateIP string) []string {
	return []string{
		"would install NO route exclusions: on macOS tailscaled owns the utun and the LAN stays outside the tunnel natively via --exit-node-allow-lan-access. The control plane is confirmed through the gate instead of pinned around it",
		fmt.Sprintf("would run: tailscale set --exit-node=%s --exit-node-allow-lan-access=true --accept-dns=false", gateIP),
	}
}

// ---------------------------------------------------------------- shared ---

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// currentUserName is only ever used to spell the operator command back at a
// human, so an unknown name degrades to the shell's own $USER rather than
// failing the refusal it appears in.
func currentUserName() string {
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		return u
	}
	if u := strings.TrimSpace(os.Getenv("LOGNAME")); u != "" {
		return u
	}
	return "$USER"
}

// launchdBootGuardLabel is the LaunchAgent that clears an exit-node selection
// at login — darwin's answer to the systemd boot guard.
//
// It is a user AGENT, not a system daemon, and that is what makes it possible
// at all: ~/Library/LaunchAgents is writable by the account aw-remote-host
// already installs its own service into (internal/servicemgr/launchd.go), so
// the escape hatch needs no privilege beyond the one-time operator grant.
//
// The premise differs from Linux's and the comment should not pretend
// otherwise. There, the guard exists because the selection survives a reboot
// and the `ip rule` exclusions do not, so the machine comes back with half
// the configuration. Here there are no exclusions to lose, so a reboot is
// symmetric — the guard is kept because the OTHER half of that unit's value
// applies unchanged: a reboot must always be a way out of a gate that stopped
// forwarding, which on a laptop is the likeliest recovery a human reaches
// for. The cost is that an agent fires at LOGIN, not at boot, so the window
// between the two is not covered. Said out loud rather than glossed.
const launchdBootGuardLabel = "com.tekflox.aw-vpn-exit-clear"

func launchdBootGuardPath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdBootGuardLabel+".plist"), nil
}

// launchdBootGuardPlist renders the agent. Split out from the install so a
// test can assert on it without a Mac — the same reason
// servicemgr.GenerateLaunchdPlist is its own function.
func launchdBootGuardPlist(tailscalePath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <!-- An exit-node selection is a tailscale PREFERENCE and survives a reboot.
       Nothing confirmed it on the way back up, so a gate that stopped
       forwarding while this Mac was off would leave it with no internet and
       no route to the control plane. Clearing at login makes a restart the
       way out, the same escape hatch tools/host-firewall establishes for the
       firewall. -->
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>set</string>
    <string>--exit-node=</string>
    <string>--exit-node-allow-lan-access=false</string>
    <string>--accept-dns=false</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>AbandonProcessGroup</key><true/>
</dict>
</plist>
`, launchdBootGuardLabel, tailscalePath)
}

// installLaunchdBootGuard writes and loads the agent. Idempotent: the agent
// is booted out before it is bootstrapped, because launchctl refuses to
// bootstrap a label already in the domain and a second use-exit must not fail
// on the guard the first one installed.
//
// Everything goes through the Runner rather than os.WriteFile so the same
// privilege wrapper the rest of the sequence uses applies here too — see
// InstallBootGuard's counterpart comment.
func installLaunchdBootGuard(ctx context.Context, r PrivilegedRunner, tailscalePath string) error {
	path, err := launchdBootGuardPath()
	if err != nil {
		return err
	}
	script := fmt.Sprintf("mkdir -p %s && cat > %s <<'AW_VPN_PLIST_EOF'\n%sAW_VPN_PLIST_EOF\n", filepath.Dir(path), path, launchdBootGuardPlist(tailscalePath))
	if out, err := r.Run(ctx, "sh", "-c", script); err != nil {
		return fmt.Errorf("write %s: %w: %s", path, err, strings.TrimSpace(out))
	}
	_, _ = r.Run(ctx, "launchctl", "bootout", launchdGUITarget())
	if out, err := r.Run(ctx, "launchctl", "bootstrap", launchdGUIDomain(), path); err != nil {
		// The legacy loader, for the same reason servicemgr keeps it: older
		// macOS, and domains where bootstrap reports a conflict this command
		// resolves anyway.
		if out2, err2 := r.Run(ctx, "launchctl", "load", "-w", path); err2 != nil {
			return fmt.Errorf("launchctl bootstrap failed (%v: %s) and launchctl load also failed (%v: %s)", err, strings.TrimSpace(out), err2, strings.TrimSpace(out2))
		}
	}
	return nil
}

func removeLaunchdBootGuard(ctx context.Context, r PrivilegedRunner) error {
	path, err := launchdBootGuardPath()
	if err != nil {
		return err
	}
	if !fileExists(path) {
		return nil
	}
	// Best-effort: an agent that is not loaded is the normal case on the
	// clear path that follows a login, and failing here would block the undo.
	_, _ = r.Run(ctx, "launchctl", "bootout", launchdGUITarget())
	if out, err := r.Run(ctx, "rm", "-f", path); err != nil {
		return fmt.Errorf("remove %s: %w: %s", path, err, strings.TrimSpace(out))
	}
	return nil
}

// launchdGUIDomain / launchdGUITarget mirror internal/servicemgr's guiDomain:
// os.Getuid works on every platform, so these need no build tag even though
// launchctl only exists on macOS.
func launchdGUIDomain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

func launchdGUITarget() string { return launchdGUIDomain() + "/" + launchdBootGuardLabel }
