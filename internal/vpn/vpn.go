// Package vpn is this host's half of the tenant mesh: the probe that decides
// whether tailscale can really be installed and enrolled against the tenant's
// own headscale, and the reader that reports what an enrolled node is
// actually doing.
//
// This file is the ENROLMENT half: install the client, enrol the node, and
// OPTIONALLY advertise it as an exit node. Nothing in it selects an exit node
// and nothing in it touches this machine's default route. That half lives in
// exit.go, deadman.go and bootguard.go, behind an explicit `vpn use-exit`
// command, because it is the dangerous one — the /link tunnel is the only
// remote-management path a BYOD host has, so a broken default route takes
// down the means of fixing it along with the machine (the same accident
// already documented in cmd/aw-remote-host/commands.go's
// bootstrapWorkspaceSelfHeal call site). `--advertise-exit-node` is safe to
// include here because it provably does NOT change the advertiser's own
// routing — confirmed on the production bare-metal on 2026-08-25.
//
// The probe is why this is a Go package and not just a shell script. It is
// modelled on internal/hostpower.Resolve(): a request is not a grant, and the
// interesting number is the difference between the two. Measured on Mac.Home
// on 2026-08-25 — aw-remote-host runs there as uid 503 with no passwordless
// sudo, /opt/homebrew belongs to a different user, `brew install` fails on
// permissions, and `tailscale set` answers "Access denied: checkprefs access
// denied". Without root, tailscaled can only run in userspace-networking
// mode, which yields a SOCKS5 proxy and NOT a default route — so a host that
// "installed" that way would report success and deliver something else
// entirely. Refusing with a readable reason is the whole contract.
package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Environment variables bootstrap/vpn/install.sh and verify.sh read — the
// same input shape every other module uses (AW_POSTGRES_PASSWORD,
// AW_WORKSPACE_SLUG, ...), so the module runs unchanged whether it is driven
// from the `vpn` command here or from the control plane's "bootstrap" verb.
const (
	// EnvLoginServer is the tenant's own headscale, e.g.
	// https://headscale.aw.tekflox.com. Never defaulted and never hardcoded:
	// the architecture is one headscale PER TENANT precisely because two
	// headscales do not federate, which makes tenant isolation a property of
	// the topology instead of a property of getting an ACL right.
	EnvLoginServer = "AW_VPN_LOGIN_SERVER"
	// EnvAuthKey is a headscale pre-auth key. Consumed by `tailscale up` and
	// never written to state — see state.VPNState's doc comment.
	EnvAuthKey = "AW_VPN_AUTHKEY"
	// EnvHostname overrides the node name registered in the mesh. Defaults to
	// the machine's own hostname.
	EnvHostname = "AW_VPN_HOSTNAME"
	// EnvAdvertiseExit ("1"/"true"/"yes") offers this node as an exit node.
	// Offering is not being used: a headscale admin still has to approve the
	// 0.0.0.0/0 route before any peer can select it, and selecting it is a
	// separate, deliberate command on the client side either way.
	EnvAdvertiseExit = "AW_VPN_ADVERTISE_EXIT"
	// EnvAcceptDNS ("1"/"true"/"yes") opts INTO MagicDNS. Off by default, and
	// that default is deliberate: accepting DNS rewrites the host's resolver,
	// so a headscale that goes wrong stops this machine resolving the control
	// plane — the lockout failure mode, arriving through DNS instead of
	// through routing.
	EnvAcceptDNS = "AW_VPN_ACCEPT_DNS"
)

// Truthy reads the "1"/"true"/"yes" convention the module's boolean env vars
// use. Anything else — including an empty or unset value — is false.
func Truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

// Host is the set of raw facts a probe reads off a machine. It is split out
// from the verdicts below so Resolve stays a pure function and can be tested
// against the three hosts that were actually measured, rather than only
// against whatever machine happens to run `go test`.
type Host struct {
	OS   string // runtime.GOOS: "linux", "darwin", "windows"
	Arch string
	// WSL is true inside a WSL2 distro. It is a Linux host in every way that
	// matters here, but it earns its own field because the daemon story
	// differs: a distro without systemd enabled in /etc/wsl.conf has no way
	// to keep tailscaled running, and that is invisible from uname alone.
	WSL bool
	UID int
	// PasswordlessSudo is whether `sudo -n true` succeeded. Checked instead
	// of assumed from UID for the reason internal/firewall/probe.go gives:
	// the only trustworthy signal about privilege is whether a command was
	// actually allowed to run.
	PasswordlessSudo bool
	HasTUN           bool // /dev/net/tun exists and is a device node (Linux)
	HasSystemd       bool // /run/systemd/system exists — systemd is PID 1
	// IPForward is whether this kernel ALREADY forwards another node's
	// packets, both families. The keys differ per platform —
	// net.ipv4.ip_forward + net.ipv6.conf.all.forwarding on Linux,
	// net.inet.ip.forwarding + net.inet6.ip6.forwarding on macOS — and both
	// halves are required: a gate that forwards v4 and not v6 is a gate half
	// of a dual-stack client's traffic dies in.
	IPForward     bool
	BrewPrefix    string
	BrewWritable  bool
	TailscalePath string // "" when tailscale is nowhere this module looks
	// Enrolled is whether this node is not merely CAPABLE of joining the mesh
	// but already on it: tailscale is present and its backend reports
	// Running. It is measured because "could tailscale be installed here" and
	// "is tailscale already working here" are different questions, and until
	// 2026-09-01 this module answered the second with the first — refusing
	// Mac.Home for a Homebrew prefix it no longer needs, on a machine that had
	// been Running at 100.64.0.3 for a week.
	//
	// It deliberately says nothing about WHICH control plane the node answers
	// to. That comparison needs a login server this pure function is never
	// given, and it is already made, and reported as drift, by the status
	// path — see reportVPNStatus's "this node answers to X, but local state
	// records Y".
	Enrolled bool
}

// Privileged reports whether this host can run a command as root at all.
func (h Host) Privileged() bool { return h.UID == 0 || h.PasswordlessSudo }

// Installer names how tailscale would be put on this machine, for display
// and for the module README's disclosure of what gets fetched from where.
const (
	InstallerUpstreamScript = "tailscale.com/install.sh"
	InstallerHomebrew       = "brew install tailscale"
	InstallerNone           = ""
)

// Eligibility is the outcome of reconciling "enrol this host in the mesh"
// with what the host can actually do. Two separate verdicts, because they
// fail for different reasons and a host that can join the mesh but cannot
// serve as an exit gate is the common case, not an error.
type Eligibility struct {
	Host Host
	// CanEnroll: tailscale can be installed and `tailscale up` can run
	// against the tenant's headscale, with a real TUN interface.
	CanEnroll     bool
	EnrollRefusal string
	// AlreadyEnrolled is why CanEnroll is true on a host that could never
	// have been enrolled FROM here. It is carried separately so `status` can
	// say "already enrolled" rather than "eligible to join", which on
	// Mac.Home would be a sentence about a decision made a week ago.
	AlreadyEnrolled bool
	// CanAdvertiseExit: this node can additionally offer itself as an exit
	// gate. Strictly narrower than CanEnroll.
	CanAdvertiseExit bool
	ExitRefusal      string
	// ExitWarning is the THIRD answer, and it exists because "may it" and
	// "should it" are different questions that this type used to answer with
	// one boolean. A WSL2 distro forwards perfectly well and forwards through
	// another layer of Windows NAT it does not control — refusing it hides a
	// real capability, and allowing it silently hides a real cost. So it is
	// allowed, and the cost travels with the permission as a complete
	// sentence the control plane shows before anyone commits to it.
	//
	// Empty when there is nothing to say. Non-empty with CanAdvertiseExit
	// false is meaningless and never produced: an outright refusal already
	// carries its own reason in ExitRefusal.
	ExitWarning string
	// CanSelectExit: this node can be pointed AT a gate — the client side,
	// which is a different question from both of the above and is not implied
	// by either.
	//
	// Enrolment asks "could tailscale be installed and joined from here";
	// selecting asks "can this node, already on the mesh, have its default
	// route moved". Mac.Home is the case that forced the split: /opt/homebrew
	// belongs to another account, so CanEnroll is false and stays false, yet
	// tailscale is installed, tailscaled runs as a root LaunchDaemon and the
	// machine can select a gate perfectly well. Reusing CanEnroll there would
	// have refused it for the brew reason and sent its owner to fix the wrong
	// thing.
	CanSelectExit     bool
	SelectExitRefusal string
	// Installer is how install.sh would get tailscale here, when CanEnroll.
	Installer string
}

// Resolve turns measured facts into the two verdicts, each with a reason that
// is a complete sentence — it is shown verbatim to a human deciding why their
// machine is not in the list, so "false" on its own is not an answer. Same
// bargain as internal/firewall's defaultPrivilegedReason.
func Resolve(h Host) Eligibility {
	e := Eligibility{Host: h}

	switch h.OS {
	case "linux":
		switch {
		case !h.Privileged():
			e.EnrollRefusal = "aw-remote-host is not running as root here and `sudo -n true` fails, so tailscaled cannot be installed as a system daemon. Without root, tailscaled can only run with --tun=userspace-networking, which provides a SOCKS5/HTTP proxy and NOT a network interface — the node would appear enrolled while carrying none of this machine's traffic. Re-run aw-remote-host as root, or add a NOPASSWD sudoers entry for this user."
		case !h.HasTUN:
			e.EnrollRefusal = "/dev/net/tun is not present on this host, so tailscaled has no way to create the mesh interface. On a container or a minimal VM this usually means the tun module is not loaded (`modprobe tun`) or the device was not passed through."
		case !h.HasSystemd:
			e.EnrollRefusal = systemdRefusal(h.WSL)
		default:
			e.CanEnroll = true
			e.Installer = InstallerUpstreamScript
		}
	case "darwin":
		switch {
		case h.Enrolled:
			// ALREADY ON THE MESH, asked BEFORE "could I install it", and the
			// order is the fix. Every refusal below is about the INSTALLER —
			// a Homebrew prefix this user cannot write to, a system daemon
			// this user cannot install — and none of them is a fact about a
			// Mac where tailscaled is already running as a root LaunchDaemon
			// and the node is Running. Asking them first is how Mac.Home read
			// "NOT eligible to enrol" while sitting at 100.64.0.3, and, worse,
			// how that installation verdict short-circuited the ADVERTISE
			// decision below before the darwin branch was ever reached.
			//
			// Deliberately darwin-only. The Linux refusals are not about an
			// installer, they are about whether tailscaled can RUN: without
			// root it falls back to --tun=userspace-networking, which reports
			// BackendState=Running and is a SOCKS5 proxy carrying none of the
			// machine's traffic (this file's header). "Running" there is
			// exactly the claim that must not be trusted, so it does not get
			// to overrule the check that catches it.
			e.CanEnroll, e.AlreadyEnrolled = true, true
			e.Installer = InstallerNone
		case h.BrewPrefix == "":
			e.EnrollRefusal = "Homebrew is not installed and this module has no vendored macOS tailscale to fall back on, so there is no way to install the client here. Install Homebrew, or install tailscale by hand from https://tailscale.com/download/mac and re-run."
		case !h.BrewWritable:
			e.EnrollRefusal = fmt.Sprintf("%s exists but this user (uid %d) cannot write to it — it belongs to a different account, so `brew install tailscale` fails on permissions. Run aw-remote-host as the user who owns the Homebrew prefix, or install tailscale by hand and re-run.", h.BrewPrefix, h.UID)
		case !h.Privileged():
			// The measured Mac.Home case. Reported even when tailscale is
			// already installed there by hand, because managing it still
			// fails: `tailscale set` answers "Access denied: checkprefs
			// access denied" without root.
			e.EnrollRefusal = "`sudo -n true` fails for this user, so `sudo tailscaled install-system-daemon` cannot run. macOS needs that system daemon: without it tailscaled has no privileged helper, and `tailscale set`/`tailscale up` fail with \"Access denied: checkprefs access denied\". Grant this user passwordless sudo, or run the tailscale enrolment by hand once as an administrator."
		default:
			e.CanEnroll = true
			e.Installer = InstallerHomebrew
		}
	case "windows":
		// Not a gap to fill later: a Windows BYOD host runs its workspace
		// inside the WSL2 distro internal/wsl provisions, and that distro is
		// an ordinary Linux host which takes the linux branch above. Enrolling
		// the Windows side as well would put two nodes on one machine.
		e.EnrollRefusal = "This is the Windows side of the host. aw-remote-host runs the workspace inside its WSL2 distro, and that distro enrols in the mesh as an ordinary Linux node — run this module in there instead, so the machine appears once rather than twice."
	default:
		e.EnrollRefusal = fmt.Sprintf("%s is not a platform this module knows how to install tailscale on — only linux and darwin are supported.", h.OS)
	}

	switch {
	case !e.CanEnroll:
		e.ExitRefusal = "this host cannot join the mesh at all: " + e.EnrollRefusal
	case h.OS == "darwin":
		// IMPLEMENTED 2026-09-01. Until then this branch was the honest
		// refusal "macOS is untested and is deliberately not claimed", and
		// the way to retire a refusal like that is to do the work, not to
		// relax the check — so what decides it now is a measurement of this
		// kernel, not an assumption about the platform.
		e.CanAdvertiseExit, e.ExitRefusal, e.ExitWarning = resolveDarwinExit(h)
	case h.OS != "linux":
		// The backstop, and unreachable in practice: windows is already
		// refused above by CanEnroll. Kept for the same reason
		// platformForOS keeps its default — a future caller that finds a way
		// past the first gate should meet a sentence, not a silent true.
		e.ExitRefusal = fmt.Sprintf("advertising an exit node needs IP forwarding enabled in the kernel, which this module only knows how to do on linux and darwin — %s is untested and is deliberately not claimed.", h.OS)
	case h.WSL:
		// The Surface. Until 2026-08-26 this was an outright refusal, on the
		// grounds that forwarding through a second layer of Windows NAT had
		// not been measured. That was the wrong shape of answer: it is the
		// only machine the account has that could be a second gate, "not
		// measured" is not the same as "does not work", and a refusal left
		// the owner of the mesh with no way to find out either.
		//
		// So: allowed, with the cost stated. Everything routed through here
		// leaves via the Windows host's NAT and then whatever connection that
		// machine is on, and this node cannot hole-punch from behind that
		// extra layer — its measured path on this mesh is DERP(mad), meaning
		// a public relay carries every byte. Those are real performance and
		// privacy consequences, not caveats, and they belong in front of the
		// person choosing rather than in a commit message.
		e.CanAdvertiseExit = true
		e.ExitWarning = "this is a WSL2 distro. It can forward, but its network is NATed again by the Windows host it runs inside, so everything routed through it leaves via that machine's own connection — and from behind that extra layer this node cannot hole-punch, so peers reach it through a PUBLIC relay rather than directly. Choosing it sends every byte of the routed host's traffic through that relay and through this machine's home connection."
	default:
		e.CanAdvertiseExit = true
	}

	e.CanSelectExit, e.SelectExitRefusal = resolveSelectExit(h)
	return e
}

// resolveDarwinExit is the macOS half of "may this node OFFER itself as a
// gate", and it turns on a fact about the kernel rather than a fact about the
// user, because the two disagree on the machine this was written for.
//
// What a Mac gate needs is exactly two things, and they need different
// privileges:
//
//   - net.inet.ip.forwarding and net.inet6.ip6.forwarding at 1. `sysctl -w`
//     needs REAL root; the tailscale operator grant does not confer it.
//   - the prefs write `tailscale set --advertise-exit-node=true`, which on
//     macOS is granted per-user by `tailscale set --operator=` and needs no
//     root at all (see darwinExit.preflight).
//
// So a Mac whose administrator has already enabled forwarding may advertise
// while running as an ordinary user, and refusing it on uid would refuse a
// machine that works. A Mac that has NOT is refused — with the literal
// command that fixes it, because the one thing this module must never do is
// apply half of this. Forwarding on with nothing advertised is inert;
// advertised with forwarding off is a gate the control plane can approve,
// peers can select, and packets die in silently. Half is worse than none.
func resolveDarwinExit(h Host) (canAdvertise bool, refusal, warning string) {
	switch {
	case h.IPForward:
		// Somebody with root has already done the part this process cannot
		// do. Whether it STAYS done across a reboot is a different question,
		// and the answer travels with the permission rather than after it.
		if !h.Privileged() {
			return true, "", fmt.Sprintf("kernel IP forwarding is already on here, but this process runs as uid %d with no passwordless sudo, so it cannot write %s to keep it that way. A reboot may retire this gate silently, and nothing on the mesh would say so. Persist it once from an administrator account on this Mac:\n\n    %s\n", h.UID, darwinSysctlConf, darwinPersistCommand)
		}
		return true, "", darwinForwardingWarning
	case h.Privileged():
		return true, "", darwinForwardingWarning
	default:
		return false, darwinForwardingRefusal(h), ""
	}
}

// darwinSysctlConf is macOS's answer to /etc/sysctl.d, and it is a shared
// file rather than a drop-in directory — which is why everything that writes
// it here merges instead of overwriting. sysctl.conf(5) on macOS 26.5.1
// (measured on Mac.Home, 2026-09-01): "The /etc/sysctl.conf file is read in
// when the system goes into multi-user mode to set default settings for the
// kernel."
const darwinSysctlConf = "/etc/sysctl.conf"

// darwinPersistCommand is the one-liner a human runs, and it appends rather
// than rewrites because a person's own kernel settings are not this module's
// to discard. Re-running it adds a duplicate line, which is harmless: both
// say 1, and sysctl.conf takes the last.
const darwinPersistCommand = `sudo /bin/sh -c 'printf "net.inet.ip.forwarding=1\nnet.inet6.ip6.forwarding=1\n" >> /etc/sysctl.conf'`

// darwinForwardingWarning is the price of a Mac gate, carried on success the
// same way the WSL2 warning is. It is NOT "this might not work" — the
// forwarding is read back from the kernel before anything is advertised. It
// is the one thing this module genuinely cannot prove without rebooting
// somebody's laptop, said plainly instead of rounded up.
const darwinForwardingWarning = "this is a Mac. It forwards through net.inet.ip.forwarding / net.inet6.ip6.forwarding, which this module enables and reads back before advertising anything, and persists in " + darwinSysctlConf + " — the file macOS's own sysctl.conf(5) says is read at multi-user boot. That persistence has NOT been proved across a real reboot of this host, so after a restart confirm the gate with `sysctl -n net.inet.ip.forwarding` rather than assuming it came back."

// darwinForwardingRefusal is the deliverable on a Mac that cannot elevate:
// the exact command its owner has to run, with absolute paths, and the reason
// on one line. Working around it — advertising anyway and hoping, or enabling
// only what an unprivileged process can — is the failure this sentence exists
// instead of.
func darwinForwardingRefusal(h Host) string {
	return fmt.Sprintf("this Mac does not forward another node's packets yet (net.inet.ip.forwarding and net.inet6.ip6.forwarding are 0) and this process cannot turn them on: it runs as uid %d and `sudo -n true` fails, so `sysctl -w` is refused. NOTHING was advertised, deliberately — a route the control plane could approve while this kernel drops what arrives is worse than no gate at all. Run these ONCE from an administrator account on this Mac:\n\n    sudo /usr/sbin/sysctl -w net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1\n    %s\n\nThe first enables forwarding now; the second keeps it across a reboot via %s. After that no further privilege is needed here — tailscale's own preference write is granted per-user by `tailscale set --operator=`, which this host already has.", h.UID, darwinPersistCommand, darwinSysctlConf)
}

// resolveSelectExit is the client-side verdict: may this node's own default
// route be moved onto somebody else's gate?
//
// What each platform needs is genuinely different, and the difference is the
// whole reason darwin can be supported at all:
//
//   - Linux does the route surgery itself — `ip rule` exclusions plus
//     `tailscale set` — and both need root. No root, no selection.
//   - macOS does none. tailscaled runs as a root LaunchDaemon and owns the
//     utun, so the only thing this module does is write a preference, and the
//     right to write it is granted per-user by `tailscale set --operator=`.
//     That grant is invisible to uid and to `sudo -n`, which is exactly why
//     it is NOT decided here: this function answers the static half, and
//     darwinExit.preflight probes the live half before anything moves.
//   - Windows enrols through its WSL2 distro, so the Windows side selecting a
//     gate would move the route of the wrong operating system.
//
// Every path needs tailscale to already be here, and that is checked first:
// "enrol it first" is a more useful sentence than any of the ones below.
func resolveSelectExit(h Host) (bool, string) {
	if h.TailscalePath == "" {
		return false, "tailscale is not installed on this host, so there is no mesh to route through — enrol it first."
	}
	switch h.OS {
	case "linux":
		if !h.Privileged() {
			return false, "aw-remote-host is not running as root here and `sudo -n true` fails. Selecting a gate on Linux moves the default route and installs `ip rule` exclusions to keep the management path outside the tunnel, and both need root — without them the route would move with nothing holding the control plane out, which is the lockout this command exists to prevent. Re-run aw-remote-host as root, or add a NOPASSWD sudoers entry for this user."
		}
		return true, ""
	case "darwin":
		// No privilege condition on purpose. See the doc comment: on macOS
		// the right to change this is a tailscale grant, not a uid, and
		// refusing here on uid would refuse a Mac that works.
		return true, ""
	case "windows":
		return false, "This is the Windows side of the host. aw-remote-host runs the workspace inside its WSL2 distro, and it is that distro whose default route would need to move — selecting a gate from out here would route the wrong operating system. Run this in the distro instead."
	default:
		return false, fmt.Sprintf("%s has no exit-gate implementation in this module — only linux and darwin can select a gate.", h.OS)
	}
}

func systemdRefusal(wsl bool) string {
	if wsl {
		return "/run/systemd/system does not exist, so systemd is not PID 1 in this WSL2 distro and there is nothing to keep tailscaled running. Add `[boot]\\nsystemd=true` to /etc/wsl.conf, run `wsl --shutdown` from Windows, and re-run."
	}
	return "/run/systemd/system does not exist, so systemd is not managing this host and this module has no other way to keep tailscaled running across reboots."
}

// Describe renders the ENROLMENT-side verdict for a status line or a log:
// can this host join the mesh, and can it offer itself as a gate.
//
// It deliberately says nothing about selecting one. That is a third verdict
// which disagrees with this one on exactly the machine it matters for —
// Mac.Home reads "NOT eligible" here, because its Homebrew prefix belongs to
// another account, and can still be pointed at a gate — so DescribeSelectExit
// is a separate sentence rather than a clause folded into this one.
func (e Eligibility) Describe() string {
	switch {
	case e.CanAdvertiseExit && e.ExitWarning != "":
		// A permission and its price, never the permission alone. An operator
		// reading `aw-remote-host status` on the Surface has to see the same
		// sentence the Networking screen shows before offering it.
		return "eligible (can join the mesh and can be advertised as an exit node) — but " + e.ExitWarning
	case e.CanAdvertiseExit:
		return "eligible (can join the mesh and can be advertised as an exit node)"
	case e.AlreadyEnrolled:
		// A node that has been on the mesh for a week is not "eligible to
		// join" it, and saying so sent Mac.Home's reader off to fix a
		// Homebrew prefix that stopped mattering the day it enrolled.
		return "already enrolled in the mesh, NOT eligible as an exit node — " + e.ExitRefusal
	case e.CanEnroll:
		return "eligible to join the mesh, NOT eligible as an exit node — " + e.ExitRefusal
	default:
		return "NOT eligible to enrol — " + e.EnrollRefusal
	}
}

// DescribeSelectExit renders the CLIENT-side verdict: can this host's own
// default route be moved onto somebody else's gate.
func (e Eligibility) DescribeSelectExit() string {
	if e.CanSelectExit {
		return "CAN select an exit gate (as a client of one — a separate question from enrolling and from offering one)"
	}
	return "CANNOT select an exit gate — " + e.SelectExitRefusal
}

// Probe reads this machine's facts. Everything it touches is read-only: it
// stats devices, reads sysctls, runs `sudo -n true`, which by definition
// cannot prompt, and asks tailscale for its own status. It never installs or
// configures anything, so it is safe to call from `status` on every host,
// including the ones it will refuse.
func Probe() Host {
	h := Host{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
		UID:  os.Getuid(),
	}
	h.TailscalePath = LookupTailscale()
	// Root already has every privilege; shelling out to sudo would only add a
	// way for the probe to fail on a host with no sudo installed at all.
	if h.UID != 0 {
		h.PasswordlessSudo = exec.Command("sudo", "-n", "true").Run() == nil
	}

	switch h.OS {
	case "linux":
		if info, err := os.Stat("/dev/net/tun"); err == nil && info.Mode()&os.ModeDevice != 0 {
			h.HasTUN = true
		}
		if info, err := os.Stat("/run/systemd/system"); err == nil && info.IsDir() {
			h.HasSystemd = true
		}
		if raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
			n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
			h.IPForward = n == 1
		}
		h.WSL = detectWSL()
	case "darwin":
		h.BrewPrefix, h.BrewWritable = probeHomebrew()
		h.IPForward = probeDarwinForwarding()
	}
	h.Enrolled = probeEnrolled(h.TailscalePath)
	return h
}

// TailscaleSearchPath is where a tailscale binary lives when it is not on the
// caller's own PATH. macOS is the case that forced it to exist: Homebrew
// installs to /opt/homebrew/bin, which a launchd-started process does not
// inherit, so a bare LookPath on Mac.Home answers "not installed" about a
// machine that is demonstrably on the mesh.
var TailscaleSearchPath = []string{
	"/usr/bin/tailscale",
	"/usr/local/bin/tailscale",
	"/opt/homebrew/bin/tailscale",
	"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
}

// LookupTailscale resolves the tailscale binary, or "" when this host has
// none. It lives here rather than in internal/ops because Probe now needs the
// same answer ops does, and two copies of this list would drift into the
// state where one half of the module thinks a Mac is enrolled and the other
// half cannot find the client to ask.
func LookupTailscale() string {
	if path, err := exec.LookPath("tailscale"); err == nil {
		return path
	}
	for _, candidate := range TailscaleSearchPath {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// probeTimeout bounds the one thing Probe asks a daemon rather than the
// filesystem. `tailscale status` answers in milliseconds when tailscaled is
// up and fails fast when it is not, but Probe is called from `status` on
// every host and must not be the reason one hangs.
const probeTimeout = 5 * time.Second

// probeEnrolled answers the question that used to be inferred from the
// installer: is this node ON the mesh right now?
//
// Read from tailscale's own backend state rather than from state.json,
// because the module can be driven from the control plane with nothing on
// this side writing state — and because the case this exists for is a Mac
// enrolled by hand by a human, which no state file here ever recorded.
func probeEnrolled(tailscalePath string) bool {
	if tailscalePath == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	st, err := FetchStatus(ctx, probeRunner{bin: tailscalePath})
	return err == nil && st.Running()
}

// probeRunner is the one shellout internal/vpn does on its own account.
// Everything else in this package takes a Runner from its caller so a test
// can pin it; Probe cannot, because measuring the real machine is the whole
// of its job — the seam is Host itself, which is why Resolve is pure.
type probeRunner struct{ bin string }

func (p probeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "tailscale" && p.bin != "" {
		name = p.bin
	}
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// probeDarwinForwarding reads BOTH families and returns true only when both
// are 1. Half-forwarding is not a lesser gate, it is a gate that black-holes
// every dual-stack client's v6 — so it reads here as not forwarding at all.
func probeDarwinForwarding() bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	for _, key := range darwinForwardingSysctls {
		out, err := probeRunner{}.Run(ctx, "sysctl", "-n", key)
		if err != nil || strings.TrimSpace(out) != "1" {
			return false
		}
	}
	return true
}

// detectWSL reads /proc/version rather than checking for an env var: the
// WSL_DISTRO_NAME the shell sets is absent from a systemd service's
// environment, which is exactly where aw-remote-host runs on a linked host.
func detectWSL() bool {
	raw, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), "microsoft")
}

// probeHomebrew locates the brew prefix and reports whether THIS user can
// actually install into it — the two are different answers on Mac.Home, where
// /opt/homebrew is present and owned by another account, so `command -v brew`
// succeeds and `brew install` then fails on permissions.
//
// Writability is tested by creating and removing a file rather than by
// reading the mode bits, because mode bits do not account for group
// membership or ACLs and would answer confidently and wrongly.
func probeHomebrew() (prefix string, writable bool) {
	brew, err := exec.LookPath("brew")
	if err != nil {
		return "", false
	}
	// /opt/homebrew/bin/brew -> /opt/homebrew
	prefix = filepath.Dir(filepath.Dir(brew))
	f, err := os.CreateTemp(filepath.Dir(brew), ".aw-vpn-probe-*")
	if err != nil {
		return prefix, false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return prefix, true
}
