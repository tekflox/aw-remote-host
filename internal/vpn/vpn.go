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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	IPForward        bool // net.ipv4.ip_forward is already 1
	BrewPrefix       string
	BrewWritable     bool
	TailscalePath    string // "" when tailscale is not on PATH
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
	// CanAdvertiseExit: this node can additionally offer itself as an exit
	// gate. Strictly narrower than CanEnroll.
	CanAdvertiseExit bool
	ExitRefusal      string
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
	case h.OS != "linux":
		// macOS can technically be an exit node, but enabling IP forwarding
		// there is a different sysctl and none of it has been exercised on
		// real hardware. Claiming it works untested is exactly the silent
		// degradation this package exists to avoid.
		e.ExitRefusal = fmt.Sprintf("advertising an exit node needs IP forwarding enabled in the kernel, which this module only knows how to do on Linux — %s is untested and is deliberately not claimed.", h.OS)
	case h.WSL:
		// The Surface. It enrols fine and is a good client; as a gate it
		// would forward through a second layer of Windows NAT it does not
		// control, and nothing about that has been measured.
		e.ExitRefusal = "this is a WSL2 distro. It can join the mesh, but its network is NATed again by the Windows host it runs inside, so traffic forwarded through it as an exit gate has not been validated and is not offered."
	default:
		e.CanAdvertiseExit = true
	}

	return e
}

func systemdRefusal(wsl bool) string {
	if wsl {
		return "/run/systemd/system does not exist, so systemd is not PID 1 in this WSL2 distro and there is nothing to keep tailscaled running. Add `[boot]\\nsystemd=true` to /etc/wsl.conf, run `wsl --shutdown` from Windows, and re-run."
	}
	return "/run/systemd/system does not exist, so systemd is not managing this host and this module has no other way to keep tailscaled running across reboots."
}

// Describe renders an eligibility verdict for a status line or a log.
func (e Eligibility) Describe() string {
	switch {
	case e.CanAdvertiseExit:
		return "eligible (can join the mesh and can be advertised as an exit node)"
	case e.CanEnroll:
		return "eligible to join the mesh, NOT eligible as an exit node — " + e.ExitRefusal
	default:
		return "NOT eligible — " + e.EnrollRefusal
	}
}

// Probe reads this machine's facts. Everything it touches is read-only: it
// stats devices, reads a sysctl, and runs `sudo -n true`, which by definition
// cannot prompt. It never installs or configures anything, so it is safe to
// call from `status` on every host, including the ones it will refuse.
func Probe() Host {
	h := Host{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
		UID:  os.Getuid(),
	}
	if path, err := exec.LookPath("tailscale"); err == nil {
		h.TailscalePath = path
	}
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
	}
	return h
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
