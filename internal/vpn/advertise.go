// OFFERING this node as an exit gate — the half that was missing.
//
// Phase 1 could advertise an exit route, but only as a side effect of
// ENROLMENT: `AW_VPN_ADVERTISE_EXIT=1` on a bootstrap run, decided once, on a
// machine that was joining the mesh for the first time. A node already on the
// mesh had no way to start offering, which is why on 2026-08-26 this account's
// mesh had exactly one gate — the one somebody had thought to ask for at
// enrolment time — and the Networking screen's gate picker was correct to list
// nothing else.
//
// OFFERING IS NOT USING, and that separation is the whole reason this file can
// exist next to usexit.go without inheriting its machinery. Advertising a
// route does not change this machine's default route: confirmed on the
// production bare-metal on 2026-08-25 (it kept egressing 65.109.66.88 while
// serving as a gate), and asserted here on every call rather than trusted —
// Advertise measures the route before and after and reports both, so a
// regression shows up as evidence instead of as somebody's outage.
//
// So there is no dead-man's switch here, no route exclusions and no boot
// guard. Those exist in usexit.go because selecting a gate can strand the
// machine along with the means of fixing it. Advertising cannot: the worst
// case is a node that offers something nobody approved, which is exactly the
// state the control plane's other half removes.
package vpn

import (
	"context"
	"fmt"
	"strings"
)

// sysctlDropIn is the SAME path bootstrap/vpn/install.sh writes. One file, so
// a host that was enrolled with AW_VPN_ADVERTISE_EXIT=1 and a host that
// started offering later end up in one state rather than two that disagree —
// the same reason bootstrap/lib/vpn.sh exists.
const sysctlDropIn = "/etc/sysctl.d/99-aw-vpn-exit-node.conf"

// forwardingSysctls are what a LINUX kernel needs before it will pass another
// node's packets at all. Both families: approving only the v4 half leaves a
// node tailscale still calls an exit node while half of a dual-stack client's
// traffic goes nowhere.
var forwardingSysctls = []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}

// darwinForwardingSysctls are the same two knobs under the names macOS gives
// them. Different names, identical stakes.
var darwinForwardingSysctls = []string{"net.inet.ip.forwarding", "net.inet6.ip6.forwarding"}

// forwarding is one OS's answer to "make this kernel pass another node's
// packets, and keep it that way across a reboot".
//
// It is a small value dispatched on the measured Host.OS rather than a build
// tag, for the reason usexit_platform.go gives at length: the darwin
// behaviour has to be testable from the Linux container this project builds
// in, and a build-tagged darwin file is code nobody here can run a test
// against until it is already on somebody's laptop.
type forwarding struct {
	// keys are the sysctls, set in this order and read back in it.
	keys []string
	// persistPath is the file that makes it survive a reboot. Named in every
	// warning and refusal that mentions it, so a human can go and look.
	persistPath string
	// persistScript is the shell that writes persistPath. On Linux it owns a
	// drop-in of its own and may overwrite it; on macOS there is no
	// /etc/sysctl.d and the file is SHARED, so the script merges — discarding
	// somebody's other kernel settings to turn on forwarding would be a
	// second, unasked-for change to their machine.
	persistScript string
}

func forwardingFor(goos string) (forwarding, bool) {
	switch goos {
	case "linux":
		return forwarding{
			keys:        forwardingSysctls,
			persistPath: sysctlDropIn,
			persistScript: fmt.Sprintf("printf '%%s' %q > %s",
				"net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n", sysctlDropIn),
		}, true
	case "darwin":
		return forwarding{
			keys:        darwinForwardingSysctls,
			persistPath: darwinSysctlConf,
			// Written through a temp file because the read and the write are
			// the same path: `cat f | ... > f` truncates f before cat opens
			// it, which would turn "add two keys" into "delete everything
			// else in it".
			persistScript: fmt.Sprintf(
				`{ cat %[1]s 2>/dev/null | grep -v '^net\.inet\.ip\.forwarding=' | grep -v '^net\.inet6\.ip6\.forwarding='; printf 'net.inet.ip.forwarding=1\nnet.inet6.ip6.forwarding=1\n'; } > %[1]s.aw-new && mv %[1]s.aw-new %[1]s`,
				darwinSysctlConf),
		}, true
	default:
		return forwarding{}, false
	}
}

// AdvertiseResult is everything one advertise/withdraw measured, kept whole so
// a caller reports what happened rather than what it asked for.
type AdvertiseResult struct {
	// Advertising is read back from tailscale's own prefs after the change,
	// never assumed from the command returning 0.
	Advertising bool
	// OffersExit is tailscale's ExitNodeOption — advertised AND approved by
	// the control plane. Normally FALSE right after advertising, and that is
	// not a failure: nobody has approved anything yet. It is the control
	// plane's job to make this true, and the caller's job to confirm it did.
	OffersExit  bool
	NodeName    string
	LoginServer string
	// Forwarding is the state of each sysctl AFTER the attempt, read back
	// from the kernel. A gate whose kernel drops forwarded packets is the
	// looks-armed-forwards-nothing failure wearing a different hat.
	Forwarding map[string]bool
	// RouteBefore/RouteAfter are the interface the kernel would send a packet
	// to the public internet out of, measured either side of the change.
	// Equal is the invariant; they are reported rather than compared away so
	// the evidence survives to the screen.
	RouteBefore string
	RouteAfter  string
	// Refused/Refusal: this host may not serve as a gate. A refusal is a
	// successful answer with a nil error — same shape vpn_bootstrap uses, so
	// a screen can tell "this machine is not able to" apart from "this
	// machine could not be asked".
	Refused bool
	Refusal string
	// Warning is the cost of choosing this gate, when it has one. Carried out
	// even on success, because the screen that offers the host is not
	// necessarily the one that later selects it.
	Warning string
}

// RouteUnchanged is the invariant: offering is not using.
//
// False only when a measurement on both sides actually disagreed. An
// unmeasurable route (no `ip`, a host that answered nothing) is not evidence
// of a change and must not be reported as one — the caller renders the two
// empty strings as unknown.
func (r AdvertiseResult) RouteUnchanged() bool {
	if r.RouteBefore == "" || r.RouteAfter == "" {
		return true
	}
	return r.RouteBefore == r.RouteAfter
}

// Advertise offers this node as an exit gate, or withdraws the offer.
//
// `elig` is the verdict from Resolve, passed in rather than probed here so a
// caller that has already probed does not do it twice and a test can pin it.
//
// ORDER, and why: forwarding is enabled BEFORE tailscale is told to
// advertise. The reverse would publish a route this kernel drops — a window,
// however short, in which the control plane could approve a gate that cannot
// forward. Withdrawing runs tailscale first for the mirror-image reason.
//
// Forwarding is deliberately NOT turned off on withdrawal. install.sh's own
// note is the argument: ip_forward on a machine nobody selects as an exit
// node changes nothing about its own traffic, and a withdraw that edits
// /etc/sysctl.d would fight the enrolment module over the same file.
func Advertise(ctx context.Context, r Runner, priv Runner, elig Eligibility, on bool, progress Progress) (AdvertiseResult, error) {
	res := AdvertiseResult{Warning: elig.ExitWarning, Forwarding: map[string]bool{}}

	if on && !elig.CanAdvertiseExit {
		res.Refused, res.Refusal = true, elig.ExitRefusal
		res.Warning = ""
		progress.emit("warning", "not offering this host as an exit gate: %s", elig.ExitRefusal)
		return res, nil
	}

	// Which sysctls, and which file keeps them. Resolve has already refused
	// every OS that has no answer here; this is the backstop that keeps a
	// future caller from reaching the kernel steps with none.
	fwd, ok := forwardingFor(elig.Host.OS)
	if on && !ok {
		res.Refused = true
		res.Refusal = fmt.Sprintf("%s has no exit-gate forwarding implementation in this module — only linux and darwin can be advertised as a gate.", elig.Host.OS)
		res.Warning = ""
		return res, nil
	}
	// The route reader is picked from the MEASURED host rather than from
	// runtime.GOOS — `ip route get` on Linux, `route -n get` on macOS — for
	// the reason usexit_platform.go's header gives: the darwin behaviour has
	// to be testable from the Linux container this project builds in.
	// RouteDevice, the exported helper, still dispatches on runtime.GOOS,
	// which is exact for the callers that have no Host to read it off.
	plat, platErr := platformForOS(elig.Host.OS)

	// Measured first, so the invariant has a baseline even on the paths that
	// fail later. A route that could not be read is not fatal here: it is
	// evidence about a claim, not a precondition of the change.
	if platErr == nil {
		res.RouteBefore, _ = plat.routeDevice(ctx, r, publicProbeAddr)
	}

	if on {
		if err := enableForwarding(ctx, r, priv, elig.Host, fwd, progress); err != nil {
			res.Refused = true
			res.Refusal = fmt.Sprintf(
				"this host cannot forward another node's packets: %s. Without kernel IP "+
					"forwarding an exit gate accepts traffic and drops it, so nothing was "+
					"advertised.", err)
			res.Warning = ""
			return res, nil
		}
		res.Forwarding = readForwarding(ctx, r, fwd)
		progress.emit("info", "advertising 0.0.0.0/0 and ::/0 — a control-plane admin still has to approve them")
	} else {
		progress.emit("info", "withdrawing this host's exit-route advertisement")
	}

	if err := setAdvertiseExit(ctx, r, priv, elig.Host, on); err != nil {
		return res, err
	}

	if platErr == nil {
		res.RouteAfter, _ = plat.routeDevice(ctx, r, publicProbeAddr)
	}
	if !res.RouteUnchanged() {
		// Loud, and not silently corrected. Advertising must never move the
		// advertiser's own route; if it ever does, the interesting thing is
		// that it happened, not that this function noticed.
		progress.emit("error",
			"this host's own default route CHANGED while it was only being asked to advertise (%s -> %s). Advertising must never do that.",
			res.RouteBefore, res.RouteAfter)
	}

	// Read back from tailscale rather than reported from the request. `set`
	// returning 0 says the daemon accepted the preference, not that it holds
	// it — and this whole package exists because those two have differed.
	if prefs, err := FetchPrefs(ctx, r); err == nil {
		res.Advertising = prefs.AdvertisesExit
		res.LoginServer = prefs.LoginServer
	}
	if st, err := FetchStatus(ctx, r); err == nil {
		res.OffersExit = st.OffersExit
		res.NodeName = st.NodeName
	}
	if !on {
		res.Warning = ""
	}
	return res, nil
}

// publicProbeAddr is the destination whose route stands in for "the default
// route". Same address ConfirmEgress uses for the same purpose, so the two
// halves of this package agree about what they are measuring.
const publicProbeAddr = "1.1.1.1"

// setAdvertiseExit writes the preference, through whichever runner this
// platform's daemon will actually accept it from.
//
// On Linux that is the privileged one and there is nothing to choose. On
// macOS the order is REVERSED and deliberately so: tailscaled runs as a root
// LaunchDaemon and gates prefs writes on the CALLING user, granted once by
// `tailscale set --operator=<user>`. Wrapping that in `sudo -n` on a Mac that
// has the grant — Mac.Home has it, OperatorUser "aw", measured 2026-09-01 —
// swaps a working call for "sudo: a password is required", which reports the
// wrong blocker about a machine that is fine. Same lesson, and the same
// remedy, as darwinExit.preflight.
//
// The FIRST failure is the one reported: on darwin that is the unprivileged
// attempt, which is the meaningful one. A trailing "a password is required"
// from the fallback would bury it.
func setAdvertiseExit(ctx context.Context, r Runner, priv Runner, h Host, on bool) error {
	arg := "--advertise-exit-node=false"
	if on {
		arg = "--advertise-exit-node=true"
	}
	runners := []Runner{priv}
	if h.OS == "darwin" {
		runners = []Runner{r, priv}
	}
	var firstOut string
	var firstErr error
	for _, runner := range runners {
		out, err := runner.Run(ctx, "tailscale", "set", arg)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstOut, firstErr = out, err
		}
	}
	return fmt.Errorf("tailscale set %s: %w: %s", arg, firstErr, strings.TrimSpace(firstOut))
}

// enableForwarding turns both sysctls on for this boot AND persists them,
// then PROVES it by reading them back.
//
// The read-back is the point, and it is the only thing here that decides
// anything. `sysctl -w` on a container with a read-only /proc/sys succeeds in
// some runtimes and changes nothing, and a gate whose kernel silently drops
// forwarded packets is indistinguishable, from the outside, from a gate
// nobody approved.
//
// The reads go through the UNPRIVILEGED runner: reading a sysctl needs no
// root anywhere, and asking through `sudo -n` on a Mac without passwordless
// sudo would turn a perfectly readable "1" into a permission error about the
// wrong thing.
func enableForwarding(ctx context.Context, r Runner, priv Runner, h Host, fwd forwarding, progress Progress) error {
	if allForwarding(readForwarding(ctx, r, fwd)) && !h.Privileged() {
		// The Mac an administrator has already prepared. Setting is
		// unnecessary, persisting is impossible from here, and failing on
		// `sudo -n` would refuse a machine that forwards perfectly well. What
		// this process cannot guarantee is said, not silently assumed.
		progress.emit("warning",
			"kernel forwarding is already on and this process has no root to write %s — a reboot may retire this gate silently, so re-check `sysctl -n %s` after a restart",
			fwd.persistPath, fwd.keys[0])
		return nil
	}
	// Persisted to the same file install.sh writes, so a reboot does not
	// quietly retire a gate other hosts are pointing at.
	if out, err := priv.Run(ctx, "sh", "-c", fwd.persistScript); err != nil {
		progress.emit("warning", "could not persist %s (%s) — forwarding will not survive a reboot", fwd.persistPath, strings.TrimSpace(out))
	}
	for _, key := range fwd.keys {
		if out, err := priv.Run(ctx, "sysctl", "-w", key+"=1"); err != nil {
			return fmt.Errorf("sysctl -w %s=1: %v: %s", key, err, strings.TrimSpace(out))
		}
	}
	for key, ok := range readForwarding(ctx, r, fwd) {
		if !ok {
			return fmt.Errorf("%s is still not 1 after being set — this kernel is not letting this host enable forwarding (a container with a read-only /proc/sys is the usual cause)", key)
		}
	}
	return nil
}

func readForwarding(ctx context.Context, r Runner, fwd forwarding) map[string]bool {
	out := map[string]bool{}
	for _, key := range fwd.keys {
		raw, err := r.Run(ctx, "sysctl", "-n", key)
		out[key] = err == nil && strings.TrimSpace(raw) == "1"
	}
	return out
}

// allForwarding is true only when every family reads 1. An empty map is
// false: "nothing was measured" is not "everything is on".
func allForwarding(state map[string]bool) bool {
	if len(state) == 0 {
		return false
	}
	for _, on := range state {
		if !on {
			return false
		}
	}
	return true
}
