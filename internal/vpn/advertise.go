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

// forwardingSysctls are what the kernel needs before it will pass another
// node's packets at all. Both families: approving only the v4 half leaves a
// node tailscale still calls an exit node while half of a dual-stack client's
// traffic goes nowhere.
var forwardingSysctls = []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}

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

	// Measured first, so the invariant has a baseline even on the paths that
	// fail later. RouteDevice's error is not fatal here: it is evidence about
	// a claim, not a precondition of the change.
	res.RouteBefore, _ = RouteDevice(ctx, r, publicProbeAddr)

	if on {
		if err := enableForwarding(ctx, priv, progress); err != nil {
			res.Refused = true
			res.Refusal = fmt.Sprintf(
				"this host cannot forward another node's packets: %s. Without kernel IP "+
					"forwarding an exit gate accepts traffic and drops it, so nothing was "+
					"advertised.", err)
			res.Warning = ""
			return res, nil
		}
		res.Forwarding = readForwarding(ctx, r)
		progress.emit("info", "advertising 0.0.0.0/0 and ::/0 — a control-plane admin still has to approve them")
	} else {
		progress.emit("info", "withdrawing this host's exit-route advertisement")
	}

	if err := setAdvertiseExit(ctx, priv, on); err != nil {
		return res, err
	}

	res.RouteAfter, _ = RouteDevice(ctx, r, publicProbeAddr)
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

func setAdvertiseExit(ctx context.Context, priv Runner, on bool) error {
	arg := "--advertise-exit-node=false"
	if on {
		arg = "--advertise-exit-node=true"
	}
	out, err := priv.Run(ctx, "tailscale", "set", arg)
	if err != nil {
		return fmt.Errorf("tailscale set %s: %w: %s", arg, err, strings.TrimSpace(out))
	}
	return nil
}

// enableForwarding turns both sysctls on for this boot AND persists them,
// then PROVES it by reading them back.
//
// The read-back is the point. `sysctl -w` on a container with a read-only
// /proc/sys succeeds in some runtimes and changes nothing, and a gate whose
// kernel silently drops forwarded packets is indistinguishable, from the
// outside, from a gate nobody approved.
func enableForwarding(ctx context.Context, priv Runner, progress Progress) error {
	drop := "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
	// Persisted to the same drop-in install.sh writes, so a reboot does not
	// quietly retire a gate other hosts are pointing at.
	if out, err := priv.Run(ctx, "sh", "-c",
		fmt.Sprintf("printf '%%s' %q > %s", drop, sysctlDropIn)); err != nil {
		progress.emit("warning", "could not persist %s (%s) — forwarding will not survive a reboot", sysctlDropIn, strings.TrimSpace(out))
	}
	for _, key := range forwardingSysctls {
		if out, err := priv.Run(ctx, "sysctl", "-w", key+"=1"); err != nil {
			return fmt.Errorf("sysctl -w %s=1: %v: %s", key, err, strings.TrimSpace(out))
		}
	}
	for key, ok := range readForwarding(ctx, priv) {
		if !ok {
			return fmt.Errorf("%s is still not 1 after being set — this kernel is not letting this host enable forwarding (a container with a read-only /proc/sys is the usual cause)", key)
		}
	}
	return nil
}

func readForwarding(ctx context.Context, r Runner) map[string]bool {
	out := map[string]bool{}
	for _, key := range forwardingSysctls {
		raw, err := r.Run(ctx, "sysctl", "-n", key)
		out[key] = err == nil && strings.TrimSpace(raw) == "1"
	}
	return out
}
