// What is ACTUALLY in force right now — the live query behind the VPN screen.
//
// WHY THIS IS NOT A READ OF state.json, which is the whole reason it exists.
// The dead-man's switch reverts AUTONOMOUSLY: it fires from a detached POSIX
// sh process that deliberately cannot call this binary, so nothing writes
// "actually, that tunnel is gone" back into the state file. A status built by
// replaying the record would therefore show "connected" minutes after the
// switch already tore the tunnel down — a protection that worked, rendered on
// screen as a lie. That is strictly worse than no status at all, because it
// is the one moment a human most needs to be told the truth.
//
// So every field that CAN be measured is measured, on every call:
//
//	up                 `wg show interfaces` — is the device actually there
//	rule_installed     `ip rule show` — is the /32 policy rule actually there
//	container_egress_ip a probe INSIDE the routed container's netns
//	host_egress_ip     this host's own public IP, over the wire
//	deadman_armed      the armed process's own command line, via Deadman.Fired
//
// The record is consulted only for IDENTITY and for TIMESTAMPS — which
// interface, which table, which container, when it was established — never for
// liveness. And `since` is nulled the moment measurement disagrees with the
// record, so the screen can never pair "connected since 14:02" with a tunnel
// that is not there.
package vpn

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// loadVPNRecords reads BOTH records in one pass over state.json.
//
// One read rather than two because this verb is polled by a screen, and
// because the two answers have to describe the same instant: a tunnel record
// read before a revert and a route record read after it would produce a report
// that never existed on the machine.
//
// A missing or unreadable state file is "nothing recorded" and never an error
// — a host that has never dialled is the normal case, not a fault.
func loadVPNRecords() (*state.ExternalTunnelState, *state.ExternalRouteState) {
	path, err := state.DefaultPath()
	if err != nil {
		return nil, nil
	}
	st, err := state.Load(path)
	if err != nil || st.VPN == nil {
		return nil, nil
	}
	return st.VPN.ExternalTunnel, st.VPN.ExternalRoute
}

// LoadExternalRouteRecord is loadVPNRecords' route half for callers outside
// this package — today vpn_public_ip (internal/ops), which has to know whether
// a container on this host is routed, and which one, before it can measure
// egress in the namespace where the answer is meaningful.
//
// A thin accessor rather than a second reader of state.json: the record's
// shape and the "a missing file is nothing recorded, not a fault" rule above
// are this package's, and a caller that re-derived them would be a caller that
// eventually disagrees with the status this file reports.
//
// nil means nothing is recorded, which is the normal case on most hosts.
func LoadExternalRouteRecord() *state.ExternalRouteState {
	_, route := loadVPNRecords()
	return route
}

// ExternalStatusReport is the shape the workspace core parses. It is fixed by
// that contract — core is already built against it and currently degrades to
// state "unknown" because this verb did not exist — so the JSON tags here are
// not free to change.
//
// The nullable fields are POINTERS on purpose. The contract spells them
// `"<ip>"|null`, and an empty Go string would marshal as `""`, which a caller
// has to special-case as a second kind of "nothing". One representation of
// absence, and it is the one that was asked for.
type ExternalStatusReport struct {
	Iface             string  `json:"iface"`
	Up                bool    `json:"up"`
	Table             int     `json:"table"`
	RuleInstalled     bool    `json:"rule_installed"`
	Container         *string `json:"container"`
	ContainerEgressIP *string `json:"container_egress_ip"`
	HostEgressIP      *string `json:"host_egress_ip"`
	DeadmanArmed      bool    `json:"deadman_armed"`
	DeadmanExpiresAt  *string `json:"deadman_expires_at"`
	Since             *string `json:"since"`

	// Guarantees carries dns_tunneled, kill_switch and warnings at the top
	// level of the JSON. Unlike the two apply verbs, which report what they
	// just DID, this one MEASURES the kill switch: it checks that the
	// exclusion routes the record says were installed are still in the
	// kernel. A pin that a rule flush took away is a kill switch that is
	// gone, and the record would never know.
	ExternalGuarantees
}

// ExternalStatusSpec is one live query.
type ExternalStatusSpec struct {
	// Iface/Table are fallbacks used only when nothing is recorded, so a
	// tunnel this tool lost track of can still be reported on.
	Iface string
	Table int
	// Runner is how every shellout is made. Required, never defaulted — same
	// field, same reason, as ExternalRouteSpec.Runner.
	Runner Runner
	// SkipEgress omits the two measurements that cost a network round trip:
	// this host's public IP, and the probe container in the routed
	// container's namespace. Both fields then report null, which the contract
	// already allows.
	//
	// It exists because a screen may poll this, and the two probes are
	// seconds each. It is OFF by default — the contract asks for the
	// addresses, and a status that quietly stopped measuring egress would be
	// exactly the kind of comfortable lie this file exists to prevent.
	SkipEgress bool
}

// ExternalStatus measures what is in force and reports it.
//
// It never returns an error for "nothing is set up" — that is a real and
// common answer, reported as up:false with null everywhere it matters. An
// error here means the query itself could not be performed.
func ExternalStatus(ctx context.Context, spec ExternalStatusSpec) (ExternalStatusReport, error) {
	runner := spec.Runner
	if runner == nil {
		return ExternalStatusReport{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	report := ExternalStatusReport{
		Iface: spec.Iface,
		Table: spec.Table,
	}

	// --- identity, from the record. Never liveness. ---
	tunnel, route := loadVPNRecords()

	if tunnel != nil {
		if report.Iface == "" {
			report.Iface = tunnel.Iface
		}
		if report.Table == 0 {
			report.Table = tunnel.Table
		}
	}
	if route != nil && report.Table == 0 {
		report.Table = route.Table
	}
	if report.Iface == "" {
		report.Iface = DefaultExternalIface
	}
	if report.Table == 0 {
		report.Table = ExternalRouteTable
	}

	// --- liveness, measured ---

	// `up` is the device being THERE, asked of wg itself. A recorded tunnel
	// whose interface has gone — which is exactly what the dead-man leaves
	// behind — reports false here, and that is the single most important
	// thing this function does.
	report.Up = interfacePresent(ctx, runner, report.Iface)

	if route != nil {
		container := route.Container
		report.Container = &container
		installed, err := ruleInstalled(ctx, runner, ExternalRoutePlan{
			SourceIP: route.SourceIP,
			Table:    route.Table,
			Priority: route.Priority,
		})
		report.RuleInstalled = err == nil && installed
	}

	// THE KILL SWITCH, MEASURED. The record lists the exclusions the apply
	// installed; this asks the kernel whether they are still there. Both
	// halves can fail independently and silently: the control plane may never
	// have resolved (so the record lists none), or systemd-networkd's daily
	// restart may have flushed the routes out from under a healthy record —
	// the same flush Reassert exists for. Either way Disconnect may not reach
	// the workspace, and either way nothing else would say so.
	killSwitch := false
	if route != nil && len(route.Exclusions) > 0 {
		killSwitch = true
		for _, prefix := range route.Exclusions {
			installed, err := routeInstalled(ctx, runner, ExternalRoutePlan{Table: route.Table}, prefix)
			if err != nil || !installed {
				killSwitch = false
				break
			}
		}
	}
	// DNS, MEASURED, on exactly the same principle as the kill switch above
	// and for the same reason: both halves of it can go away silently. The
	// DNS rules are flushed by the same daily systemd-networkd restart
	// Reassert exists for, and the aardvark upstream is rewritten by anything
	// that reloads the network — and neither failure is loud. A status that
	// replayed "dns_tunneled: true" from the record would be claiming a
	// privacy guarantee that had already lapsed, which is the one lie this
	// file exists to make impossible.
	report.ExternalGuarantees = newExternalGuarantees(report.Up || report.RuleInstalled, killSwitch, measuredDNSTunneled(ctx, runner, route))

	if d, err := LoadDeadman(); err == nil && d != nil {
		expires := d.ExpiresAt
		if expires != "" {
			report.DeadmanExpiresAt = &expires
		}
		// Fired() reads the armed process's own command line, so a switch
		// whose process is gone reports disarmed rather than armed-forever.
		report.DeadmanArmed = !d.Fired()
	}

	if !spec.SkipEgress {
		if host, err := PublicIP(ctx); err == nil && host.IP != "" {
			ip := host.IP
			report.HostEgressIP = &ip
		}
		if route != nil && route.Runtime != "" && route.ContainerID != "" {
			if got := MeasureNetnsEgress(ctx, runner, route.Runtime, route.ContainerID); got.IP != "" {
				ip := got.IP
				report.ContainerEgressIP = &ip
			}
		}
		// THE GENERAL "IT DIDN'T ACTUALLY ROUTE" SIGNAL. dialer.py's own
		// comment ("NEVER host_egress_ip... a host whose address moved is
		// a failed apply that reverts") and this file's Describe() text
		// both already say this is the failure state; nothing compared
		// the two fields until now. Independent of ExpectEgress, so it
		// catches every route that silently fell through to the main
		// table -- a peer added to the tunnel but never to the far end's
		// forwarding rules -- same failure shape as the mismatch check
		// below but without needing an expectation to have been given.
		if w := hostEgressMatchesContainer(report.HostEgressIP, report.ContainerEgressIP); w != "" {
			report.Warnings = appendWarning(report.Warnings, w)
		}
		// THE MISMATCH THAT CAUGHT THE GATE, complementary to the general
		// check above, not a replacement for it: this one only fires when
		// an expectation WAS given (the mesh exit-gate flow), and is a
		// stronger, exact-match check for that narrower case.
		if w := expectedEgressMismatch(route, report.ContainerEgressIP); w != "" {
			report.Warnings = appendWarning(report.Warnings, w)
		}
	}

	// --- `since`, and it is gated on the TUNNEL being up ---
	//
	// A timestamp is the most quietly convincing thing on a status screen:
	// "connected since 14:02" reads as proof, and a reader will believe it
	// over the word next to it. So it is emitted only when this call has just
	// measured the tunnel as present.
	//
	// In particular a leftover POLICY RULE does not earn one. That state is
	// real — the rule outliving its interface is exactly what a dead-man that
	// removed the tunnel leaves behind — but there is no connection for the
	// date to be the start of, and "connected since 14:02" next to a tunnel
	// that is gone is the precise lie this verb exists to stop. The leftover
	// is reported through rule_installed and the warning in Describe instead.
	//
	// The second branch is not redundant: a host can be ROUTED onto a tunnel
	// it did not dial (aw-vpn-hub's, say), so there is no tunnel record to
	// date it from and the route's own timestamp is the honest answer.
	if report.Up {
		switch {
		case tunnel != nil && tunnel.DialedAt != "":
			since := tunnel.DialedAt
			report.Since = &since
		case report.RuleInstalled && route != nil && route.RoutedAt != "":
			since := route.RoutedAt
			report.Since = &since
		}
	}

	return report, nil
}

// measuredDNSTunneled asks the machine whether the resolver is STILL moved,
// rather than whether an apply once moved it.
//
// Both halves have to hold, because either one missing reopens the leak in a
// different way: without the aardvark upstream the queries go back out through
// the host, and without the policy rules they take the main table's own path
// to the resolver — in the clear. The second is the quieter of the two and the
// reason this is not a single check: a flushed rule leaves an upstream that
// still LOOKS right in the config file while every query on the network goes
// out unprotected.
//
// EVERY rule has to be there, tcp included. A host where only the udp rule
// survived is leaking exactly the responses that were too big for udp, which
// is a partial leak reported as a full guarantee.
//
// Deliberately cheap: two reads, no probe container, no round trip. This verb
// is polled by a screen, and the end-to-end resolution check belongs to the
// apply (§4.5), not to a poll that would run it every few seconds.
func measuredDNSTunneled(ctx context.Context, r Runner, route *state.ExternalRouteState) bool {
	if route == nil || len(route.DNSServers) == 0 || route.DNSNetwork == "" {
		return false
	}
	upstreams := aardvarkUpstreams(ctx, r, route.DNSNetwork)
	for _, dns := range route.DNSServers {
		if !containsAddress(upstreams, dns) {
			return false
		}
	}
	// Spelled through a plan so the rule vocabulary — the selector, the table
	// and the priority band — lives in exactly one place (dnsRulesFor) and a
	// poll cannot drift from what the apply installed.
	plan := ExternalRoutePlan{
		Table:       route.Table,
		DNSServers:  route.DNSServers,
		DNSNetwork:  route.DNSNetwork,
		DNSPriority: route.DNSPriority,
	}
	for _, ru := range plan.dnsRules() {
		if ok, err := dnsRuleInstalled(ctx, r, plan, ru); err != nil || !ok {
			return false
		}
	}
	return true
}

// expectedEgressMismatch reports the warning to append, or "" when there is
// nothing to say: no route recorded, no expectation given for it (ExpectEgress
// is optional — see ExternalRouteSpec), or no container measurement to compare
// against yet (SkipEgress, or the probe failed). Kept pure and separate from
// ExternalStatus's own body so the decision is testable without a runner, a
// probe container, or a network round trip — the same reason ScopeRefusal and
// externalRouteShadowRefusal (usexit.go) are pulled out the same way.
func expectedEgressMismatch(route *state.ExternalRouteState, containerEgressIP *string) string {
	if route == nil || route.ExpectEgress == "" || containerEgressIP == nil || *containerEgressIP == route.ExpectEgress {
		return ""
	}
	return egressMismatchWarning(route.ExpectEgress, *containerEgressIP)
}

// hostEgressMatchesContainer reports the warning to append when the
// container's measured egress is IDENTICAL to this host's own — the general
// "route silently failed" signal, independent of whether an ExpectEgress was
// ever given. "" when either side is unmeasured (SkipEgress, or a probe that
// failed), so a poll with a hole in it stays silent rather than manufacturing
// a false positive out of nothing to compare. Kept pure and separate from
// ExternalStatus's own body for the same reason expectedEgressMismatch is.
func hostEgressMatchesContainer(hostEgressIP, containerEgressIP *string) string {
	if hostEgressIP == nil || containerEgressIP == nil || *hostEgressIP != *containerEgressIP {
		return ""
	}
	return containerEgressUnroutedWarning(*hostEgressIP)
}

// interfacePresent asks wg which interfaces exist. A host with no `wg` at all
// answers false rather than erroring: this verb is polled by a screen, and a
// host that cannot run WireGuard genuinely has no tunnel up.
func interfacePresent(ctx context.Context, r Runner, iface string) bool {
	if iface == "" {
		return false
	}
	out, err := r.Run(ctx, "wg", "show", "interfaces")
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(out) {
		if f == iface {
			return true
		}
	}
	return false
}

// Describe renders the report for a human reading a terminal. The JSON is what
// the workspace parses; this is what an operator reads, and it leads with the
// disagreement between record and machine because that is the state worth
// noticing.
func (r ExternalStatusReport) Describe() []string {
	var out []string
	out = append(out, "interface "+r.Iface+": "+upWord(r.Up)+", table "+strconv.Itoa(r.Table))
	if r.Container != nil {
		out = append(out, "container "+*r.Container+": policy rule "+installedWord(r.RuleInstalled))
	} else {
		out = append(out, "no container is recorded as routed through this tunnel")
	}
	if r.RuleInstalled && !r.Up {
		out = append(out, "WARNING — a policy rule is in force and the tunnel interface is GONE. That is what the dead-man's switch leaves behind when it fires, or what a flush leaves behind. Run `aw-remote-host vpn external-down` to tidy up.")
	}
	if r.HostEgressIP != nil {
		out = append(out, "host egress: "+*r.HostEgressIP+" (this must NOT be the tunnel's address)")
	}
	if r.ContainerEgressIP != nil {
		out = append(out, "container egress: "+*r.ContainerEgressIP)
	}
	if r.DeadmanArmed {
		expires := "unknown"
		if r.DeadmanExpiresAt != nil {
			expires = *r.DeadmanExpiresAt
		}
		out = append(out, "a dead-man's switch is ARMED and fires at "+expires+" unless something stands it down")
	}
	if r.Since != nil {
		out = append(out, "in force since "+*r.Since)
	}
	if r.Up || r.RuleInstalled {
		out = append(out, "kill switch: "+killSwitchWord(r.KillSwitch))
		out = append(out, "DNS: "+dnsWord(r.DNSTunneled))
	}
	// The warnings are the sentences a person is meant to read, so they are
	// printed verbatim rather than summarised into a word.
	for _, w := range r.Warnings {
		out = append(out, "WARNING — "+w)
	}
	return out
}

func upWord(up bool) string {
	if up {
		return "UP"
	}
	return "not present"
}

func installedWord(in bool) string {
	if in {
		return "INSTALLED"
	}
	return "NOT installed"
}

// dnsWord says which of the two states this is in one line. The false case
// deliberately does not repeat DNSNotTunnelledWarning — that sentence is
// printed verbatim by the warnings loop just below, and saying it twice is how
// a reader learns to skip both.
func dnsWord(ok bool) string {
	if ok {
		return "the container resolver's own upstream is inside the tunnel, so name lookups do not leave through this host"
	}
	return "NOT fully tunnelled"
}

func killSwitchWord(ok bool) string {
	if ok {
		return "the control plane is pinned outside the tunnel, so Disconnect stays reachable"
	}
	return "MISSING"
}
