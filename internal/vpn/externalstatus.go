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

	// DNSTunneled is ADDITIVE — not part of the shape core was built against,
	// and a caller that ignores it loses nothing.
	//
	// It exists because the honest answer to "is my DNS going through the VPN"
	// is currently "partly", and a screen with no way to say that will imply
	// "yes". The resolvers are no longer pinned outside the tunnel
	// (planExternalExclusions), so a query the container addresses DIRECTLY to
	// an external resolver now goes through it — but on this deployment glibc
	// sends essentially everything to the local aardvark first, and from that
	// hop on the packet no longer carries the container's source address, so
	// no source-anchored rule can reach it. Until aardvark's own upstream can
	// be moved (podman 4.3.1 cannot express it and a POSIX-sh dead-man cannot
	// revert it) this is false whenever a route is in force, and saying so is
	// the point.
	DNSTunneled bool `json:"dns_tunneled"`
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

	// A route in force means the container's egress is supposed to have
	// moved. DNS is only as tunnelled as that rule makes it — see
	// DNSTunneled's own comment for why "partly" is the honest answer.
	report.DNSTunneled = false

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
			if got := measureNetnsEgress(ctx, runner, route.Runtime, route.ContainerID); got.IP != "" {
				ip := got.IP
				report.ContainerEgressIP = &ip
			}
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
		out = append(out, "DNS through the tunnel: "+dnsWord(r.DNSTunneled)+" — queries this container sends DIRECTLY to an external resolver go through the tunnel, but the ones it sends to the local container resolver are forwarded from a different source address and still leave via this host.")
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

func dnsWord(full bool) string {
	if full {
		return "fully tunnelled"
	}
	return "PARTLY — not fully tunnelled"
}
