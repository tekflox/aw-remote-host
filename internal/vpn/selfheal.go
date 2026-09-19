// Background self-heal for the external tunnel — the half `external_route`
// already had and this one did not.
//
// WHAT THIS FIXES. `external_route` has had a continuous self-heal loop since
// the day systemd-networkd was caught flushing its policy rule (Reassert /
// ReassertLoop, externalroute.go). `external_tunnel` — the mechanism actually
// carrying traffic — had nothing equivalent: the handshake was confirmed once,
// at dial time, from a CLI somebody was watching, and never again. A tunnel
// that died quietly at 03:00 stayed dead until a human noticed, which is
// exactly the symptom that opened this card. A one-shot confirmation is not a
// guarantee; it is a snapshot.
//
// ONE LOOP, TUNNEL FIRST. Both passes write to `ip` and to table 200, so they
// run in one goroutine in a fixed order instead of two goroutines behind a
// mutex: if the tunnel came back on a NEW wg0, the route has to be re-asserted
// AFTER it, not concurrently with it. A mutex would make that ordering
// implicit, and the first refactor would lose it.
//
// IT REPAIRS, IT DOES NOT MERELY OBSERVE. Logging alone reproduces the
// incident — nobody reads stderr overnight, and the watchdog on the workspace
// side that would have read it does not run in production at all (aw-backend
// is AW_ROLE=replica, so vpn_poller's leader-lease callback never fires).
//
// THE REPAIR IS `applyExternalUp` DIRECTLY, never `ExternalUp`. ExternalUp
// arms the dead-man's switch, measures this host's public IP and pre-pulls a
// probe image — every one of which needs the internet, on a host whose whole
// problem is that it has none. applyExternalUp works from the 0600 config
// already on disk at plan.ConfPath, so it needs neither the profile nor the
// control plane. That is what makes an offline re-dial possible at all.
package vpn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/instance"
)

// SelfHealInterval is how often one pass runs. Deliberately ReassertInterval:
// the tunnel check is three local reads (`wg show interfaces`, `wg show <if>
// peers`/`latest-handshakes`, `ip route show table N`) with no network round
// trip and no probe container — the same class of cost ReassertInterval's own
// comment justifies, and the two passes share this one ticker anyway.
const SelfHealInterval = ReassertInterval

// HandshakeStaleAfter is the age past which a peer is presumed gone.
//
// PlanExternalUp REFUSES a profile with persistent_keepalive: 0
// (KeepaliveZeroRefusal), so every tunnel this loop can ever see has a
// keepalive configured, and WireGuard renegotiates roughly every 120s. A live
// peer therefore cannot reach 180s. Anything shorter turns an idle-but-healthy
// tunnel into a false positive.
//
// What would change this: measuring, on the bare metal, a healthy idle GL.iNet
// peer routinely exceeding 180s between handshakes. Then the threshold rises,
// or the check moves to the rx/tx counters instead. One hour of `wg show wg0
// latest-handshakes` on the host falsifies it either way.
const HandshakeStaleAfter = 180 * time.Second

// A stale handshake has to be seen this many passes running before anything is
// torn down. The other symptoms do not: a missing device, a missing peer or a
// missing default are unambiguous and get repaired on the first pass, the same
// rule Reassert applies to a flushed rule. Staleness is the one measurement
// that can be a transient, and re-dialling costs every connection in flight.
const staleRepairsAfterPasses = 2

// Backoff after a repair. The tunnel's peer may be genuinely dead, or the
// host's own uplink may be down — and `wg-quick up` returns 0 with an
// unreachable peer, so a loop with no backoff would destroy and rebuild the
// routing table every 30s, forever, while achieving nothing. It doubles to a
// ceiling and is cleared outright the moment a fresh handshake is measured.
const (
	healBackoffMin = 5 * time.Minute
	healBackoffMax = 30 * time.Minute
)

// confPresent is os.Stat on the synthesized config, indirected so healTunnelPlan
// stays testable without writing to /etc/wireguard on the machine running
// `go test` — the same reason lookupExternalBinary is a var.
var confPresent = func(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// healVerdict is what one measurement pass concluded.
type healVerdict int

const (
	// healHealthy: the device, the peer and the default are all in place and
	// the handshake is fresh. Clears the backoff and the stale counter.
	healHealthy healVerdict = iota
	// healUnknown: a shellout was REFUSED or answered something this code
	// cannot read. Never a repair, and never reported as "down". A `sudo -n
	// wg` that is refused says nothing whatsoever about the peer, and acting
	// on it would tear down healthy tunnels on every host where the daemon
	// happens to lose its privilege.
	healUnknown
	// healStale: everything is installed but the peer has not handshaked
	// inside HandshakeStaleAfter (or ever). Repaired only after
	// staleRepairsAfterPasses consecutive passes.
	healStale
	// healBroken: the device, the peer or the default is missing. Repaired on
	// the first pass.
	healBroken
	// healConfGone: state.json records a tunnel and plan.ConfPath is not on
	// disk. removeExternalConf only runs in the teardown, alongside
	// clearExternalTunnelState, so a record without its config is a real
	// anomaly and not a state this loop can undo — wg-quick has nothing to be
	// pointed at. Reported loudly, never repaired, so it cannot become a
	// failure loop. The same shape as reassertPlan's `gone` branch.
	healConfGone
)

// healAssessment is one pass's measurement, kept separate from the decision to
// act on it so both are testable on their own.
type healAssessment struct {
	verdict healVerdict
	// reason is a complete sentence naming what was measured. Rendered to a
	// person and written to the self-heal log.
	reason string
	// handshakeAge is meaningful for healHealthy and for healStale that is not
	// handshakeNever.
	handshakeAge   time.Duration
	handshakeNever bool
}

// healTunnelPlan measures one tunnel and says what should happen to it.
//
// It ONLY talks to Runner (and confPresent) — no state file, no clock of its
// own, no writes. That is what lets every fixture below be a table of command
// output, the same seam reassertPlan is tested through.
//
// The order is load-bearing. The config is checked before anything is asked of
// wg, because a missing config makes every repair impossible and the answer
// would otherwise be "broken, repair" on a plan that cannot be applied. The
// device is checked before the peer, because `wg show <iface> peers` fails on
// an interface that does not exist — asking in the other order would read a
// missing device as a refused shellout and skip the pass forever.
func healTunnelPlan(ctx context.Context, r Runner, plan ExternalUpPlan, now time.Time) healAssessment {
	if !confPresent(plan.ConfPath) {
		return healAssessment{
			verdict: healConfGone,
			reason: fmt.Sprintf("state.json records a tunnel on %s but its config %s is not on disk, so it cannot be re-dialled from this host. Nothing removes that file except `vpn external-down`, which clears the record at the same time — a record without its config means something deleted it out from under the daemon. Run `aw-remote-host vpn external-down` to clear the stale record, then dial again from the workspace",
				plan.Iface, plan.ConfPath),
		}
	}

	devicePresent, err := tunnelDeviceState(ctx, r, plan)
	if err != nil {
		return healAssessment{verdict: healUnknown, reason: err.Error()}
	}
	if !devicePresent {
		return healAssessment{
			verdict: healBroken,
			reason:  fmt.Sprintf("interface %s is not present — the tunnel device is gone", plan.Iface),
		}
	}

	peerPresent, err := tunnelPeerState(ctx, r, plan)
	if err != nil {
		return healAssessment{verdict: healUnknown, reason: err.Error()}
	}
	if !peerPresent {
		return healAssessment{
			verdict: healBroken,
			reason:  fmt.Sprintf("interface %s exists but does not carry the configured peer %s — it belongs to a different profile", plan.Iface, shortFingerprint(plan.PeerPublicKey)),
		}
	}

	hasDefault, err := defaultInTable(ctx, r, plan)
	if err != nil {
		return healAssessment{verdict: healUnknown, reason: err.Error()}
	}
	if !hasDefault {
		return healAssessment{
			verdict: healBroken,
			reason:  fmt.Sprintf("table %d does not carry a default route out of %s — the routing this tunnel exists for is not in force", plan.Table, plan.Iface),
		}
	}

	handshakeAt, err := latestHandshake(ctx, r, plan)
	if err != nil {
		return healAssessment{verdict: healUnknown, reason: err.Error()}
	}
	if handshakeAt == 0 {
		// "Never" is treated as stale rather than broken on purpose. The
		// device, the peer and the default are all in place, which is what a
		// tunnel dialled seconds ago by an interactive `vpn external-up` looks
		// like before its first handshake lands. Repairing that on the first
		// pass would have this loop fighting a human at the console.
		return healAssessment{
			verdict:        healStale,
			handshakeNever: true,
			reason:         fmt.Sprintf("the peer on %s has never completed a handshake, so the interface exists but the tunnel carries nothing", plan.Iface),
		}
	}

	age := now.Sub(time.Unix(handshakeAt, 0))
	if age < 0 {
		// A clock that moved backwards is not evidence of a stale peer.
		age = 0
	}
	if age > HandshakeStaleAfter {
		return healAssessment{
			verdict:      healStale,
			handshakeAge: age,
			reason: fmt.Sprintf("the peer on %s last handshaked %s ago, past the %s a keepalive-configured peer can go quiet for",
				plan.Iface, age.Round(time.Second), HandshakeStaleAfter),
		}
	}
	return healAssessment{
		verdict:      healHealthy,
		handshakeAge: age,
		reason:       fmt.Sprintf("the peer on %s handshaked %s ago", plan.Iface, age.Round(time.Second)),
	}
}

// tunnelHealer carries the hysteresis and the backoff between passes.
//
// It is a struct rather than closure state so the decision it makes is
// testable across a SEQUENCE of passes without running a real ticker — which
// is the only way to prove "one stale pass does not repair, two do" and "a
// repair is not retried inside the backoff".
type tunnelHealer struct {
	consecutiveStale int
	backoff          time.Duration
	// nextRepairAt is the zero time when no repair has been attempted yet.
	nextRepairAt time.Time
}

// healDecision is what the healer decided to do about one assessment.
type healDecision struct {
	repair bool
	// note is what to report, empty when there is nothing worth saying. A
	// healthy pass says nothing — this runs every 30s forever, and a loop that
	// narrates its own health teaches everyone to filter it out, taking the
	// one line that mattered with it.
	note string
}

// decide turns an assessment into an action, applying hysteresis and backoff.
func (h *tunnelHealer) decide(a healAssessment, now time.Time) healDecision {
	switch a.verdict {
	case healHealthy:
		// A fresh handshake is the only thing that clears the backoff. Not a
		// successful `wg-quick up` — that returns 0 with an unreachable peer,
		// which is precisely the failure the backoff exists to survive.
		h.consecutiveStale = 0
		h.backoff = 0
		h.nextRepairAt = time.Time{}
		return healDecision{}

	case healUnknown:
		// Deliberately leaves consecutiveStale alone rather than resetting it:
		// a pass that could not measure is not evidence the peer recovered,
		// and zeroing here would let an intermittently-refused `wg` postpone a
		// real repair indefinitely.
		return healDecision{note: "self-heal skipped this pass — " + a.reason}

	case healConfGone:
		h.consecutiveStale = 0
		return healDecision{note: "ANOMALY, and this loop cannot fix it: " + a.reason}

	case healStale:
		h.consecutiveStale++
		if h.consecutiveStale < staleRepairsAfterPasses {
			return healDecision{note: fmt.Sprintf("%s. Waiting one more pass before re-dialling — a single stale reading is not enough to justify dropping every connection on this tunnel", a.reason)}
		}
	case healBroken:
		h.consecutiveStale = 0
	}

	// healStale (having reached the threshold) and healBroken both land here.
	if !h.nextRepairAt.IsZero() && now.Before(h.nextRepairAt) {
		return healDecision{note: fmt.Sprintf("%s. NOT re-dialling yet: a repair was already attempted and the next is not due until %s — the peer or this host's uplink may be genuinely down, and re-dialling every %s would rebuild the routing table forever without fixing anything",
			a.reason, h.nextRepairAt.UTC().Format(time.RFC3339), SelfHealInterval)}
	}
	return healDecision{repair: true, note: a.reason}
}

// repaired records that a repair was attempted, moving the backoff on. Called
// whether the repair succeeded or failed, because `wg-quick up` succeeding
// proves nothing about the peer.
func (h *tunnelHealer) repaired(now time.Time) {
	h.consecutiveStale = 0
	switch {
	case h.backoff == 0:
		h.backoff = healBackoffMin
	default:
		h.backoff *= 2
		if h.backoff > healBackoffMax {
			h.backoff = healBackoffMax
		}
	}
	h.nextRepairAt = now.Add(h.backoff)
}

// healTunnelPass is one whole tunnel pass: read the record, decide, repair.
//
// It returns what it restored and any error, in the same shape Reassert uses,
// so SelfHealLoop can hand both passes to one report callback.
func (h *tunnelHealer) pass(ctx context.Context, r Runner, now time.Time) ([]string, error) {
	plan, err := loadExternalTunnelPlan()
	if err != nil {
		return nil, fmt.Errorf("the recorded external tunnel could not be read: %w", err)
	}
	if plan == nil {
		// NO TUNNEL RECORDED. Silent, and the overwhelmingly common case: every
		// host that has never dialled, and every non-Linux host, which cannot
		// dial at all. A loop that narrated this would print a line every 30s
		// on every machine in the fleet.
		return nil, nil
	}

	// A DEAD-MAN'S SWITCH THAT IS ARMED MEANS A DIAL IS IN FLIGHT, and the
	// whole pass is skipped. Two reasons, and either one is sufficient. The
	// measurement is meaningless: mid-dial the routing is half-applied by
	// design, so every predicate here would read "broken". And the repair
	// would be actively destructive: applyExternalUp under a live dial races
	// the dial itself, and the interactive path's guard is armed against a
	// tunnel state this loop would be busy changing underneath it.
	//
	// Fired() and not merely non-nil: a switch whose process is gone has
	// already reverted, and honouring that record would park this loop
	// permanently on a host that most needs it.
	if d, derr := LoadDeadman(); derr == nil && d != nil && !d.Fired() {
		return nil, nil
	}

	assessment := healTunnelPlan(ctx, r, *plan, now)
	decision := h.decide(assessment, now)
	if !decision.repair {
		if decision.note != "" {
			logSelfHeal(decision.note)
		}
		return nil, nil
	}

	logSelfHeal("re-dialling " + plan.Iface + " from its recorded config: " + decision.note)
	h.repaired(now)
	if err := applyExternalUp(ctx, r, *plan); err != nil {
		werr := fmt.Errorf("%s. Re-dialling it from %s FAILED: %w", decision.note, plan.ConfPath, err)
		logSelfHeal(werr.Error())
		return nil, werr
	}
	// Deliberately NOT called "confirmed". applyExternalUp returning nil means
	// the config was applied and the table rebuilt, not that the peer answered
	// — confirmation is a later pass measuring a fresh handshake, which is
	// also the only thing that clears the backoff.
	restored := fmt.Sprintf("external tunnel %s re-dialled from %s (%s) — the peer has not answered yet; a later pass reports whether it does", plan.Iface, plan.ConfPath, decision.note)
	logSelfHeal(restored)
	return []string{restored}, nil
}

// SelfHealLoop keeps this host's external tunnel AND its external route in
// force until ctx is cancelled, reporting whatever it had to put back.
//
// It replaces ReassertLoop, which only ever covered the route half. One
// goroutine, one ticker, tunnel first — see the file header for why the order
// is not an implementation detail.
//
// One pass runs immediately: a host coming back from a reboot has neither the
// interface nor the rule and a state file that records both, and waiting a
// full interval to notice would be a gap for no reason. Errors are reported
// and never fatal, the same bargain firewall.SelfHeal makes at the same point
// in startup — a self-heal that could not run must not stop this process from
// linking at all.
func SelfHealLoop(ctx context.Context, r Runner, report func(restored []string, err error)) {
	healer := &tunnelHealer{}
	emit := func(restored []string, err error) {
		if report != nil && (len(restored) > 0 || err != nil) {
			report(restored, err)
		}
	}
	pass := func() {
		// TUNNEL FIRST. If the tunnel came back on a new device, the route has
		// to be re-asserted after it, not before.
		emit(healer.pass(ctx, r, time.Now()))
		emit(Reassert(ctx, r))
	}
	pass()
	ticker := time.NewTicker(SelfHealInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass()
		}
	}
}

// SelfHealLogPath returns ~/.aw-remote-host/vpn-selfheal.log.
//
// THE EVIDENCE HAS TO OUTLIVE THE CONTAINER, which is the lesson the incident
// behind this card taught the hard way: the daemon's stdout and stderr are the
// container's, and both were gone by the time anyone looked — vpn-deadman.log
// and restart.log were the only durable record of that night, and neither had
// anything to say. A self-heal whose only trace dies with the process it runs
// in recreates that exact hole.
// PER-MACHINE, like the dead-man switch it is the twin of: the tunnel and
// the routing policy it reasserts belong to the host, not to an identity.
func SelfHealLogPath() (string, error) {
	dir, err := instance.MachineDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vpn-selfheal.log"), nil
}

// logSelfHeal appends one timestamped line, best effort. A logging failure is
// never allowed to stop or fail a heal: this file is for the human reading it
// afterwards, and the tunnel matters more than the note about the tunnel.
func logSelfHeal(line string) {
	path, err := SelfHealLogPath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), strings.ReplaceAll(line, "\n", " "))
}
