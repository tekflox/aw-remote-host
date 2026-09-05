// What this connection can and cannot PROMISE the person who switched it on —
// and the sentences that say so when it cannot.
//
// WHY THIS EXISTS AS A TYPE OF ITS OWN. Two guarantees a user reasonably
// assumes a VPN gives them are, on this deployment, conditional:
//
//	the kill switch  — the control plane is held OUTSIDE the tunnel, so
//	                   Disconnect still reaches the workspace when the tunnel
//	                   degrades. It exists only if the control plane's address
//	                   could be resolved at the moment the route was applied.
//	tunnelled DNS    — only queries the container sends DIRECTLY to an external
//	                   resolver use the tunnel; the ones it sends to the local
//	                   container resolver are forwarded from a different source
//	                   address and still leave via this host.
//
// Either can be absent while everything else looks perfectly healthy, and
// THAT is the failure this file is here to prevent: an apply with no kill
// switch used to be byte-for-byte indistinguishable from an apply with one.
// Layer 1 (planExternalExclusions, 2026-09-05) made that possible by design —
// it removed the nameserver pins, so the exclusion list is no longer kept
// non-empty by accident, and a control plane that failed to resolve now
// produces zero exclusions and says nothing.
//
// The DECISION, taken by the architect and recorded here so it is not
// re-litigated: warn loudly, do NOT refuse. Refusing would turn a transient
// DNS blip on the control-plane hostname into "the VPN cannot be switched
// on", and that resolution happens at apply time — exactly when the network
// is most likely to be in flux. The runner-up was to refuse; what would
// change the decision is evidence this fails in practice rather than in
// theory.
//
// The strings below are rendered VERBATIM to a person. They are complete
// sentences that name the consequence and the way out, not codes for a UI to
// translate — a warning nobody can act on is a warning everybody learns to
// scroll past.
package vpn

// KillSwitchMissingWarning is shown whenever the control plane could not be
// pinned outside the tunnel.
//
// It has to answer three things in the order a worried person asks them: what
// is not protected, what could go wrong because of it, and what to do. The
// recovery is deliberately a host-side command, because the whole point of
// this warning is that the on-screen Disconnect is the thing that might not
// work.
const KillSwitchMissingWarning = "This connection has NO KILL SWITCH: the control plane's address could not be resolved when the connection was made, so it has not been held outside the tunnel. If the tunnel degrades while it is up, the Disconnect button may not be able to reach the workspace, and the VPN could not be switched off from this screen. To recover from the host itself, run `aw-remote-host vpn external-unroute` and then `aw-remote-host vpn external-down`. Disconnecting and reconnecting once name resolution is working again will pin it properly."

// DNSNotTunnelledWarning is shown whenever DNS is only partly tunnelled,
// which on this deployment is always — see ExternalStatusReport.DNSTunneled
// and planExternalExclusions for why, and the card for what closing it needs.
const DNSNotTunnelledWarning = "DNS IS NOT FULLY TUNNELLED. Traffic goes through the VPN, but names looked up through this machine's local container resolver are still resolved outside it, so DNS queries can still reveal which sites are being visited. Only lookups sent directly to an external resolver travel inside the tunnel."

// ExternalGuarantees is the honest summary carried by every surface that
// reports on an external tunnel — the two apply verbs and the live status —
// so a caller reads the same three fields whichever one it reached.
//
// Warnings is never nil once it has been through newExternalGuarantees: the
// contract these fields ship under says `[]` when there is nothing to say,
// never null, because a caller that has to handle both is a caller that will
// handle one of them wrong.
type ExternalGuarantees struct {
	// DNSTunneled is false on this deployment. It is a field rather than a
	// constant so that the day aardvark's upstream can be moved, exactly one
	// place changes and every surface follows.
	DNSTunneled bool `json:"dns_tunneled"`
	// KillSwitch is true IFF the control plane was pinned outside the tunnel.
	KillSwitch bool `json:"kill_switch"`
	// Warnings are complete sentences, rendered verbatim to a person.
	Warnings []string `json:"warnings"`
}

// newExternalGuarantees builds the summary and its sentences together, so a
// state can never be reported without the sentence that explains it. That
// pairing is the entire point: the bug being fixed is a false `kill_switch`
// that nothing narrated.
//
// inForce says whether anything is actually applied. On a host with no tunnel
// and no route there is nothing to warn ABOUT, and warning anyway would put a
// permanent scare on an idle screen — which is how a user learns that these
// sentences are noise, and then misses the one that matters.
func newExternalGuarantees(inForce, killSwitch bool) ExternalGuarantees {
	g := ExternalGuarantees{
		DNSTunneled: false,
		KillSwitch:  killSwitch,
		Warnings:    []string{},
	}
	if !inForce {
		return g
	}
	if !g.KillSwitch {
		g.Warnings = append(g.Warnings, KillSwitchMissingWarning)
	}
	if !g.DNSTunneled {
		g.Warnings = append(g.Warnings, DNSNotTunnelledWarning)
	}
	return g
}

// appendWarning adds one sentence to a warnings list, skipping the empty
// string so callers do not each have to guard.
//
// It exists because the teardown's warning is produced by a function that
// usually has nothing to say ("" is the normal return of revertExternalUp),
// and every call site would otherwise repeat the same `if warning != ""`. One
// of them eventually would not — the sibling defect on this card was exactly
// one branch missing a call the others made.
func appendWarning(warnings []string, warning string) []string {
	if warning == "" {
		return warnings
	}
	return append(OrEmptyStrings(warnings), warning)
}

// OrEmptyStrings keeps a nil slice marshalling as `[]` rather than `null`.
//
// Needed because a plan rebuilt from state.json (loadExternalRouteState) has
// never been through newExternalGuarantees — it carries whatever was
// persisted, and Warnings is not persisted at all. Every payload builder runs
// its slices through this so the wire shape is the same whichever path the
// value took to get there.
func OrEmptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
