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

// egressMismatchWarning is shown when the container's measured egress is not
// the address this route was told to expect. It says what it looks like
// rather than merely what it is, because the actual observed cause (a mesh
// exit gate picked after this VPN connected) is what PlanUseExit's own shadow
// refusal (usexit.go) now prevents going forward — this is the same theft,
// reported from the VPN screen's side, for anything that shadowed the rule
// before that refusal existed to stop it.
func egressMismatchWarning(expected, got string) string {
	return "Container egress is " + got + ", not the expected " + expected +
		". Something else is routing this container's traffic — most likely a mesh exit gate (Settings -> Networking) picked after this VPN connected, which silently takes priority over this rule. Clear whichever was picked last, or run `aw-remote-host vpn external-unroute` and reconnect."
}

// containerEgressUnroutedWarning is shown when the container's measured
// egress is the SAME as this host's own — the general shape of "the route
// silently failed", independent of whether anything predicted the exact
// expected IP in advance (that is expectedEgressMismatch's narrower job).
// The tunnel and its policy rule can both report healthy while this is true:
// the packet leaves the container correctly, but whatever should have NAT'd
// or forwarded it on the far end (a hub-side policy rule that was never
// installed for this peer, an exit peer with no NAT of its own, a rule a
// daily flush took away) did not, so it falls back to this host's own
// address. Named for what it looks like, not for the one cause already seen
// in production — the same design as egressMismatchWarning above.
func containerEgressUnroutedWarning(ip string) string {
	return "Container egress is " + ip + ", the SAME as this host's own public IP. The tunnel may report up and the policy rule installed, but nothing is actually forwarding this container's traffic through it — most likely a routing rule the far end (a peer or hub) needs for this connection was never installed or was flushed. Disconnect and reconnect; if it recurs, check the routing on the far end of the tunnel."
}

// DNSNotTunnelledWarning is shown whenever DNS is only partly tunnelled.
//
// It used to be unconditional, because on this deployment it was always true.
// It is now the honest answer for every path where the proof in
// planTunnelDNS/applyTunnelDNS FAILS — a profile that carries no resolver, a
// runtime that is not podman, a `podman network update` that did not take, a
// name that would not resolve afterwards. It is deliberately NOT deleted: a
// warning that only ever appeared is easy to mistake for a placeholder, but
// the state it describes is still reachable and still the one a user most
// needs told.
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
	// DNSTunneled is true only when the local container resolver's OWN
	// upstream has been moved onto the profile's resolver and every step of
	// that was proven — see §4 of the design and applyTunnelDNS, which
	// refuses to set it rather than claim it. It was a constant `false` until
	// podman 5 made the upstream movable; this comment used to promise that
	// "the day aardvark's upstream can be moved, exactly one place changes
	// and every surface follows", and that day is what this field now carries.
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
// dnsTunneled is passed in rather than assumed, for the same reason
// killSwitch is: it is a MEASUREMENT, made by whoever is in a position to make
// it, and a default here would be this file quietly deciding an answer it
// cannot see. Every caller that cannot prove it passes false, which is the
// state DNSNotTunnelledWarning describes.
func newExternalGuarantees(inForce, killSwitch, dnsTunneled bool) ExternalGuarantees {
	g := ExternalGuarantees{
		DNSTunneled: dnsTunneled,
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
