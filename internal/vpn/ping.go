package vpn

import (
	"context"
	"regexp"
	"strings"
	"sync"
)

// This file exists because `tailscale status` cannot answer the question the
// Networking screen is for.
//
// Status carries CurAddr and Relay per peer, but CurAddr is only populated
// while a peer is ACTIVE. An idle peer reports an empty CurAddr and the DERP
// region it merely WOULD use, so ParseStatus reads it as relayed whether or
// not a direct path would come up the moment traffic started. Measured
// 2026-08-25 on the production bare-metal: every peer was idle, so status
// alone would have reported all three as relayed — including aw-baremetal
// <-> aw-mac, which is direct.
//
// `tailscale ping` is what actually establishes the path and then says what
// it is. That is the whole reason this is a second shellout rather than one
// more field parsed out of the status JSON.

// PingTimeout is the per-peer budget handed to `tailscale ping`. Kept short:
// this runs once per online peer on every read of the Networking screen, and
// a peer that cannot answer in five seconds is not going to be usefully
// described by waiting longer.
const PingTimeout = "5s"

// Ping is one measured path to a peer.
type Ping struct {
	// Path is what was measured. PathNone means nothing was — see Reason.
	Path PathKind
	// Relay is the DERP region code (e.g. "mad") when Path is PathRelay.
	Relay string
	// DirectAddr is the peer-to-peer endpoint (e.g. "65.109.66.88:41641")
	// when Path is PathDirect.
	DirectAddr string
	// Latency is tailscale's own rendering of the round trip ("217ms"), kept
	// exactly as printed rather than parsed into a number: it is displayed,
	// never computed with, so re-formatting it would only add a way to be
	// wrong about a value we did not measure ourselves.
	Latency string
	// Local is true when the target is this node's own mesh IP. Not an error
	// and not a path — a node does not relay to itself.
	Local bool
	// Reason carries the line that explained a PathNone, verbatim (e.g.
	// "no matching peer"), so nothing downstream has to invent one.
	Reason string
}

// Via renders the path the way the Networking screen shows it: "DERP(mad)"
// for a relayed path, the endpoint for a direct one, "" when nothing was
// measured.
func (p Ping) Via() string {
	switch p.Path {
	case PathDirect:
		return p.DirectAddr
	case PathRelay:
		return "DERP(" + p.Relay + ")"
	}
	return ""
}

// pongRe matches tailscale's pong line. Both forms below are real output
// captured 2026-08-25, not invented shapes:
//
//	pong from aw-baremetal (100.64.0.1) via 65.109.66.88:41641 in 74ms
//	pong from aw-mac (100.64.0.3) via DERP(mad) in 217ms
var pongRe = regexp.MustCompile(`pong from (\S+) \(([^)]+)\) via (\S+) in (\S+)`)

// derpRe tells the two `via` forms apart. A DERP region is the relay case; an
// ip:port is the direct one.
var derpRe = regexp.MustCompile(`^DERP\(([^)]*)\)$`)

// ParsePing turns one `tailscale ping` run into a Ping.
//
// The output it is given is stdout AND stderr combined, because that is what
// ops.Runner produces — and it matters here: a relayed pong prints the pong
// on stdout and "direct connection not established" on stderr, so a parser
// reading either stream alone would see half the story. The first pong line
// wins for exactly that reason; the complaint after it is not a failure.
func ParsePing(output string) Ping {
	result := Ping{Path: PathNone}
	firstLine := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if firstLine == "" {
			firstLine = line
		}
		if strings.Contains(line, "is local Tailscale IP") {
			result.Local = true
			result.Reason = line
			return result
		}
		match := pongRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		result.Latency = match[4]
		if derp := derpRe.FindStringSubmatch(match[3]); derp != nil {
			result.Path = PathRelay
			result.Relay = derp[1]
		} else {
			result.Path = PathDirect
			result.DirectAddr = match[3]
		}
		return result
	}
	result.Reason = firstLine
	if result.Reason == "" {
		result.Reason = "tailscale ping produced no output"
	}
	return result
}

// FetchPing runs `tailscale ping` against one mesh address and parses it.
//
// A non-zero exit is NOT treated as failure, for a stronger version of the
// reason FetchStatus tolerates one: `tailscale ping` exits 1 on a perfectly
// good RELAYED pong, because not reaching a direct path is a failure by its
// own default. Measured 2026-08-25 — exit 1 alongside
// "pong from aw-mac (100.64.0.3) via DERP(mad) in 217ms". Treating that as an
// error would discard precisely the answer this call exists to get.
func FetchPing(ctx context.Context, r Runner, addr string) Ping {
	out, _ := r.Run(ctx, "tailscale", "ping", "-c", "1", "--timeout", PingTimeout, addr)
	return ParsePing(out)
}

// MeasurePaths replaces each ONLINE peer's guessed path with a measured one,
// in place. Peers are pinged concurrently: serially, a host with several
// peers would spend PingTimeout on each and could outlast the control plane's
// own command budget while every individual ping was still well inside its.
//
// Two deliberate non-actions:
//
//   - An offline peer is not pinged. There is nothing to measure and it would
//     cost the full timeout to find that out again.
//   - A ping that measures nothing leaves the peer exactly as status read it,
//     rather than downgrading it to PathNone. A failed measurement is not
//     evidence that there is no path, and Measured stays false to say so.
func MeasurePaths(ctx context.Context, r Runner, peers []Peer) {
	var wg sync.WaitGroup
	for i := range peers {
		if !peers[i].Online || len(peers[i].IPs) == 0 {
			continue
		}
		wg.Add(1)
		go func(peer *Peer) {
			defer wg.Done()
			ping := FetchPing(ctx, r, peer.IPs[0])
			if ping.Path == PathNone {
				return
			}
			peer.Path = ping.Path
			peer.Relay = ping.Relay
			peer.DirectAddr = ping.DirectAddr
			peer.Latency = ping.Latency
			peer.Measured = true
		}(&peers[i])
	}
	wg.Wait()
}
