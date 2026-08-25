package vpn

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Every fixture below is REAL output, captured 2026-08-25 by running the
// command on the production bare-metal (aw-baremetal, 100.64.0.1) and on
// Mac.Home (aw-mac, 100.64.0.3) through the /link exec verb. Hand-written
// shapes are what let a parser pass its tests and fail on the one host it
// exists for.
const (
	// aw-baremetal -> aw-mac. Note the exit status: this command exited 1.
	pingRelayed = "pong from aw-mac (100.64.0.3) via DERP(mad) in 217ms\n" +
		"direct connection not established\n"
	// aw-mac -> aw-baremetal, exit 0.
	pingDirect = "pong from aw-baremetal (100.64.0.1) via 65.109.66.88:41641 in 74ms\n"
	// aw-baremetal -> itself.
	pingLocal = "100.64.0.1 is local Tailscale IP\n"
	// aw-baremetal -> an address no node holds. stdout was empty; this is all
	// of it, and it arrived on stderr.
	pingNoPeer = "no matching peer\n"
)

func TestParsePingRelayed(t *testing.T) {
	got := ParsePing(pingRelayed)
	if got.Path != PathRelay {
		t.Fatalf("path = %q, want %q", got.Path, PathRelay)
	}
	if got.Relay != "mad" {
		t.Fatalf("relay = %q, want mad", got.Relay)
	}
	if got.Via() != "DERP(mad)" {
		t.Fatalf("via = %q, want DERP(mad)", got.Via())
	}
	if got.Latency != "217ms" {
		t.Fatalf("latency = %q, want 217ms", got.Latency)
	}
}

// The trailing "direct connection not established" is on stderr and arrives
// merged with stdout. It is a complaint about the pong, not a failure to get
// one — a parser that let it win would report the relayed path as no path,
// which is the exact case this whole feature exists to make visible.
func TestParsePingRelayedIgnoresTheStderrComplaint(t *testing.T) {
	if got := ParsePing(pingRelayed); got.Reason != "" {
		t.Fatalf("reason = %q, want empty — a relayed pong is a real answer", got.Reason)
	}
}

func TestParsePingDirect(t *testing.T) {
	got := ParsePing(pingDirect)
	if got.Path != PathDirect {
		t.Fatalf("path = %q, want %q", got.Path, PathDirect)
	}
	if got.DirectAddr != "65.109.66.88:41641" {
		t.Fatalf("direct addr = %q", got.DirectAddr)
	}
	if got.Via() != "65.109.66.88:41641" {
		t.Fatalf("via = %q", got.Via())
	}
	if got.Relay != "" {
		t.Fatalf("relay = %q, want empty on a direct path", got.Relay)
	}
}

func TestParsePingLocal(t *testing.T) {
	got := ParsePing(pingLocal)
	if !got.Local {
		t.Fatal("local = false, want true")
	}
	if got.Path != PathNone {
		t.Fatalf("path = %q — a node does not have a path to itself", got.Path)
	}
}

// A ping that measured nothing must carry tailscale's own words for why, so
// nothing downstream has to invent an explanation.
func TestParsePingNoPeerKeepsTheReasonVerbatim(t *testing.T) {
	got := ParsePing(pingNoPeer)
	if got.Path != PathNone {
		t.Fatalf("path = %q, want %q", got.Path, PathNone)
	}
	if got.Reason != "no matching peer" {
		t.Fatalf("reason = %q, want %q", got.Reason, "no matching peer")
	}
	if got.Via() != "" {
		t.Fatalf("via = %q, want empty", got.Via())
	}
}

func TestParsePingEmpty(t *testing.T) {
	got := ParsePing("   \n\n")
	if got.Path != PathNone || got.Reason == "" {
		t.Fatalf("got %+v, want PathNone with a written reason", got)
	}
}

// scriptedRunner answers each `tailscale ping` by target address, and records
// the argv so the timeout/count flags stay pinned.
type scriptedRunner struct {
	mu      sync.Mutex
	replies map[string]string
	err     error
	calls   [][]string
}

func (s *scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, append([]string{name}, args...))
	return s.replies[args[len(args)-1]], s.err
}

// A relayed pong comes back with a NON-ZERO exit status — tailscale considers
// "no direct path" a failure of its own default. Discarding the output on that
// basis would throw away the answer.
func TestFetchPingKeepsAPongThatExitedNonZero(t *testing.T) {
	r := &scriptedRunner{
		replies: map[string]string{"100.64.0.3": pingRelayed},
		err:     fmt.Errorf("exit status 1"),
	}
	got := FetchPing(context.Background(), r, "100.64.0.3")
	if got.Path != PathRelay || got.Relay != "mad" {
		t.Fatalf("got %+v, want a relayed path via mad", got)
	}
	argv := strings.Join(r.calls[0], " ")
	if !strings.Contains(argv, "ping -c 1 --timeout "+PingTimeout+" 100.64.0.3") {
		t.Fatalf("argv = %q", argv)
	}
}

func TestMeasurePathsUpgradesTheStatusGuess(t *testing.T) {
	// What ParseStatus produces for two IDLE peers: no CurAddr, so both read
	// as relayed off the DERP region they would use. One of them is wrong.
	peers := []Peer{
		{Name: "aw-baremetal", IPs: []string{"100.64.0.1"}, Online: true, Path: PathRelay, Relay: "hel"},
		{Name: "aw-surface-wsl", IPs: []string{"100.64.0.2"}, Online: true, Path: PathRelay, Relay: "mad"},
	}
	r := &scriptedRunner{replies: map[string]string{
		"100.64.0.1": pingDirect,
		"100.64.0.2": pingRelayed,
	}}

	MeasurePaths(context.Background(), r, peers)

	if peers[0].Path != PathDirect || peers[0].DirectAddr != "65.109.66.88:41641" {
		t.Fatalf("peer 0 = %+v, want a measured direct path", peers[0])
	}
	if peers[0].Relay != "" {
		t.Fatalf("peer 0 relay = %q — a measured direct path must clear the guessed region", peers[0].Relay)
	}
	if peers[1].Path != PathRelay || peers[1].Via() != "DERP(mad)" {
		t.Fatalf("peer 1 = %+v, want a measured relay via mad", peers[1])
	}
	for i := range peers {
		if !peers[i].Measured {
			t.Fatalf("peer %d not marked measured", i)
		}
	}
}

// An offline peer is not worth a five-second timeout, and a ping that measured
// nothing is not evidence that there is no path — the status reading stands,
// and Measured stays false to say it was never confirmed.
func TestMeasurePathsLeavesUnmeasurablePeersAlone(t *testing.T) {
	peers := []Peer{
		{Name: "offline-one", IPs: []string{"100.64.0.9"}, Online: false, Path: PathNone},
		{Name: "unreachable", IPs: []string{"100.64.0.8"}, Online: true, Path: PathRelay, Relay: "mad"},
	}
	r := &scriptedRunner{replies: map[string]string{"100.64.0.8": pingNoPeer}}

	MeasurePaths(context.Background(), r, peers)

	if len(r.calls) != 1 {
		t.Fatalf("%d pings sent, want 1 — the offline peer must not be pinged", len(r.calls))
	}
	if peers[1].Path != PathRelay || peers[1].Relay != "mad" {
		t.Fatalf("peer 1 = %+v, want the status reading left intact", peers[1])
	}
	for i := range peers {
		if peers[i].Measured {
			t.Fatalf("peer %d claims to be measured when nothing was measured", i)
		}
	}
}
