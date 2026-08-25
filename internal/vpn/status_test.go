package vpn

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// testdata/status-baremetal.json and testdata/prefs-baremetal.json are
// verbatim captures from `aw-baremetal` on 2026-08-25 — the real mesh, three
// real nodes, not hand-written approximations.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseStatusRealBareMetal(t *testing.T) {
	s, err := ParseStatus(readFixture(t, "status-baremetal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Running() {
		t.Fatalf("BackendState = %q", s.BackendState)
	}
	if s.NodeName != "aw-baremetal" {
		t.Fatalf("node = %q", s.NodeName)
	}
	if s.DNSName != "aw-baremetal.mesh.aw.tekflox.com" {
		t.Fatalf("DNSName should have its trailing dot stripped, got %q", s.DNSName)
	}
	if len(s.MeshIPs) != 2 || s.MeshIPs[0] != "100.64.0.1" {
		t.Fatalf("mesh IPs = %v", s.MeshIPs)
	}
	if !s.Online {
		t.Fatal("should be online")
	}
	if s.Tailnet != "headscale.aw.tekflox.com" {
		t.Fatalf("tailnet = %q", s.Tailnet)
	}
	if !s.OffersExit {
		t.Fatal("this node advertises 0.0.0.0/0 and headscale approved it — ExitNodeOption is true in the capture")
	}
	if len(s.Peers) != 2 {
		t.Fatalf("peers = %d", len(s.Peers))
	}
}

// The measurement this whole field exists for: aw-mac and aw-surface-wsl are
// on the SAME home network behind the same public IP, and neither has a
// direct path — the Surface is WSL2, behind a second layer of NAT, so both
// sit on DERP(mad). If "direct" and "relay" collapsed into one word, "it
// works, but every packet goes to Madrid and back" would be invisible.
func TestParseStatusReportsRelayedPeers(t *testing.T) {
	s, err := ParseStatus(readFixture(t, "status-baremetal.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Peers {
		if p.Path != PathRelay {
			t.Fatalf("peer %s: path = %q, want relay (the capture has CurAddr empty and Relay=mad)", p.Name, p.Path)
		}
		if p.Relay != "mad" {
			t.Fatalf("peer %s: relay = %q", p.Name, p.Relay)
		}
		if p.Active {
			t.Fatalf("peer %s: the capture has Active=false", p.Name)
		}
		// Idle: "relay mad" alone would overstate it — the honest statement is
		// that no direct path was established and a relay is what it would use.
		desc := p.PathDescription()
		if !strings.Contains(desc, "no direct path established") || !strings.Contains(desc, "mad") {
			t.Fatalf("peer %s: %q does not say what was actually measured", p.Name, desc)
		}
	}
}

// Peer arrives as a map keyed by node key, so Go's iteration order is random.
// A status block that reshuffles between runs reads as a change that did not
// happen.
func TestParseStatusPeerOrderIsStable(t *testing.T) {
	data := readFixture(t, "status-baremetal.json")
	var first []string
	for i := 0; i < 20; i++ {
		s, err := ParseStatus(data)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, p := range s.Peers {
			names = append(names, p.Name)
		}
		if first == nil {
			first = names
			continue
		}
		for j := range names {
			if names[j] != first[j] {
				t.Fatalf("peer order changed between runs: %v vs %v", first, names)
			}
		}
	}
	if len(first) != 2 || first[0] != "aw-mac" || first[1] != "aw-surface-wsl" {
		t.Fatalf("peers should be sorted by name, got %v", first)
	}
}

// No direct path existed between any of the three real nodes on 2026-08-25,
// so this case is constructed rather than captured — CurAddr is the field
// tailscale fills in once a peer-to-peer path is established, and it wins
// over Relay, which stays populated as the fallback region even then.
func TestParseStatusReportsDirectPeers(t *testing.T) {
	p := peerFrom(&tsPeer{
		HostName: "aw-surface-wsl",
		CurAddr:  "192.168.1.73:41641",
		Relay:    "mad",
		Online:   true,
		Active:   true,
	})
	if p.Path != PathDirect {
		t.Fatalf("CurAddr set must mean direct, got %q", p.Path)
	}
	if p.PathDescription() != "direct 192.168.1.73:41641" {
		t.Fatalf("got %q", p.PathDescription())
	}
	// Idle but with a known direct endpoint: say it is idle rather than
	// claim a path is carrying traffic right now.
	p.Active = false
	if !strings.HasPrefix(p.PathDescription(), "idle") {
		t.Fatalf("got %q", p.PathDescription())
	}
}

func TestParseStatusOfflinePeerHasNoPath(t *testing.T) {
	p := peerFrom(&tsPeer{HostName: "gone", Online: false})
	if p.Path != PathNone {
		t.Fatalf("path = %q", p.Path)
	}
	if p.PathDescription() != "offline" {
		t.Fatalf("got %q", p.PathDescription())
	}
}

// `tailscale debug prefs` records a selected exit node as ExitNodeID and, on
// a real selection made by `vpn use-exit` (lab node, 2026-08-25), left
// ExitNodeIP EMPTY. Without the peer's stable node id there is nothing to
// match that against, and `status` reported the gate as "1" — then wrongly
// accused state.json of disagreeing with the machine.
func TestParseStatusCarriesPeerNodeIDs(t *testing.T) {
	s, err := ParseStatus(readFixture(t, "status-baremetal.json"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Peer{}
	for _, p := range s.Peers {
		byName[p.Name] = p
	}
	if got := byName["aw-surface-wsl"].ID; got != "2" {
		t.Fatalf("aw-surface-wsl ID = %q, want 2 (the capture's value)", got)
	}
	if got := byName["aw-mac"].DNSName; got != "aw-mac.mesh.aw.tekflox.com" {
		t.Fatalf("peer DNSName should have its trailing dot stripped like Self's, got %q", got)
	}
}

func TestParsePrefsCarriesTheSelectedGate(t *testing.T) {
	p, err := ParsePrefs([]byte(`{"ControlURL":"https://headscale.aw.tekflox.com","ExitNodeID":"1","ExitNodeIP":"","ExitNodeAllowLANAccess":true,"CorpDNS":false}`))
	if err != nil {
		t.Fatal(err)
	}
	// The shape that actually comes back from a live selection: an id and no
	// IP. UsesExitNode has to be true off the id alone, or `status` would say
	// nothing at all while the default route is on the mesh.
	if !p.UsesExitNode || p.ExitNodeID != "1" || p.ExitNodeIP != "" {
		t.Fatalf("got %+v", p)
	}
	if !p.ExitNodeAllowLANAccess {
		t.Fatal("ExitNodeAllowLANAccess must be read — with it off, the host's own LAN is inside the tunnel")
	}
}

func TestParseStatusRejectsGarbage(t *testing.T) {
	if _, err := ParseStatus([]byte("not json")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParsePrefsRealBareMetal(t *testing.T) {
	p, err := ParsePrefs(readFixture(t, "prefs-baremetal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.LoginServer != "https://headscale.aw.tekflox.com" {
		t.Fatalf("login server = %q", p.LoginServer)
	}
	if p.Hostname != "aw-baremetal" {
		t.Fatalf("hostname = %q", p.Hostname)
	}
	if !p.AdvertisesExit {
		t.Fatal("AdvertiseRoutes contains 0.0.0.0/0 in the capture")
	}
	// The node that ADVERTISES an exit route does not itself USE one — the
	// property phase 1 depends on, confirmed on production hardware.
	if p.UsesExitNode {
		t.Fatal("advertising an exit node must not mean selecting one")
	}
	if p.AcceptsRoutes || p.AcceptsDNS {
		t.Fatalf("capture has RouteAll=false, CorpDNS=false; got %+v", p)
	}
}

type fakeRunner struct {
	out string
	err error
}

func (f fakeRunner) Run(context.Context, string, ...string) (string, error) {
	return f.out, f.err
}

// tailscale exits non-zero while logged out and still prints a perfectly good
// JSON document saying so. "BackendState: NeedsLogin" is a far more useful
// answer than "exit status 1", so a non-zero exit with JSON on stdout is not
// treated as fatal.
func TestFetchStatusPrefersJSONOverExitCode(t *testing.T) {
	r := fakeRunner{out: `{"BackendState":"NeedsLogin"}`, err: errors.New("exit status 1")}
	s, err := FetchStatus(context.Background(), r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.BackendState != "NeedsLogin" || s.Running() {
		t.Fatalf("got %+v", s)
	}
}

func TestFetchStatusFailsWhenThereIsNoJSON(t *testing.T) {
	r := fakeRunner{out: "tailscale: command not found", err: errors.New("exit status 127")}
	if _, err := FetchStatus(context.Background(), r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSameLoginServerIgnoresTrailingSlashAndCase(t *testing.T) {
	if !SameLoginServer("https://headscale.aw.tekflox.com/", "HTTPS://headscale.aw.tekflox.com") {
		t.Fatal("a trailing slash is not a different control plane")
	}
	if SameLoginServer("https://headscale.aw.tekflox.com", "https://headscale.other.example") {
		t.Fatal("different hosts are different control planes")
	}
}
