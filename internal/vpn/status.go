package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Runner abstracts the `tailscale` shellouts so tests parse fixtures instead
// of needing a real mesh. Same shape as ops.Runner and firewall.Runner — any
// value satisfying either satisfies this one, so ops.DefaultRunner passes
// straight through with no adapter.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (output string, err error)
}

// PathKind is how this node currently reaches a peer.
//
// This distinction is the whole reason peers are reported at all. Measured
// 2026-08-25: aw-mac and aw-surface-wsl sit on the SAME home network, behind
// the same public IP, and still talk `via DERP(mad)` — the Surface is WSL2 and
// therefore behind a second layer of NAT, so no direct path is ever
// established. A relayed path works; it just goes to Madrid and back. Without
// this field that is invisible, which is the house's silent-degradation
// failure mode exactly.
type PathKind string

const (
	// PathDirect: a peer-to-peer UDP path is established.
	PathDirect PathKind = "direct"
	// PathRelay: traffic goes through a DERP relay.
	PathRelay PathKind = "relay"
	// PathNone: no path is known — an offline peer, or one never contacted.
	PathNone PathKind = "none"
)

// Peer is one other node in the tenant mesh.
type Peer struct {
	Name string
	// ID is tailscale's stable node id — "1", "2", ... as headscale hands
	// them out. It is carried because `tailscale debug prefs` records a
	// selected exit node as ExitNodeID and quite often leaves ExitNodeIP
	// empty, so this is the only field a selection can be matched back to a
	// name through. Measured on the lab node 2026-08-25, where the first
	// version of this reported the exit gate as "1".
	ID string
	// DNSName is the peer's fully-qualified mesh name, trailing dot stripped.
	// Carried so `vpn use-exit` can accept the name a human copied out of a
	// status listing, whichever of the two forms that was.
	DNSName string
	IPs     []string
	OS      string
	Online  bool
	// Active is tailscale's own "there is traffic on this path right now".
	// It matters for reading Path honestly: an idle peer's Relay is the DERP
	// region it WOULD use, not one it is measurably using.
	Active bool
	Path   PathKind
	// Relay is the DERP region code (e.g. "mad") when Path is PathRelay.
	Relay string
	// DirectAddr is the peer-to-peer endpoint when Path is PathDirect.
	DirectAddr string
	// Measured is whether Path came from an actual `tailscale ping` rather
	// than from the status JSON. It carries the honesty of the whole field:
	// an idle peer's status reading is a guess (see ping.go), and a consumer
	// that cannot tell a guess from a measurement will present one as the
	// other.
	Measured bool
	// Latency is the round trip `tailscale ping` printed ("217ms"), and is
	// only ever set when Measured is true.
	Latency string
	// OffersExit is tailscale's ExitNodeOption: advertised AND approved by
	// the control plane. An advertised-but-unapproved node reads false here,
	// which is the honest answer — until a headscale admin approves the
	// route, nobody can select it.
	OffersExit bool
}

// PathDescription renders the path the way it should be read, including the
// idle case. "relay mad" on an idle peer would overstate what was measured;
// "no direct path" on an idle peer is what is actually known.
func (p Peer) PathDescription() string {
	switch p.Path {
	case PathDirect:
		if p.Active {
			return "direct " + p.DirectAddr
		}
		return "idle, last path direct " + p.DirectAddr
	case PathRelay:
		if p.Active {
			return "RELAY via DERP(" + p.Relay + ")"
		}
		return "idle, no direct path established — would relay via DERP(" + p.Relay + ")"
	default:
		if !p.Online {
			return "offline"
		}
		return "no path known"
	}
}

// Via renders just the "through what" half of the path — "DERP(mad)" when
// relayed, the endpoint when direct, "" when no path is known. Separate from
// PathDescription because a screen shows the kind and the route as two
// different things (a badge and a caption), where a log line wants one
// sentence.
func (p Peer) Via() string {
	switch p.Path {
	case PathDirect:
		return p.DirectAddr
	case PathRelay:
		return "DERP(" + p.Relay + ")"
	}
	return ""
}

// Status is what this node reports about its own mesh membership.
type Status struct {
	// Installed is false when the tailscale CLI is not on this host at all;
	// every other field is then meaningless.
	Installed bool
	// BackendState is tailscale's own word for it: "Running", "NeedsLogin",
	// "Stopped", "NoState".
	BackendState   string
	Version        string
	Tailnet        string // CurrentTailnet.Name — the headscale this node answers to
	MagicDNSSuffix string
	NodeName       string
	DNSName        string
	MeshIPs        []string
	Online         bool
	// OffersExit is Self.ExitNodeOption — this node advertises exit routes
	// AND the control plane has approved them. Compared against the stored
	// AdvertiseExit request in `status` so an advertised-but-unapproved node
	// is reported as the half-done thing it is, rather than silently.
	OffersExit bool
	Peers      []Peer
}

// Running reports whether the node is actually up in the mesh.
func (s Status) Running() bool { return s.Installed && s.BackendState == "Running" }

// tsStatus mirrors just the fields of `tailscale status --json` this package
// reads. Deliberately a local subset rather than a dependency on
// tailscale.com/ipn/ipnstate: pulling the tailscale module in for four
// structs would add a very large dependency tree to a binary whose whole
// selling point (see the root README) is being small enough to read.
type tsStatus struct {
	Version        string             `json:"Version"`
	BackendState   string             `json:"BackendState"`
	MagicDNSSuffix string             `json:"MagicDNSSuffix"`
	Self           *tsPeer            `json:"Self"`
	Peer           map[string]*tsPeer `json:"Peer"`
	CurrentTailnet *tsCurrentTailnet  `json:"CurrentTailnet"`
}

type tsCurrentTailnet struct {
	Name           string `json:"Name"`
	MagicDNSSuffix string `json:"MagicDNSSuffix"`
}

type tsPeer struct {
	ID             string   `json:"ID"`
	HostName       string   `json:"HostName"`
	DNSName        string   `json:"DNSName"`
	OS             string   `json:"OS"`
	TailscaleIPs   []string `json:"TailscaleIPs"`
	CurAddr        string   `json:"CurAddr"`
	Relay          string   `json:"Relay"`
	Online         bool     `json:"Online"`
	Active         bool     `json:"Active"`
	ExitNodeOption bool     `json:"ExitNodeOption"`
}

// ParseStatus turns `tailscale status --json` output into a Status.
func ParseStatus(data []byte) (Status, error) {
	var raw tsStatus
	if err := json.Unmarshal(data, &raw); err != nil {
		return Status{}, fmt.Errorf("parse tailscale status: %w", err)
	}
	s := Status{
		Installed:      true,
		BackendState:   raw.BackendState,
		Version:        raw.Version,
		MagicDNSSuffix: raw.MagicDNSSuffix,
	}
	if raw.CurrentTailnet != nil {
		s.Tailnet = raw.CurrentTailnet.Name
		if s.MagicDNSSuffix == "" {
			s.MagicDNSSuffix = raw.CurrentTailnet.MagicDNSSuffix
		}
	}
	if raw.Self != nil {
		s.NodeName = raw.Self.HostName
		s.DNSName = strings.TrimSuffix(raw.Self.DNSName, ".")
		s.MeshIPs = raw.Self.TailscaleIPs
		s.Online = raw.Self.Online
		s.OffersExit = raw.Self.ExitNodeOption
	}
	for _, p := range raw.Peer {
		if p == nil {
			continue
		}
		s.Peers = append(s.Peers, peerFrom(p))
	}
	// Peer arrives as a map keyed by node key, so its iteration order is
	// random. A status block that reshuffles between two runs reads as a
	// change that did not happen — same reasoning as hostpower's `order`.
	sortPeers(s.Peers)
	return s, nil
}

func peerFrom(p *tsPeer) Peer {
	out := Peer{
		ID:         p.ID,
		Name:       p.HostName,
		DNSName:    strings.TrimSuffix(p.DNSName, "."),
		IPs:        p.TailscaleIPs,
		OS:         p.OS,
		Online:     p.Online,
		Active:     p.Active,
		OffersExit: p.ExitNodeOption,
		Relay:      p.Relay,
		DirectAddr: p.CurAddr,
		Path:       PathNone,
	}
	switch {
	case p.CurAddr != "":
		out.Path = PathDirect
	case p.Relay != "":
		out.Path = PathRelay
	}
	return out
}

func sortPeers(peers []Peer) {
	for i := 1; i < len(peers); i++ {
		for j := i; j > 0 && peers[j].Name < peers[j-1].Name; j-- {
			peers[j], peers[j-1] = peers[j-1], peers[j]
		}
	}
}

// FetchStatus runs `tailscale status --json` and parses it.
//
// A non-zero exit is NOT treated as fatal on its own: tailscale exits 1 while
// logged out or stopped and still prints a perfectly good JSON document
// saying so, and "BackendState: NeedsLogin" is a far more useful answer than
// "exit status 1".
func FetchStatus(ctx context.Context, r Runner) (Status, error) {
	out, err := r.Run(ctx, "tailscale", "status", "--json")
	trimmed := strings.TrimSpace(out)
	if strings.HasPrefix(trimmed, "{") {
		return ParseStatus([]byte(trimmed))
	}
	if err != nil {
		return Status{}, fmt.Errorf("tailscale status: %w: %s", err, trimmed)
	}
	return Status{}, fmt.Errorf("tailscale status returned no JSON: %s", trimmed)
}

// tsPrefs mirrors the fields of `tailscale debug prefs` this package reads.
type tsPrefs struct {
	ControlURL             string   `json:"ControlURL"`
	Hostname               string   `json:"Hostname"`
	AdvertiseRoutes        []string `json:"AdvertiseRoutes"`
	ExitNodeIP             string   `json:"ExitNodeIP"`
	ExitNodeID             string   `json:"ExitNodeID"`
	ExitNodeAllowLANAccess bool     `json:"ExitNodeAllowLANAccess"`
	RouteAll               bool     `json:"RouteAll"`
	CorpDNS                bool     `json:"CorpDNS"`
}

// Prefs is the subset of this node's tailscale preferences that says what it
// was ASKED to do — as opposed to Status, which says what it is doing.
type Prefs struct {
	LoginServer string
	Hostname    string
	// AdvertisesExit is whether 0.0.0.0/0 is in the advertised routes. True
	// with Status.OffersExit false means advertised but not yet approved by a
	// headscale admin, which is a real state a host can sit in indefinitely.
	AdvertisesExit bool
	// UsesExitNode is whether this node has SELECTED an exit node — i.e. its
	// default route goes through the mesh. Phase 1 never sets this; phase 2's
	// `vpn use-exit` does, and `status` reads it live rather than trusting
	// state.json, because this is the one setting on this host that can cut
	// it off from the control plane and the dangerous case is precisely the
	// one where something OTHER than this binary set it.
	UsesExitNode bool
	// ExitNodeIP / ExitNodeID are which gate is in force. ExitNodeIP is
	// usually the useful one; ExitNodeID is tailscale's stable node id and is
	// what remains populated when the peer has since gone away, which is a
	// state worth being able to report rather than blank.
	ExitNodeIP string
	ExitNodeID string
	// ExitNodeAllowLANAccess is whether the LAN stays reachable while the
	// default route is on the mesh.
	ExitNodeAllowLANAccess bool
	// AcceptsRoutes / AcceptsDNS are the other two settings that change this
	// machine's behaviour rather than just its membership.
	AcceptsRoutes bool
	AcceptsDNS    bool
}

// ParsePrefs turns `tailscale debug prefs` output into a Prefs.
func ParsePrefs(data []byte) (Prefs, error) {
	var raw tsPrefs
	if err := json.Unmarshal(data, &raw); err != nil {
		return Prefs{}, fmt.Errorf("parse tailscale prefs: %w", err)
	}
	p := Prefs{
		LoginServer:            strings.TrimSuffix(raw.ControlURL, "/"),
		Hostname:               raw.Hostname,
		UsesExitNode:           raw.ExitNodeIP != "" || raw.ExitNodeID != "",
		ExitNodeIP:             raw.ExitNodeIP,
		ExitNodeID:             raw.ExitNodeID,
		ExitNodeAllowLANAccess: raw.ExitNodeAllowLANAccess,
		AcceptsRoutes:          raw.RouteAll,
		AcceptsDNS:             raw.CorpDNS,
	}
	for _, route := range raw.AdvertiseRoutes {
		if route == "0.0.0.0/0" || route == "::/0" {
			p.AdvertisesExit = true
		}
	}
	return p, nil
}

// FetchPrefs runs `tailscale debug prefs` and parses it.
func FetchPrefs(ctx context.Context, r Runner) (Prefs, error) {
	out, err := r.Run(ctx, "tailscale", "debug", "prefs")
	trimmed := strings.TrimSpace(out)
	if strings.HasPrefix(trimmed, "{") {
		return ParsePrefs([]byte(trimmed))
	}
	if err != nil {
		return Prefs{}, fmt.Errorf("tailscale debug prefs: %w: %s", err, trimmed)
	}
	return Prefs{}, fmt.Errorf("tailscale debug prefs returned no JSON: %s", trimmed)
}

// SameLoginServer compares two control-plane URLs for the purpose of "is this
// node already enrolled where I want it". Trailing slashes and case in the
// scheme/host are not differences a human would consider meaningful, and
// treating them as one would make a re-run tear down a perfectly good
// enrolment.
func SameLoginServer(a, b string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "/"))
	}
	return norm(a) == norm(b)
}
