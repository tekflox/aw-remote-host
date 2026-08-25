package ops

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// Fixtures below are trimmed from REAL output captured 2026-08-25 on the
// production bare-metal (aw-baremetal, node id 1, 100.64.0.1) — the field
// names, the id/IP pairs and the "Peer is a map keyed by node key" shape are
// tailscale's, not a guess at them.
const tsStatusJSON = `{
  "Version": "1.102.3-t9329c3677-ga522f65e9",
  "BackendState": "Running",
  "MagicDNSSuffix": "mesh.aw.tekflox.com",
  "Self": {
    "ID": "1", "HostName": "aw-baremetal", "DNSName": "aw-baremetal.mesh.aw.tekflox.com.",
    "OS": "linux", "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
    "CurAddr": "", "Relay": "hel", "Online": true, "Active": false, "ExitNodeOption": true
  },
  "CurrentTailnet": {"Name": "headscale.aw.tekflox.com", "MagicDNSSuffix": "mesh.aw.tekflox.com"},
  "Peer": {
    "nodekey:c423": {
      "ID": "3", "HostName": "aw-mac", "DNSName": "aw-mac.mesh.aw.tekflox.com.",
      "OS": "macOS", "TailscaleIPs": ["100.64.0.3", "fd7a:115c:a1e0::3"],
      "CurAddr": "", "Relay": "mad", "Online": true, "Active": false, "ExitNodeOption": false
    },
    "nodekey:a119": {
      "ID": "2", "HostName": "aw-surface-wsl", "DNSName": "aw-surface-wsl.mesh.aw.tekflox.com.",
      "OS": "linux", "TailscaleIPs": ["100.64.0.2", "fd7a:115c:a1e0::2"],
      "CurAddr": "", "Relay": "mad", "Online": true, "Active": false, "ExitNodeOption": false
    }
  }
}`

const tsPrefsJSON = `{
  "ControlURL": "https://headscale.aw.tekflox.com",
  "RouteAll": false, "ExitNodeID": "", "ExitNodeIP": "",
  "ExitNodeAllowLANAccess": false, "CorpDNS": false,
  "Hostname": "aw-baremetal", "AdvertiseRoutes": ["0.0.0.0/0", "::/0"]
}`

const (
	pongViaDERP  = "pong from aw-mac (100.64.0.3) via DERP(mad) in 217ms\ndirect connection not established\n"
	pongDirect   = "pong from aw-surface-wsl (100.64.0.2) via 192.168.1.44:41641 in 3ms\n"
	tailscaleBin = "/usr/bin/tailscale"
)

// withTailscale points lookupTailscale at a fixed answer for the duration of
// one test — otherwise the verb's behaviour depends on whether whatever
// machine runs `go test` happens to have tailscale installed.
func withTailscale(t *testing.T, bin string) {
	t.Helper()
	original := lookupTailscale
	lookupTailscale = func() string { return bin }
	t.Cleanup(func() { lookupTailscale = original })
}

func meshRunner() *fakeRunner {
	r := newFakeRunner()
	r.on(tsStatusJSON, tailscaleBin, "status", "--json")
	r.on(tsPrefsJSON, tailscaleBin, "debug", "prefs")
	r.on(pongViaDERP, tailscaleBin, "ping", "-c", "1", "--timeout", "5s", "100.64.0.3")
	r.on(pongDirect, tailscaleBin, "ping", "-c", "1", "--timeout", "5s", "100.64.0.2")
	return r
}

func peerNamed(t *testing.T, data map[string]any, name string) map[string]any {
	t.Helper()
	peers, ok := data["peers"].([]map[string]any)
	if !ok {
		t.Fatalf("peers is %T, want []map[string]any", data["peers"])
	}
	for _, peer := range peers {
		if peer["name"] == name {
			return peer
		}
	}
	t.Fatalf("no peer named %q in %v", name, peers)
	return nil
}

// vpn_status must never be gated behind the workspace runtime: a lean-linked
// laptop has no podman and is exactly the kind of machine most likely to be on
// the mesh. Same guarantee the firewall verbs carry.
func TestVPNStatusIsNotAWorkspaceLifecycleVerb(t *testing.T) {
	if workspaceLifecycleVerbs["vpn_status"] {
		t.Fatal("vpn_status must not be in workspaceLifecycleVerbs")
	}
}

func TestVPNStatusReportsTheNodeAndItsControlPlane(t *testing.T) {
	withTailscale(t, tailscaleBin)
	h := &Handler{Runner: meshRunner()}

	data, err := h.Dispatch(context.Background(), "vpn_status", nil, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)

	if out["installed"] != true || out["running"] != true {
		t.Fatalf("installed/running = %v/%v, want true/true", out["installed"], out["running"])
	}
	if out["node_name"] != "aw-baremetal" {
		t.Fatalf("node_name = %v", out["node_name"])
	}
	// The IPv4, not the fd7a: one address is shown and that is the one people
	// recognise.
	if out["mesh_ip"] != "100.64.0.1" {
		t.Fatalf("mesh_ip = %v, want 100.64.0.1", out["mesh_ip"])
	}
	// The control plane is read off the node's own prefs. It is per tenant and
	// must never be a constant anywhere in this chain.
	if out["login_server"] != "https://headscale.aw.tekflox.com" {
		t.Fatalf("login_server = %v", out["login_server"])
	}
	if out["offers_exit"] != true || out["advertises_exit"] != true {
		t.Fatalf("exit advertisement = %v/%v, want true/true", out["offers_exit"], out["advertises_exit"])
	}
	if out["exit_node"] != "" {
		t.Fatalf("exit_node = %v, want empty — this node selects none", out["exit_node"])
	}
}

// The point of the whole card: two peers that `tailscale status` reports
// identically (both idle, both with a "mad" region and no CurAddr) are
// reported as one relayed and one direct, because they were pinged.
func TestVPNStatusMeasuresDirectVersusRelayPerPeer(t *testing.T) {
	withTailscale(t, tailscaleBin)
	h := &Handler{Runner: meshRunner()}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}

	mac := peerNamed(t, data, "aw-mac")
	if mac["path"] != "relay" || mac["via"] != "DERP(mad)" {
		t.Fatalf("aw-mac = %v/%v, want relay/DERP(mad)", mac["path"], mac["via"])
	}
	if mac["latency"] != "217ms" || mac["measured"] != true {
		t.Fatalf("aw-mac latency/measured = %v/%v", mac["latency"], mac["measured"])
	}

	surface := peerNamed(t, data, "aw-surface-wsl")
	if surface["path"] != "direct" || surface["via"] != "192.168.1.44:41641" {
		t.Fatalf("aw-surface-wsl = %v/%v, want direct/192.168.1.44:41641", surface["path"], surface["via"])
	}
	if surface["mesh_ip"] != "100.64.0.2" {
		t.Fatalf("aw-surface-wsl mesh_ip = %v", surface["mesh_ip"])
	}
}

// A launchd-started daemon on macOS does not inherit Homebrew's bin dir, so
// the resolved absolute path — not a bare "tailscale" — has to be what
// actually gets executed.
func TestVPNStatusRunsTheResolvedBinary(t *testing.T) {
	withTailscale(t, "/opt/homebrew/bin/tailscale")
	r := newFakeRunner()
	r.on(tsStatusJSON, "/opt/homebrew/bin/tailscale", "status", "--json")
	h := &Handler{Runner: r}

	if _, err := h.VPNStatus(context.Background()); err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	for _, call := range r.calls {
		if call[0] != "/opt/homebrew/bin/tailscale" {
			t.Fatalf("ran %q, want the resolved absolute path", strings.Join(call, " "))
		}
	}
}

// A host with no tailscale is the NORMAL case, not an error. Returning one
// would leave the control plane unable to tell "this host says it is off the
// mesh" from "this host could not be asked" — and the second must render as
// unknown, never as offline.
func TestVPNStatusOnAHostWithoutTailscaleSucceedsWithAReason(t *testing.T) {
	withTailscale(t, "")
	h := &Handler{Runner: newFakeRunner()}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("want a successful reply, got error: %v", err)
	}
	if data["installed"] != false || data["running"] != false {
		t.Fatalf("installed/running = %v/%v, want false/false", data["installed"], data["running"])
	}
	if reason, _ := data["reason"].(string); !strings.Contains(reason, "not installed") {
		t.Fatalf("reason = %q, want it to say tailscale is not installed", reason)
	}
	// Nothing invented on the way out — no mesh IP, no peer list.
	if data["mesh_ip"] != nil || data["peers"] != nil {
		t.Fatalf("a host without tailscale reported mesh_ip=%v peers=%v", data["mesh_ip"], data["peers"])
	}
}

// tailscale installed but stopped: still a successful, written answer, and no
// peer is pinged (there is nothing to measure through a stopped daemon).
func TestVPNStatusOnAStoppedNodeDoesNotPing(t *testing.T) {
	withTailscale(t, tailscaleBin)
	r := newFakeRunner()
	r.on(`{"BackendState":"Stopped","Self":{"HostName":"aw-baremetal","TailscaleIPs":["100.64.0.1"]},
	       "Peer":{"nodekey:c423":{"ID":"3","HostName":"aw-mac","TailscaleIPs":["100.64.0.3"],"Online":true}}}`,
		tailscaleBin, "status", "--json")
	r.on(tsPrefsJSON, tailscaleBin, "debug", "prefs")
	h := &Handler{Runner: r}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	if data["running"] != false {
		t.Fatalf("running = %v, want false", data["running"])
	}
	if reason, _ := data["reason"].(string); !strings.Contains(reason, "Stopped") {
		t.Fatalf("reason = %q, want tailscale's own BackendState in it", reason)
	}
	for _, call := range r.calls {
		if len(call) > 1 && call[1] == "ping" {
			t.Fatalf("pinged a peer through a stopped tailscaled: %v", call)
		}
	}
	if peerNamed(t, data, "aw-mac")["measured"] != false {
		t.Fatal("an unpinged peer must not claim to be measured")
	}
}

// A status read that fails is still a successful verb reply carrying the
// error text — the alternative is an opaque cmd_result the screen can only
// render as "something went wrong somewhere".
func TestVPNStatusSurfacesAFailedStatusReadAsAReason(t *testing.T) {
	withTailscale(t, tailscaleBin)
	r := newFakeRunner()
	r.fail(fmt.Errorf("exit status 1"), tailscaleBin, "status", "--json")
	r.on("failed to connect to local tailscaled", tailscaleBin, "status", "--json")
	h := &Handler{Runner: r}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("want a successful reply, got error: %v", err)
	}
	if data["installed"] != true || data["running"] != false {
		t.Fatalf("installed/running = %v/%v, want true/false", data["installed"], data["running"])
	}
	if reason, _ := data["reason"].(string); !strings.Contains(reason, "failed to connect") {
		t.Fatalf("reason = %q, want tailscale's own message in it", reason)
	}
}

// The exit gate in force is recorded as a node ID with an empty IP more often
// than not, so the ID has to resolve back to a name against the peer list.
func TestVPNStatusNamesTheExitGateInForce(t *testing.T) {
	withTailscale(t, tailscaleBin)
	r := meshRunner()
	r.on(`{"ControlURL":"https://headscale.aw.tekflox.com","ExitNodeID":"3","ExitNodeIP":"",
	       "AdvertiseRoutes":[]}`, tailscaleBin, "debug", "prefs")
	h := &Handler{Runner: r}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	if data["exit_node"] != "aw-mac" {
		t.Fatalf("exit_node = %v, want aw-mac resolved from ExitNodeID=3", data["exit_node"])
	}
}

// A gate whose peer has since gone away still gets reported as the raw id —
// "this node routes through something that is no longer here" is a real state
// and blanking it is how it stays invisible.
func TestVPNStatusReportsAnUnresolvableExitGateRatherThanBlankingIt(t *testing.T) {
	withTailscale(t, tailscaleBin)
	r := meshRunner()
	r.on(`{"ControlURL":"https://headscale.aw.tekflox.com","ExitNodeID":"99","ExitNodeIP":"",
	       "AdvertiseRoutes":[]}`, tailscaleBin, "debug", "prefs")
	h := &Handler{Runner: r}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	if data["exit_node"] != "99" {
		t.Fatalf("exit_node = %v, want the raw id 99", data["exit_node"])
	}
}

// withEligibility pins the verdict for one test. The real Probe() reads the
// machine running `go test`, and "is this box root with /dev/net/tun and
// systemd" is exactly the thing that differs between a CI runner, a laptop
// and the container this is meant to describe.
func withEligibility(t *testing.T, h vpn.Host) {
	t.Helper()
	original := probeEligibility
	probeEligibility = func() vpn.Eligibility { return vpn.Resolve(h) }
	t.Cleanup(func() { probeEligibility = original })
}

// The `aw` host, measured 2026-08-25: linux/amd64 running as root with
// /dev/net/tun, inside a container where systemd is not PID 1. The verdict
// AND its sentence have to reach the control plane — a bare `false` next to a
// generic reason is what the Networking screen was already doing off `os`
// alone, and it is what this carries the sentence to replace.
func TestVPNStatusCarriesTheEligibilityVerdictAndItsSentence(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withEligibility(t, vpn.Host{OS: "linux", Arch: "amd64", UID: 0, HasTUN: true})
	h := &Handler{Runner: meshRunner()}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	el, ok := data["eligibility"].(map[string]any)
	if !ok {
		t.Fatalf("eligibility is %T, want map[string]any", data["eligibility"])
	}
	if el["can_enroll"] != false {
		t.Fatalf("can_enroll = %v, want false — systemd is not managing this host", el["can_enroll"])
	}
	refusal, _ := el["enroll_refusal"].(string)
	if !strings.Contains(refusal, "/run/systemd/system does not exist") {
		t.Fatalf("enroll_refusal = %q, want the probe's own systemd sentence", refusal)
	}
	// A host that cannot join at all cannot be a gate either, and it says so
	// rather than leaving the second verdict unexplained.
	if el["can_advertise_exit"] != false {
		t.Fatalf("can_advertise_exit = %v, want false", el["can_advertise_exit"])
	}
	if exit, _ := el["exit_refusal"].(string); exit == "" {
		t.Fatal("can_advertise_exit=false with no exit_refusal — the refusal must carry a reason")
	}
}

// The host most in need of this answer is the one with no tailscale on it:
// "could I install it here" is the whole question, and the early return used
// to be the one path out of the verb that said nothing about it.
func TestVPNStatusReportsEligibilityWithoutTailscaleInstalled(t *testing.T) {
	withTailscale(t, "")
	withEligibility(t, vpn.Host{OS: "linux", Arch: "amd64", UID: 0, HasTUN: true, HasSystemd: true})
	h := &Handler{Runner: newFakeRunner()}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	el, ok := data["eligibility"].(map[string]any)
	if !ok {
		t.Fatalf("eligibility is %T, want map[string]any", data["eligibility"])
	}
	if el["can_enroll"] != true {
		t.Fatalf("can_enroll = %v, want true — root, tun and systemd are all present", el["can_enroll"])
	}
	if refusal, _ := el["enroll_refusal"].(string); refusal != "" {
		t.Fatalf("enroll_refusal = %q, want empty on an eligible host", refusal)
	}
	if el["installer"] != vpn.InstallerUpstreamScript {
		t.Fatalf("installer = %v, want %q", el["installer"], vpn.InstallerUpstreamScript)
	}
}

// A read failure is about tailscale, not about whether this host could run
// it. Dropping the verdict on that path would report "unknown" about a
// machine the probe just answered for.
func TestVPNStatusKeepsTheVerdictWhenTheStatusReadFails(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withEligibility(t, vpn.Host{OS: "darwin", Arch: "arm64", UID: 503})
	r := newFakeRunner()
	r.fail(fmt.Errorf("exit status 1"), tailscaleBin, "status", "--json")
	r.on("failed to connect to local tailscaled", tailscaleBin, "status", "--json")
	h := &Handler{Runner: r}

	data, err := h.VPNStatus(context.Background())
	if err != nil {
		t.Fatalf("VPNStatus: %v", err)
	}
	el, ok := data["eligibility"].(map[string]any)
	if !ok {
		t.Fatalf("eligibility is %T, want map[string]any", data["eligibility"])
	}
	if el["can_enroll"] != false {
		t.Fatalf("can_enroll = %v, want false — Mac.Home has no Homebrew prefix it can write", el["can_enroll"])
	}
	if refusal, _ := el["enroll_refusal"].(string); !strings.Contains(refusal, "Homebrew") {
		t.Fatalf("enroll_refusal = %q, want the macOS reason", refusal)
	}
}
