package ops

import (
	"context"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// wgDump is trimmed from REAL `wg show all dump` output captured 2026-09-02
// on the production bare metal (2d5d56ef224359c0) — the interface `wg0` is
// aw-vpn-hub, with 9 peers, one of them the GL.iNet
// (jtYfpXLGZGcTpT/xq6gVXn5q/Ywt2Bhb5d6sJmGHCE4=, endpoint 24.90.8.255). Per
// the E1 card: use the measured fixture, not a synthetic one.
const wgDump = "wg0\tMA8wxrXQRGTZIX3d3689gi5Fs31/QaThPvI4LGIonXg=\tlAY93J69DBD8ZHX7IoYhzfyLocKQMNiuRUluM9a7Hwc=\t51820\toff\n" +
	"wg0\t4gZYmz65N8Zxenrvx1W4YLmF7dbSZa7LdBa7ZSwsBTU=\t(none)\t172.17.0.6:47783\t10.8.0.3/32\t1788315923\t7048\t232040\t25\n" +
	"wg0\tFQcqGgNn8fKP1LmpCBjwfYx80OvZEYCIZGgX8Ven8w0=\t(none)\t(none)\t10.8.0.4/32\t0\t0\t0\t25\n" +
	"wg0\t65RLn03rK6/HdOWP/NJPFsrTtGog3+8nVd4stcelJBE=\t(none)\t(none)\t10.8.0.5/32\t0\t0\t0\t25\n" +
	"wg0\tfVTjbJm83CzueQfl6UsD0K+151VDxJrZQfZObf6Yekk=\t(none)\t(none)\t10.8.0.6/32\t0\t0\t0\t25\n" +
	"wg0\tNfQX4Rzkc5xVjWMEM/7GMjyeg/POoh8ie/SlumZrUmQ=\t(none)\t(none)\t10.8.0.7/32\t0\t0\t0\t25\n" +
	"wg0\tPKG+4ojhKmzpAIOR8iL8hNG5qppdoV/R3ivt198QuVc=\t(none)\t(none)\t10.8.0.8/32\t0\t0\t0\t25\n" +
	"wg0\tzqsaMSoEF1WKNuQMwOWdGMYWLqtTh8zftU04PDnohVg=\t(none)\t(none)\t10.8.0.9/32\t0\t0\t0\t25\n" +
	"wg0\tG1qW4QehVfbNq/svYGLh50oMw67QcuuL4gSbqcgVEXc=\t(none)\t(none)\t10.8.0.10/32\t0\t0\t0\t25\n" +
	"wg0\tjtYfpXLGZGcTpT/xq6gVXn5q/Ywt2Bhb5d6sJmGHCE4=\t(none)\t24.90.8.255:50456\t0.0.0.0/0,::/0\t1788318109\t22948\t31428\t25\n"

const wgBin = "/usr/bin/wg"

// withWG points lookupWG at a fixed answer for the duration of one test —
// otherwise this verb's behaviour depends on whether the machine running
// `go test` happens to have `wg` installed. Mirrors withTailscale
// (ops_vpn_test.go).
func withWG(t *testing.T, bin string) {
	t.Helper()
	original := lookupWG
	lookupWG = func() string { return bin }
	t.Cleanup(func() { lookupWG = original })
}

// withNow pins nowUnix so a handshake age test asserts an exact number
// instead of a moving target.
func withNow(t *testing.T, ts int64) {
	t.Helper()
	original := nowUnix
	nowUnix = func() int64 { return ts }
	t.Cleanup(func() { nowUnix = original })
}

func rootHost() vpn.Host { return vpn.Host{OS: "linux", UID: 0} }

// Trap 1 (architecture doc §6.2 / the card's own): a host with no `wg`
// binary reports "unknown" — supported:false — and never claims the tunnel
// is down.
func TestExternalTunnelsUnknownWhenWGMissing(t *testing.T) {
	withWG(t, "")
	out := externalTunnelsPayload(context.Background(), newFakeRunner(), rootHost())

	if out["supported"] != false {
		t.Fatalf("supported = %v, want false", out["supported"])
	}
	if _, ok := out["tunnels"]; ok {
		t.Fatalf("tunnels present on an unsupported host: %v", out)
	}
	if reason, _ := out["reason"].(string); reason == "" {
		t.Fatal("reason must be a non-empty sentence when unsupported")
	}
}

// Same trap, the other cause named by the card: the shellout is REFUSED
// (no root, no CAP_NET_ADMIN) rather than the binary being absent. Refusal
// must also read as unknown, never as down.
func TestExternalTunnelsUnknownWhenShelloutRefused(t *testing.T) {
	withWG(t, wgBin)
	r := newFakeRunner()
	r.fail(context.DeadlineExceeded, "sudo", "-n", wgBin, "show", "all", "dump")
	// non-root host on Linux -> PrivilegedRunner prefixes sudo -n
	out := externalTunnelsPayload(context.Background(), r, vpn.Host{OS: "linux", UID: 1000})

	if out["supported"] != false {
		t.Fatalf("supported = %v, want false", out["supported"])
	}
	if _, ok := out["tunnels"]; ok {
		t.Fatalf("tunnels present when the shellout was refused: %v", out)
	}
}

// A non-root Linux host must go through `sudo -n`, matching every other
// privileged WireGuard/tailscale shellout in this package.
func TestExternalTunnelsUsesPrivilegeWrapperWhenNotRoot(t *testing.T) {
	withWG(t, wgBin)
	r := newFakeRunner()
	r.on(wgDump, "sudo", "-n", wgBin, "show", "all", "dump")
	withNow(t, 1788318109)

	out := externalTunnelsPayload(context.Background(), r, vpn.Host{OS: "linux", UID: 1000})
	if out["supported"] != true {
		t.Fatalf("supported = %v, want true (fakeRunner answered the sudo-prefixed call): %v", out["supported"], out)
	}
}

// Root needs no `sudo -n` prefix — the same bargain PrivilegedRunner makes
// everywhere else it is used.
func TestExternalTunnelsCallsWGDirectlyAsRoot(t *testing.T) {
	withWG(t, wgBin)
	r := newFakeRunner()
	r.on(wgDump, wgBin, "show", "all", "dump")
	withNow(t, 1788318109)

	out := externalTunnelsPayload(context.Background(), r, rootHost())
	if out["supported"] != true {
		t.Fatalf("supported = %v, want true (fakeRunner answered the direct call): %v", out["supported"], out)
	}
}

func tunnelsFromFixture(t *testing.T) []map[string]any {
	t.Helper()
	withWG(t, wgBin)
	r := newFakeRunner()
	r.on(wgDump, wgBin, "show", "all", "dump")
	withNow(t, 1788318109) // pinned to the GL.iNet peer's own captured handshake ts

	out := externalTunnelsPayload(context.Background(), r, rootHost())
	tunnels, ok := out["tunnels"].([]map[string]any)
	if !ok {
		t.Fatalf("tunnels is %T, want []map[string]any: %v", out["tunnels"], out)
	}
	return tunnels
}

// Trap 3: `latest-handshake = 0` means NO handshake ever happened. Rendering
// that as an age computes an age since the Unix epoch — the screen must say
// "never" instead.
func TestExternalTunnelsNeverHandshakeIsNeverNotAnAge(t *testing.T) {
	tunnels := tunnelsFromFixture(t)
	for _, tun := range tunnels {
		if tun["peer_public_key"] != "FQcqGgNn8fKP1LmpCBjwfYx80OvZEYCIZGgX8Ven8w0=" {
			continue
		}
		if tun["last_handshake_never"] != true {
			t.Fatalf("last_handshake_never = %v, want true for a peer with latest-handshake=0", tun["last_handshake_never"])
		}
		if tun["last_handshake_age_seconds"] != nil {
			t.Fatalf("last_handshake_age_seconds = %v, want nil for a peer that never handshaked", tun["last_handshake_age_seconds"])
		}
		return
	}
	t.Fatal("fixture peer with ts=0 not found in parsed tunnels")
}

// The GL.iNet peer DID handshake, and its age must be computed, not "never".
func TestExternalTunnelsComputesAgeForARealHandshake(t *testing.T) {
	tunnels := tunnelsFromFixture(t)
	for _, tun := range tunnels {
		if tun["peer_public_key"] != "jtYfpXLGZGcTpT/xq6gVXn5q/Ywt2Bhb5d6sJmGHCE4=" {
			continue
		}
		if tun["last_handshake_never"] != false {
			t.Fatalf("last_handshake_never = %v, want false for the GL.iNet peer", tun["last_handshake_never"])
		}
		// nowUnix is pinned to this peer's own captured handshake timestamp,
		// so the age must be exactly zero.
		if tun["last_handshake_age_seconds"] != int64(0) {
			t.Fatalf("last_handshake_age_seconds = %v, want 0", tun["last_handshake_age_seconds"])
		}
		if tun["endpoint"] != "24.90.8.255:50456" {
			t.Fatalf("endpoint = %v, want the GL.iNet endpoint", tun["endpoint"])
		}
		if got := tun["allowed_ips"].([]string); len(got) != 2 || got[0] != "0.0.0.0/0" || got[1] != "::/0" {
			t.Fatalf("allowed_ips = %v, want [0.0.0.0/0 ::/0]", got)
		}
		if tun["transfer_rx_bytes"] != uint64(22948) || tun["transfer_tx_bytes"] != uint64(31428) {
			t.Fatalf("transfer counters = %v/%v, want 22948/31428", tun["transfer_rx_bytes"], tun["transfer_tx_bytes"])
		}
		return
	}
	t.Fatal("GL.iNet peer not found in parsed tunnels")
}

// A peer with no known endpoint prints wg's own "(none)" — that must not
// leak into the payload verbatim.
func TestExternalTunnelsRendersNoEndpointAsEmpty(t *testing.T) {
	tunnels := tunnelsFromFixture(t)
	for _, tun := range tunnels {
		if tun["peer_public_key"] != "FQcqGgNn8fKP1LmpCBjwfYx80OvZEYCIZGgX8Ven8w0=" {
			continue
		}
		if tun["endpoint"] != "" {
			t.Fatalf("endpoint = %q, want \"\" (wg printed \"(none)\")", tun["endpoint"])
		}
		return
	}
	t.Fatal("fixture peer with no endpoint not found in parsed tunnels")
}

// The whole fixture: 9 peer lines in, 9 tunnels out, and never the
// interface's own line (which carries the LOCAL private key and must never
// be surfaced).
func TestExternalTunnelsParsesEveryPeerAndNeverThePrivateKey(t *testing.T) {
	tunnels := tunnelsFromFixture(t)
	if len(tunnels) != 9 {
		t.Fatalf("len(tunnels) = %d, want 9", len(tunnels))
	}
	for _, tun := range tunnels {
		for _, v := range tun {
			if v == "MA8wxrXQRGTZIX3d3689gi5Fs31/QaThPvI4LGIonXg=" { // the interface's own private key
				t.Fatalf("the local private key leaked into a tunnel entry: %v", tun)
			}
		}
	}
}

// Trap 4 (architecture doc §3.1 / §6.4): tailscale0 is excluded BY NAME. A
// mesh interface reported as an "external VPN" would show the mesh as an
// upstream of itself.
func TestExternalTunnelsExcludesTheMeshInterfaceByName(t *testing.T) {
	withWG(t, wgBin)
	dump := "tailscale0\tsomeprivkey\tsomepubkey\t0\toff\n" +
		"tailscale0\tpeerkey123\t(none)\t100.64.0.5:41641\t100.64.0.5/32\t1788318109\t100\t200\t25\n" +
		wgDump
	r := newFakeRunner()
	r.on(dump, wgBin, "show", "all", "dump")
	withNow(t, 1788318109)

	out := externalTunnelsPayload(context.Background(), r, rootHost())
	tunnels := out["tunnels"].([]map[string]any)
	for _, tun := range tunnels {
		if tun["interface"] == meshInterfaceName {
			t.Fatalf("tailscale0 leaked into external_tunnels: %v", tun)
		}
	}
	if len(tunnels) != 9 {
		t.Fatalf("len(tunnels) = %d, want 9 (the mesh interface's peer must not count)", len(tunnels))
	}
}

// A host with `wg` present but genuinely nothing configured reports
// supported:true with an EMPTY list — a real, known state, distinct from
// "could not ask" (supported:false).
func TestExternalTunnelsSupportedWithNoInterfacesIsAnEmptyListNotUnknown(t *testing.T) {
	withWG(t, wgBin)
	r := newFakeRunner()
	r.on("", wgBin, "show", "all", "dump")

	out := externalTunnelsPayload(context.Background(), r, rootHost())
	if out["supported"] != true {
		t.Fatalf("supported = %v, want true", out["supported"])
	}
	tunnels, ok := out["tunnels"].([]map[string]any)
	if !ok || tunnels == nil {
		t.Fatalf("tunnels = %v, want a non-nil empty slice", out["tunnels"])
	}
	if len(tunnels) != 0 {
		t.Fatalf("len(tunnels) = %d, want 0", len(tunnels))
	}
}

// external_tunnels must ride on EVERY path out of VPNStatus, including the
// one taken by a host with no tailscale at all — exactly the kind of host
// most likely to be running its own external tunnel and nothing else.
func TestVPNStatusCarriesExternalTunnelsWithNoTailscale(t *testing.T) {
	withTailscale(t, "")
	withWG(t, wgBin)
	withEligibility(t, rootHost())
	r := newFakeRunner()
	r.on(wgDump, wgBin, "show", "all", "dump")
	withNow(t, 1788318109)
	h := &Handler{Runner: r}

	data, err := h.Dispatch(context.Background(), "vpn_status", nil, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)
	ext, ok := out["external_tunnels"].(map[string]any)
	if !ok {
		t.Fatalf("external_tunnels missing/wrong type on the no-tailscale path: %v", out)
	}
	if ext["supported"] != true {
		t.Fatalf("external_tunnels.supported = %v, want true", ext["supported"])
	}
}

// And it rides on the normal, tailscale-running path too.
func TestVPNStatusCarriesExternalTunnelsWithTailscaleRunning(t *testing.T) {
	withTailscale(t, tailscaleBin)
	withWG(t, wgBin)
	withEligibility(t, rootHost())
	r := meshRunner()
	r.on(wgDump, wgBin, "show", "all", "dump")
	withNow(t, 1788318109)
	h := &Handler{Runner: r}

	data, err := h.Dispatch(context.Background(), "vpn_status", nil, noopEmit)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := data.(map[string]any)
	ext, ok := out["external_tunnels"].(map[string]any)
	if !ok {
		t.Fatalf("external_tunnels missing/wrong type on the tailscale-running path: %v", out)
	}
	tunnels, ok := ext["tunnels"].([]map[string]any)
	if !ok || len(tunnels) != 9 {
		t.Fatalf("external_tunnels.tunnels = %v, want 9 parsed tunnels", ext["tunnels"])
	}
}
