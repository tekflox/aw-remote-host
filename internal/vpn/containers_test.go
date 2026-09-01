package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Verbatim `podman network inspect` from the Surface (DESKTOP-DRMKFBT,
// podman 4.9.3 / netavark), 2026-08-26. The shape, not an approximation of it.
const podman4NetworkInspect = `[
     {
          "name": "aw-remote-host",
          "id": "06b4b0d60b902b99e0f52891e6024e2af25468dd74bb15ad2c65608c12441ad9",
          "driver": "bridge",
          "network_interface": "podman1",
          "subnets": [
               {
                    "subnet": "10.89.0.0/24",
                    "gateway": "10.89.0.1"
               }
          ],
          "ipv6_enabled": false,
          "internal": false,
          "dns_enabled": true,
          "ipam_options": {
               "driver": "host-local"
          }
     }
]`

// docker's shape, which shares no key names at all with the one above.
const dockerNetworkInspect = `[
    {
        "Name": "bridge",
        "Driver": "bridge",
        "IPAM": {
            "Driver": "default",
            "Config": [
                {"Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1"}
            ]
        }
    }
]`

// podman 3.x / CNI, still live: internal/wsl/wsl.go's header records that
// jammy ships podman 3.4.4, which is CNI-era.
const podman3NetworkInspect = `[
    {
        "cniVersion": "0.4.0",
        "name": "podman",
        "plugins": [
            {
                "type": "bridge",
                "ipam": {
                    "type": "host-local",
                    "ranges": [[{"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}]]
                }
            }
        ]
    }
]`

// THREE shapes, one parser. Which one a host answers with is not knowable
// from the command name — the same `podman network inspect` produces two of
// them depending on a version this module does not control.
func TestParseNetworkSubnetsReadsEveryRuntimeShape(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want string
	}{
		"podman 4 / netavark": {podman4NetworkInspect, "10.89.0.0/24"},
		"docker":              {dockerNetworkInspect, "172.17.0.0/16"},
		"podman 3 / CNI":      {podman3NetworkInspect, "10.88.0.0/16"},
	}
	for name, tc := range cases {
		got := parseNetworkSubnets(tc.raw)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("%s: got %v, want [%s]", name, got, tc.want)
		}
	}
}

// net.ParseCIDR is the only thing that promotes a string to a routing rule. A
// document with a field that merely looks like a subnet must not produce one:
// this list becomes `ip rule` entries on a production machine.
func TestParseNetworkSubnetsRefusesWhatIsNotAnIPv4Network(t *testing.T) {
	for _, raw := range []string{
		`[{"subnets":[{"subnet":"not-a-cidr"}]}]`,
		`[{"subnets":[{"subnet":"fd00::/64"}]}]`,
		`[{"subnets":[{"subnet":""}]}]`,
		`not json at all`,
		`[]`,
	} {
		if got := parseNetworkSubnets(raw); len(got) != 0 {
			t.Fatalf("%q produced %v — a rule must never be built from a field that only looks like a subnet", raw, got)
		}
	}
}

// A subnet written from a gateway address is the same network; keying two
// rules on it would make the cleanup count disagree with what was installed.
func TestParseNetworkSubnetsMasksToTheNetwork(t *testing.T) {
	got := parseNetworkSubnets(`[{"subnets":[{"subnet":"10.89.0.1/24"}]}]`)
	if len(got) != 1 || got[0] != "10.89.0.0/24" {
		t.Fatalf("got %v, want [10.89.0.0/24]", got)
	}
}

func TestContainerSubnetsDeduplicatesAcrossNetworks(t *testing.T) {
	nets := []ContainerNetwork{
		{Name: "b", Subnets: []string{"10.89.0.0/24"}},
		{Name: "a", Subnets: []string{"10.89.0.0/24", "172.17.0.0/16"}},
	}
	got := ContainerSubnets(nets)
	if len(got) != 2 || got[0] != "10.89.0.0/24" || got[1] != "172.17.0.0/16" {
		t.Fatalf("got %v", got)
	}
	if names := NetworksFor(nets, "10.89.0.0/24"); len(names) != 2 {
		t.Fatalf("both networks share that prefix and both should be named: %v", names)
	}
}

// End-to-end through ContainerNetworks, not just PickProbeNetwork's own
// hand-built fixtures: the `ps --filter network=<name>` measurement has to
// actually reach ContainerNetwork.Attached, or PickProbeNetwork's corrected
// logic would still be picking blind. Mirrors the real shape measured on the
// aw-remote-host workspace container (b614f41828c8, 2026-09-01): `podman`
// defined but empty, `aw-remote-host` carrying every real container.
func TestContainerNetworksMeasuresAttachment(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "network" && args[1] == "ls" {
			return "aw-remote-host\npodman\n", nil
		}
		if len(args) >= 2 && args[0] == "network" && args[1] == "inspect" {
			if args[2] == "aw-remote-host" {
				return `[{"name":"aw-remote-host","subnets":[{"subnet":"10.89.0.0/24"}]}]`, nil
			}
			return `[{"name":"podman","subnets":[{"subnet":"10.88.0.0/16"}]}]`, nil
		}
		if len(args) >= 1 && args[0] == "ps" {
			network := ""
			for _, a := range args {
				if strings.HasPrefix(a, "network=") {
					network = strings.TrimPrefix(a, "network=")
				}
			}
			if network == "aw-remote-host" {
				return "id1\nid2\nid3\n", nil
			}
			return "", nil
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	})
	nets, err := ContainerNetworks(context.Background(), runner, ContainerRuntime{Name: "podman"})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for _, n := range nets {
		byName[n.Name] = n.Attached
	}
	if byName["aw-remote-host"] != 3 {
		t.Fatalf("aw-remote-host attachment = %d, want 3: %v", byName["aw-remote-host"], byName)
	}
	if byName["podman"] != 0 {
		t.Fatalf("podman attachment = %d, want 0: %v", byName["podman"], byName)
	}
}

// A runtime must ANSWER, not merely be on PATH. A `docker` shim with no daemon
// behind it is this house's silent-degradation shape exactly: present, green,
// and serving nothing.
func TestDetectContainerRuntimeRequiresAnAnswer(t *testing.T) {
	_, err := DetectContainerRuntime(context.Background(), runnerFunc(func(context.Context, string, ...string) (string, error) {
		return "Cannot connect to the Docker daemon", errors.New("exit status 1")
	}))
	if err == nil {
		t.Fatal("a runtime that does not answer is not a runtime")
	}
	if !strings.Contains(err.Error(), NoContainerRuntimeRefusal) {
		t.Fatalf("the refusal has to carry the reason it is not a fallback: %v", err)
	}
	// And the failures are attributed, or an operator cannot tell "not
	// installed" from "no permission".
	if !strings.Contains(err.Error(), "docker:") || !strings.Contains(err.Error(), "podman:") {
		t.Fatalf("both attempts must be reported: %v", err)
	}
}

func TestDetectContainerRuntimePrefersTheOneThatAnswers(t *testing.T) {
	rt, err := DetectContainerRuntime(context.Background(), runnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		if name == "docker" {
			return "", errors.New("not found")
		}
		if len(args) > 0 && args[0] == "--version" {
			return "podman version 4.9.3\n", nil
		}
		return "podman\naw-remote-host\n", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rt.Name != "podman" || rt.Version != "podman version 4.9.3" {
		t.Fatalf("got %+v", rt)
	}
	if rt.DefaultNetwork() != "podman" {
		t.Fatalf("default network = %q", rt.DefaultNetwork())
	}
}

// The probe network must be deterministic. An egress measurement that silently
// changes which network it describes gives two answers that are both true and
// not comparable — which is worse than no measurement, because the whole
// feature is a comparison.
func TestPickProbeNetworkIsStable(t *testing.T) {
	nets := []ContainerNetwork{
		{Name: "aw-remote-host", Subnets: []string{"10.89.0.0/24"}, Attached: 75},
		{Name: "podman", Subnets: []string{"10.88.0.0/16"}, Attached: 3},
	}
	rt := ContainerRuntime{Name: "podman"}
	if got, _ := PickProbeNetwork(rt, nets); got != "podman" {
		t.Fatalf("the runtime's default should win when it too is populated, got %q", got)
	}
	// With the default gone, the first by name among the populated ones —
	// never "whichever came back first from the runtime".
	if got, _ := PickProbeNetwork(rt, nets[:1]); got != "aw-remote-host" {
		t.Fatalf("got %q", got)
	}
	if got, reason := PickProbeNetwork(rt, nil); got != "" || reason == "" {
		t.Fatalf("no networks is an empty answer WITH a reason, not a guess: %q %q", got, reason)
	}
}

// THE MEASURED BUG (finding vpn:pick-probe-network-prefers-empty-podman-network,
// confirmed live on the aw-remote-host workspace container b614f41828c8,
// 2026-09-01): the default-named network is NOT always the populated one.
// Preferring it by NAME picked `podman` while it sat empty and all 75 real
// containers were on `aw-remote-host`. The choice must be keyed on which
// network has a container ATTACHED, not on which one matches the runtime's
// default name.
func TestPickProbeNetworkPrefersThePopulatedNetworkOverTheDefaultName(t *testing.T) {
	nets := []ContainerNetwork{
		{Name: "aw-remote-host", Subnets: []string{"10.89.0.0/24"}, Attached: 75},
		{Name: "podman", Subnets: []string{"10.88.0.0/16"}, Attached: 0},
	}
	rt := ContainerRuntime{Name: "podman"}
	got, reason := PickProbeNetwork(rt, nets)
	if got != "aw-remote-host" {
		t.Fatalf("the populated network must win over the empty default-named one, got %q", got)
	}
	if !strings.Contains(reason, "aw-remote-host") || !strings.Contains(reason, "75") {
		t.Fatalf("the reason must name the network chosen and how many containers justified it: %q", reason)
	}
}

// The other half of the same fix: a host whose networks are all defined but
// none has a container attached is not "pick the first one anyway" — it is a
// refusal with a reason, the same honesty contract NoContainerNetworkRefusal
// already holds one step earlier for a runtime with no network at all.
func TestPickProbeNetworkRefusesWhenNothingIsAttached(t *testing.T) {
	nets := []ContainerNetwork{
		{Name: "aw-remote-host", Subnets: []string{"10.89.0.0/24"}, Attached: 0},
		{Name: "podman", Subnets: []string{"10.88.0.0/16"}, Attached: 0},
	}
	rt := ContainerRuntime{Name: "podman"}
	got, reason := PickProbeNetwork(rt, nets)
	if got != "" {
		t.Fatalf("no network has a container attached — the answer must be a refusal, not %q", got)
	}
	if reason == "" || !strings.Contains(reason, "2") {
		t.Fatalf("the refusal must say why: %q", reason)
	}
}

// The by-IP endpoint is FIRST and that is not cosmetic: a container on a
// network with dns_enabled=false, or one that inherited a broken resolver,
// would otherwise report "no internet" for a gate that is forwarding
// perfectly. Measured working from a podman container on the Surface.
func TestTheFirstEgressEndpointNeedsNoDNS(t *testing.T) {
	if !egressEndpoints[0].ByIP {
		t.Fatal("the first endpoint must be reachable without DNS")
	}
	if !strings.Contains(containerEgressEndpoints[0], "1.1.1.1") {
		t.Fatalf("the container probe's first endpoint must be an IP literal too: %q", containerEgressEndpoints[0])
	}
}

// Cloudflare's trace is a key=value blob, the others answer a bare address,
// and a captive portal answers HTTP 200 with neither.
func TestParseEgressBodyReadsBothShapesAndRefusesNeither(t *testing.T) {
	trace := "fl=123f45\nh=one.one.one.one\nip=188.250.165.236\nts=1787741999\n"
	if got := parseEgressBody(trace, true); got != "188.250.165.236" {
		t.Fatalf("got %q", got)
	}
	if got := parseEgressBody("65.109.66.88\n", false); got != "65.109.66.88" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"<html>Sign in to the network</html>", "", "error code: 1034"} {
		if got := parseEgressBody(bad, false); got != "" {
			t.Fatalf("%q became %q — an HTTP 200 from a portal is not an egress address", bad, got)
		}
	}
}

// The probe's answer is marked, because a pull progress line, a podman warning
// or an image banner all arrive on the same stream.
func TestParseContainerEgressTakesOnlyTheMarkedLine(t *testing.T) {
	out := "Trying to pull docker.io/curlimages/curl:latest...\nGetting image source signatures\nAW_EGRESS https://1.1.1.1/cdn-cgi/trace 65.109.66.88\n"
	via, ip := parseContainerEgress(out)
	if ip != "65.109.66.88" || via != "https://1.1.1.1/cdn-cgi/trace" {
		t.Fatalf("via=%q ip=%q", via, ip)
	}
	if _, ip := parseContainerEgress("Trying to pull 172.17.0.5 ...\n"); ip != "" {
		t.Fatalf("an unmarked line that happens to contain an address is not a measurement: %q", ip)
	}
	if _, ip := parseContainerEgress("AW_EGRESS https://x not-an-ip\n"); ip != "" {
		t.Fatalf("got %q", ip)
	}
}

// THE HONESTY CONTRACT, and it is the one that decides whether a screen can be
// trusted: a container-egress measurement that could not be made says so, and
// NEVER borrows the host's address. Under the corrected model the two numbers
// differing IS the evidence, so copying one into the other fabricates exactly
// the proof somebody is about to rely on.
func TestContainerEgressNeverInventsAnAddress(t *testing.T) {
	ctx := context.Background()

	none := MeasureContainerEgress(ctx, stubRunner{}, ContainerRuntime{}, "podman")
	if none.IP != "" || none.Error == "" {
		t.Fatalf("no runtime must answer an empty address WITH a reason: %+v", none)
	}

	noNetwork := MeasureContainerEgress(ctx, stubRunner{}, ContainerRuntime{Name: "podman"}, "")
	if noNetwork.IP != "" || !strings.Contains(noNetwork.Error, "no container network") {
		t.Fatalf("%+v", noNetwork)
	}

	failed := MeasureContainerEgress(ctx, runnerFunc(func(context.Context, string, ...string) (string, error) {
		return "Error: short-name resolution enforced but cannot prompt", errors.New("exit status 125")
	}), ContainerRuntime{Name: "podman"}, "podman")
	if failed.IP != "" {
		t.Fatalf("a failed run must not produce an address: %+v", failed)
	}
	if !strings.Contains(failed.Error, "short-name resolution") {
		t.Fatalf("the reason must carry the evidence: %+v", failed)
	}
	// Attribution survives the failure: a row that cannot say which runtime and
	// which network it failed on cannot be acted on.
	if failed.Runtime != "podman" || failed.Network != "podman" {
		t.Fatalf("%+v", failed)
	}
}

// The probe runs ON the network under test, and in a throwaway container —
// which is what makes the connection fresh by construction, with no pool that
// could answer over the path that existed before the route moved.
func TestContainerEgressRunsAThrowawayContainerOnTheNamedNetwork(t *testing.T) {
	var got string
	MeasureContainerEgress(context.Background(), runnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		got = name + " " + strings.Join(args, " ")
		return "AW_EGRESS https://1.1.1.1/cdn-cgi/trace 65.109.66.88\n", nil
	}), ContainerRuntime{Name: "podman"}, "aw-remote-host")

	for _, want := range []string{"podman run", "--rm", "--network aw-remote-host", ContainerProbeImage} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q missing from %q", want, got)
		}
	}
}
