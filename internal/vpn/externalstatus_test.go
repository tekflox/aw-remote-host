package vpn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tekflox/aw-remote-host/internal/state"
)

// recordATunnelAndARoute writes the state a healthy dial + route leaves
// behind, so the tests below can then present a machine that DISAGREES with
// it. That disagreement is the whole subject of this file.
func recordATunnelAndARoute(t *testing.T) {
	t.Helper()
	withFakeBinaries(t)
	plan := planUpOn(t, upHost(), mustProfile(t))
	if err := saveExternalTunnelState(*plan); err != nil {
		t.Fatalf("save tunnel: %v", err)
	}
	if err := saveExternalRouteState(ExternalRoutePlan{
		Container:   "aw-remote-host-workspace",
		ContainerID: "abc123def456",
		SourceIP:    "10.89.0.4",
		Table:       200,
		Priority:    5399,
		Runtime:     "podman",
		TunnelDev:   "wg0",
		MainGateway: "172.18.0.1",
		MainDev:     "eth0",
	}); err != nil {
		t.Fatalf("save route: %v", err)
	}
}

// liveHost is a machine where the tunnel and the rule really ARE in place.
func liveHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"wg show interfaces": "wg0\n",
		"ip rule show":       "0:\tfrom all lookup local\n5399:\tfrom 10.89.0.4 lookup 200\n32766:\tfrom all lookup main\n",
	}}
}

// deadHost is the state the DEAD-MAN LEAVES BEHIND: state.json still records a
// dial and a route, and the machine has neither. Nothing writes that fact back
// — the revert is a detached POSIX sh process that deliberately cannot call
// this binary — so the record is stale and only a measurement can tell.
func deadHost() *tableRunner {
	return &tableRunner{answers: map[string]string{
		"wg show interfaces": "\n",
		"ip rule show":       "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n",
	}}
}

func statusOn(t *testing.T, r Runner) ExternalStatusReport {
	t.Helper()
	report, err := ExternalStatus(context.Background(), ExternalStatusSpec{
		Runner: r,
		// Skipped so the test never reaches the network. The two fields it
		// suppresses are separately asserted to be null in that case.
		SkipEgress: true,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return report
}

// THE TEST THIS FILE EXISTS FOR.
//
// The dead-man's switch reverts autonomously and writes nothing back, so a
// status that replayed state.json would report "connected" long after the
// tunnel was torn down — a protection that WORKED, rendered on screen as a
// lie, at the one moment a human most needs the truth.
//
// So: a full record on disk, a machine with nothing on it, and the report has
// to side with the machine on every field that can be measured.
func TestStatusReportsTheMACHINEAndNotTheRecordedState(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)

	// Sanity: the record really is there, so a false "down" below cannot be
	// an empty state file quietly passing the test.
	if tunnel, route := loadVPNRecords(); tunnel == nil || route == nil {
		t.Fatal("the fixture did not record a tunnel and a route, so this test would prove nothing")
	}

	got := statusOn(t, deadHost())

	if got.Up {
		t.Fatal("up=true with no interface on the machine — the report replayed state.json instead of measuring, which is exactly the lie the dead-man produces")
	}
	if got.RuleInstalled {
		t.Fatal("rule_installed=true with no rule in `ip rule show` — the report replayed state.json")
	}
	if got.Since != nil {
		t.Fatalf("since=%q while nothing is in force; a timestamp is the most convincing thing on a status screen and must never outlive what it dates", *got.Since)
	}
	// Identity DOES come from the record — that is legitimate, and it is what
	// lets the screen say WHICH tunnel is down rather than just "something".
	if got.Iface != "wg0" || got.Table != 200 {
		t.Fatalf("identity was lost: iface=%q table=%d", got.Iface, got.Table)
	}
	if got.Container == nil || *got.Container != "aw-remote-host-workspace" {
		t.Fatalf("container identity was lost: %v", got.Container)
	}
}

// The other direction, so the test above cannot pass by always answering
// "down". Same record, a machine that agrees with it.
func TestStatusReportsUpWhenTheMachineActuallyAgrees(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)

	got := statusOn(t, liveHost())
	if !got.Up {
		t.Fatal("up=false while `wg show interfaces` lists wg0")
	}
	if !got.RuleInstalled {
		t.Fatal("rule_installed=false while the rule is in `ip rule show`")
	}
	if got.Since == nil {
		t.Fatal("since is null while the tunnel is genuinely up — the record's timestamp is the right source once measurement confirms it")
	}
}

// The leftover shape, and it is a real state rather than an edge case: the
// tunnel is gone and the policy rule is still installed, which is what a
// dead-man that removed the interface but not the rule — or a partial revert
// — leaves behind. The container is then pointed at a table with no default.
// The report has to be able to express that combination at all.
func TestStatusCanExpressARuleThatOutlivedItsTunnel(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)

	r := deadHost()
	r.answers["ip rule show"] = "0:\tfrom all lookup local\n5399:\tfrom 10.89.0.4 lookup 200\n"
	got := statusOn(t, r)

	if got.Up || !got.RuleInstalled {
		t.Fatalf("up=%v rule_installed=%v; the leftover state must be representable", got.Up, got.RuleInstalled)
	}
	if got.Since != nil {
		t.Fatalf("since=%q — the tunnel this was dated from is gone", *got.Since)
	}
	joined := strings.Join(got.Describe(), " ")
	if !strings.Contains(joined, "dead-man") || !strings.Contains(joined, "external-down") {
		t.Fatalf("the human rendering does not name the leftover state or how to clear it:\n%s", joined)
	}
}

// A host that has never dialled anything is the NORMAL case, not a fault. It
// reports down with nulls and no error — a status verb that errored here
// would make every unconfigured host look broken on the screen.
func TestStatusOnAHostThatNeverDialledIsNotAnError(t *testing.T) {
	isolateState(t)
	got := statusOn(t, deadHost())

	if got.Up || got.RuleInstalled || got.DeadmanArmed {
		t.Fatalf("a fresh host reported something in force: %+v", got)
	}
	for name, v := range map[string]*string{
		"container": got.Container, "since": got.Since,
		"container_egress_ip": got.ContainerEgressIP, "deadman_expires_at": got.DeadmanExpiresAt,
	} {
		if v != nil {
			t.Fatalf("%s = %q on a host that never dialled; the contract says null", name, *v)
		}
	}
	// The defaults still have to be sensible, or the screen has nothing to
	// label the "disconnected" state with.
	if got.Iface != "wg0" || got.Table != 200 {
		t.Fatalf("iface=%q table=%d", got.Iface, got.Table)
	}
}

// The nullable fields marshal as JSON `null`, not `""`. The contract spells
// them `"<value>"|null`, and an empty string is a second kind of "nothing"
// that every caller would have to special-case — including the core that is
// already built against this shape.
func TestNullableFieldsMarshalAsNullAndNeverAsEmptyString(t *testing.T) {
	isolateState(t)
	got := statusOn(t, deadHost())
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"container":null`, `"container_egress_ip":null`,
		`"host_egress_ip":null`, `"deadman_expires_at":null`, `"since":null`,
	} {
		if !strings.Contains(string(blob), want) {
			t.Fatalf("missing %s in:\n%s", want, blob)
		}
	}
	if strings.Contains(string(blob), `:""`) {
		t.Fatalf("an empty string is standing in for null:\n%s", blob)
	}
}

// Every key the workspace core parses has to be present and spelled exactly
// as the contract states. Core is ALREADY built against this shape and
// currently degrades to "unknown" because the verb did not exist — a key
// spelled differently here would leave it degrading forever against a verb
// that now answers, which is a worse failure than the one being fixed.
func TestTheReportCarriesExactlyTheContractedKeys(t *testing.T) {
	isolateState(t)
	blob, err := json.Marshal(statusOn(t, deadHost()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"iface", "up", "table", "rule_installed", "container",
		"container_egress_ip", "host_egress_ip", "deadman_armed",
		"deadman_expires_at", "since",
	} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("the contracted key %q is missing from the report: %s", key, blob)
		}
	}
}

// SkipEgress is the only thing allowed to suppress the two round-trip
// measurements, and it has to suppress BOTH — a status that quietly stopped
// measuring egress while still reporting an address would be the comfortable
// lie this whole file exists to prevent.
func TestSkipEgressSuppressesBothProbesAndNeitherIsInvented(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)

	r := liveHost()
	got := statusOn(t, r)
	if got.HostEgressIP != nil || got.ContainerEgressIP != nil {
		t.Fatalf("skip-egress still reported an address: host=%v container=%v", got.HostEgressIP, got.ContainerEgressIP)
	}
	// And it genuinely did not run the probe container, rather than running it
	// and discarding the answer.
	if r.ran("podman run") || r.ran("docker run") {
		t.Fatalf("the probe container ran despite skip-egress: %v", r.calls)
	}
}

// The dead-man's armed state is read from the armed PROCESS, not from the
// record — Deadman.Fired() checks the process's own command line. A record for
// a switch that has already fired must report disarmed, or the screen shows a
// protection that is no longer there.
func TestDeadmanArmedIsMeasuredFromTheProcessNotTheRecord(t *testing.T) {
	isolateState(t)

	// A record whose deadline has already passed: fired, whatever it says.
	past := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	if err := saveDeadman(&Deadman{PID: 999999, ArmedAt: past, ExpiresAt: past, ExitNode: "external tunnel wg0"}); err != nil {
		t.Fatalf("save deadman: %v", err)
	}
	if got := statusOn(t, deadHost()); got.DeadmanArmed {
		t.Fatal("deadman_armed=true for a switch whose deadline has passed — read from the record instead of the process")
	}

	// A record that is still in the future but whose process does not carry
	// the marker is ALSO not armed. PIDs are reused; only the marker makes
	// this answerable.
	future := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	if err := saveDeadman(&Deadman{PID: 999999, ArmedAt: future, ExpiresAt: future}); err != nil {
		t.Fatalf("save deadman: %v", err)
	}
	got := statusOn(t, deadHost())
	if got.DeadmanArmed {
		t.Fatal("deadman_armed=true for a PID that carries no marker")
	}
	if got.DeadmanExpiresAt == nil || *got.DeadmanExpiresAt != future {
		t.Fatalf("the recorded expiry is still worth reporting next to a disarmed verdict: %v", got.DeadmanExpiresAt)
	}
}

// DNS is not fully tunnelled, and the report has to say so rather than let a
// screen imply otherwise. Frederico's decision put DNS through the VPN, and
// Layer 1 delivers that only for resolvers the container addresses directly —
// see planExternalExclusions and ExternalStatusReport.DNSTunneled.
func TestStatusIsHonestThatDNSIsNotFullyTunnelled(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)

	got := statusOn(t, liveHost())
	if got.DNSTunneled {
		t.Fatal("dns_tunneled=true; aardvark's upstream has not moved, so this would be a claim the deployment does not deliver")
	}
	joined := strings.Join(got.Describe(), " ")
	if !strings.Contains(joined, "not fully tunnelled") {
		t.Fatalf("the human rendering does not admit the gap:\n%s", joined)
	}
}

// state.json must never gain key material through this path either — the
// report is rendered on a screen and stored by a control plane.
func TestStatusReportCarriesNoKeyMaterial(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)
	blob, _ := json.Marshal(statusOn(t, liveHost()))
	if strings.Contains(string(blob), testPrivateKey) || strings.Contains(string(blob), testPeerKey) {
		t.Fatalf("the status report carries key material:\n%s", blob)
	}
}

// Guard on the record shape this file reads: both records live under the same
// VPNState, and reading them in one pass is what makes the report describe a
// single instant rather than two.
func TestBothRecordsAreReadInOnePass(t *testing.T) {
	isolateState(t)
	recordATunnelAndARoute(t)
	tunnel, route := loadVPNRecords()
	if tunnel == nil || route == nil {
		t.Fatal("one of the two records was lost")
	}
	if tunnel.Iface != "wg0" || route.Container != "aw-remote-host-workspace" {
		t.Fatalf("records did not round-trip: %+v %+v", tunnel, route)
	}
	var _ *state.ExternalTunnelState = tunnel
}
