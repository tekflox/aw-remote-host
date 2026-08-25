package ops

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

const testLoginServer = "https://headscale.aw.tekflox.com"

// withVerdict pins the probe's verdict directly, bypassing vpn.Resolve — the
// sibling withEligibility in ops_vpn_test.go pins a Host and lets Resolve
// decide, which is right for testing the probe and wrong here: these tests are
// about what the verb DOES with a verdict, including synthetic ones no real
// machine produces.
func withVerdict(t *testing.T, e vpn.Eligibility) {
	t.Helper()
	prev := probeEligibility
	probeEligibility = func() vpn.Eligibility { return e }
	t.Cleanup(func() { probeEligibility = prev })
}

func eligible() vpn.Eligibility {
	return vpn.Eligibility{
		Host:             vpn.Host{OS: "linux", Arch: "amd64", UID: 0, HasTUN: true, HasSystemd: true},
		CanEnroll:        true,
		CanAdvertiseExit: true,
		Installer:        vpn.InstallerUpstreamScript,
	}
}

// withModuleRunner swaps the real bootstrap.Run for one that records the env
// it was handed and reports whatever outcome the test asks for. Nothing is
// installed; the point is the verb's own decisions.
func withModuleRunner(t *testing.T, err error, output string) *[]string {
	t.Helper()
	var gotEnv []string
	prev := runVPNModules
	runVPNModules = func(_ context.Context, m *bootstrap.Manifest, opts bootstrap.RunOptions) ([]bootstrap.ModuleStatus, error) {
		gotEnv = opts.Env
		st := bootstrap.ModuleStatus{Module: "vpn", Installed: true, OK: err == nil, Output: output}
		return []bootstrap.ModuleStatus{st}, err
	}
	t.Cleanup(func() { runVPNModules = prev })
	return &gotEnv
}

// withTempState points the state writer at a temp dir so a test never touches
// the invoking user's real ~/.aw-remote-host/state.json.
func withTempState(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	prev := vpnStatePath
	vpnStatePath = func() (string, error) { return path, nil }
	t.Cleanup(func() { vpnStatePath = prev })
	return path
}

// captureEmit records the events the verb streams to the control plane, which
// is where a leaked credential would be most visible and least recoverable.
func captureEmit() (Emit, *[]string) {
	var lines []string
	return func(level, scope, msg string) {
		lines = append(lines, level+" "+scope+" "+msg)
	}, &lines
}

func bootstrapArgs() map[string]any {
	return map[string]any{"login_server": testLoginServer, "authkey": secretKey}
}

// A real headscale pre-auth key's shape: 48 hex chars. Long enough that
// keyPattern's bare-hex arm matches it, which is the belt-and-braces path.
const secretKey = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"

// A host the probe refuses answers SUCCESSFULLY, carrying the sentence. This
// is the whole "refusal is a feature" contract: the control plane has to be
// able to tell "this machine cannot do this, here is why" apart from "this
// machine could not be asked", and an error collapses the two.
func TestVPNBootstrapRefusesWithItsReasonAndDoesNotRun(t *testing.T) {
	refusal := "/run/systemd/system does not exist, so systemd is not managing this host and this module has no other way to keep tailscaled running across reboots."
	withVerdict(t, vpn.Eligibility{CanEnroll: false, EnrollRefusal: refusal})
	ranEnv := withModuleRunner(t, nil, "")
	withTailscale(t, "")
	emit, lines := captureEmit()

	h := &Handler{Runner: newFakeRunner()}
	out, err := h.VPNBootstrap(context.Background(), bootstrapArgs(), emit)
	if err != nil {
		t.Fatalf("a refusal must be a successful reply, got error: %v", err)
	}
	if out["refused"] != true || out["enrolled"] != false || out["changed"] != false {
		t.Fatalf("expected a refusal that enrolled nothing, got %#v", out)
	}
	if out["refusal"] != refusal {
		t.Fatalf("the probe's own sentence must be passed through verbatim, got %q", out["refusal"])
	}
	if *ranEnv != nil {
		t.Fatal("the module ran on a host the probe refused — a half-install is exactly what refusing early prevents")
	}
	if !strings.Contains(strings.Join(*lines, "\n"), refusal) {
		t.Fatalf("the reason should reach the caller as progress too, got %v", *lines)
	}
}

// Asking for an exit gate on a host that cannot serve as one is refused with
// the EXIT sentence, not the enrol one — they fail for different reasons and a
// host that can join but cannot serve as a gate is the common case.
func TestVPNBootstrapRefusesAdvertiseExitOnItsOwnReason(t *testing.T) {
	e := eligible()
	e.CanAdvertiseExit = false
	e.ExitRefusal = "net.ipv4.ip_forward cannot be set on this host, so it cannot forward another node's traffic."
	withVerdict(t, e)
	ranEnv := withModuleRunner(t, nil, "")
	withTailscale(t, "")

	args := bootstrapArgs()
	args["advertise_exit"] = true
	h := &Handler{Runner: newFakeRunner()}
	out, err := h.VPNBootstrap(context.Background(), args, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["refusal"] != e.ExitRefusal {
		t.Fatalf("expected the exit refusal, got %q", out["refusal"])
	}
	if *ranEnv != nil {
		t.Fatal("nothing should have been installed")
	}
}

// The second press of the button. A node already up against the same login
// server must change NOTHING — and prove it by never invoking the module,
// rather than relying on verify.sh to no-op after the fact.
func TestVPNBootstrapOnAnAlreadyEnrolledNodeChangesNothing(t *testing.T) {
	withVerdict(t, eligible())
	ranEnv := withModuleRunner(t, nil, "")
	withTailscale(t, tailscaleBin)

	r := newFakeRunner()
	r.on(tsStatusJSON, tailscaleBin, "status", "--json")
	r.on(tsPrefsJSON, tailscaleBin, "debug", "prefs")

	h := &Handler{Runner: r}
	out, err := h.VPNBootstrap(context.Background(), bootstrapArgs(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *ranEnv != nil {
		t.Fatal("an already-enrolled node re-ran the enrolment module")
	}
	if out["enrolled"] != true || out["already_enrolled"] != true || out["changed"] != false {
		t.Fatalf("expected already-enrolled/unchanged, got %#v", out)
	}
	if out["node_name"] != "aw-baremetal" {
		t.Fatalf("expected the live node's name, got %q", out["node_name"])
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "already enrolled") {
		t.Fatalf("expected a written reason saying nothing changed, got %q", reason)
	}
}

// A node up against a DIFFERENT control plane is not "already enrolled" — it
// belongs to another tenant's mesh, and re-enrolling it is the whole point of
// the call. Two headscales do not federate, so this is not a near-miss.
func TestVPNBootstrapReEnrolsANodeOnAnotherControlPlane(t *testing.T) {
	withVerdict(t, eligible())
	ranEnv := withModuleRunner(t, nil, "")
	withTailscale(t, tailscaleBin)
	withTempState(t)

	r := newFakeRunner()
	r.on(tsStatusJSON, tailscaleBin, "status", "--json")
	r.on(strings.Replace(tsPrefsJSON, testLoginServer, "https://headscale.other-tenant.example", 1),
		tailscaleBin, "debug", "prefs")

	h := &Handler{Runner: r}
	out, err := h.VPNBootstrap(context.Background(), bootstrapArgs(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *ranEnv == nil {
		t.Fatal("expected the module to run for a node on a different control plane")
	}
	if out["already_enrolled"] != false || out["changed"] != true {
		t.Fatalf("expected a real enrolment, got %#v", out)
	}
}

// The environment handed to the module. --accept-dns stays forced off: it is
// phase 1's contract and NOT something the control plane may relax remotely,
// because accepting MagicDNS rewrites this host's resolver and a headscale
// that misbehaves then stops the machine resolving the control plane — the
// lockout failure mode arriving through DNS instead of through routing.
func TestVPNBootstrapForcesAcceptDNSOffAndNeverSelectsAnExitNode(t *testing.T) {
	withVerdict(t, eligible())
	ranEnv := withModuleRunner(t, nil, "")
	withTailscale(t, "")
	withTempState(t)

	args := bootstrapArgs()
	args["accept_dns"] = true // a caller asking for it is simply not honoured
	h := &Handler{Runner: newFakeRunner()}
	if _, err := h.VPNBootstrap(context.Background(), args, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	env := strings.Join(*ranEnv, "\n")
	if !strings.Contains(env, vpn.EnvAcceptDNS+"=0") {
		t.Fatalf("AW_VPN_ACCEPT_DNS must be forced to 0, got:\n%s", env)
	}
	if strings.Contains(env, "EXIT_NODE") || strings.Contains(env, "USE_EXIT") {
		t.Fatalf("enrolment must never select an exit node — that is `vpn use-exit`, a separate deliberate command:\n%s", env)
	}
	if !strings.Contains(env, vpn.EnvLoginServer+"="+testLoginServer) {
		t.Fatalf("the login server must be passed through as given, got:\n%s", env)
	}
}

// A trailing slash on the login server must not make an already-enrolled node
// look like a stranger and trigger a pointless re-enrolment.
func TestVPNBootstrapNormalisesTheLoginServer(t *testing.T) {
	withVerdict(t, eligible())
	ranEnv := withModuleRunner(t, nil, "")
	withTailscale(t, tailscaleBin)

	r := newFakeRunner()
	r.on(tsStatusJSON, tailscaleBin, "status", "--json")
	r.on(tsPrefsJSON, tailscaleBin, "debug", "prefs")

	args := bootstrapArgs()
	args["login_server"] = testLoginServer + "/"
	h := &Handler{Runner: r}
	out, err := h.VPNBootstrap(context.Background(), args, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *ranEnv != nil || out["already_enrolled"] != true {
		t.Fatalf("a trailing slash caused a needless re-enrolment: %#v", out)
	}
}

// No login server is a CALLER error, not a host refusal. The two have
// different fixes and only one of them is about this machine, so they must not
// come back in the same shape.
func TestVPNBootstrapWithoutALoginServerIsACallerError(t *testing.T) {
	withVerdict(t, eligible())
	withModuleRunner(t, nil, "")
	withTailscale(t, "")

	h := &Handler{Runner: newFakeRunner()}
	_, err := h.VPNBootstrap(context.Background(), map[string]any{"authkey": secretKey}, nil)
	if err == nil {
		t.Fatal("expected an error, not a refusal")
	}
	if !strings.Contains(err.Error(), "one headscale per tenant") {
		t.Fatalf("the error should say why there is no default, got: %v", err)
	}
}

// The credential must not come back out — not in the reply, not in the
// progress stream. This is the failure that cannot be walked back once it has
// happened, so it is asserted over the whole serialised response rather than
// field by field.
func TestVPNBootstrapNeverReturnsOrEmitsThePreAuthKey(t *testing.T) {
	withVerdict(t, eligible())
	// A failure path on purpose: the happy path never prints the key (see
	// bootstrap/vpn/install.sh), so the interesting case is the one nobody
	// planned — `tailscale up` failing and printing its own argv.
	failure := "vpn: enrolling 'node-7'\n+ tailscale up --login-server=" + testLoginServer +
		" --authkey=" + secretKey + "\nError: invalid key\n"
	withModuleRunner(t, errors.New("module \"vpn\" failed:\n"+failure), failure)
	withTailscale(t, "")
	withTempState(t)
	emit, lines := captureEmit()

	h := &Handler{Runner: newFakeRunner()}
	out, err := h.VPNBootstrap(context.Background(), bootstrapArgs(), emit)
	if err != nil {
		t.Fatalf("a failed enrolment should still be a reportable reply: %v", err)
	}
	if out["enrolled"] != false {
		t.Fatalf("a failed enrolment must not report enrolled: %#v", out)
	}
	serialised, marshalErr := json.Marshal(out)
	if marshalErr != nil {
		t.Fatalf("marshal: %v", marshalErr)
	}
	if strings.Contains(string(serialised), secretKey) {
		t.Fatalf("the pre-auth key reached the control plane in the reply:\n%s", serialised)
	}
	if strings.Contains(strings.Join(*lines, "\n"), secretKey) {
		t.Fatalf("the pre-auth key reached the control plane in an event:\n%v", *lines)
	}
	// And the diagnostic is still useful after redaction — a scrub that
	// throws the error away trades one problem for another.
	if detail, _ := out["detail"].(string); !strings.Contains(detail, "invalid key") {
		t.Fatalf("expected the failure to survive redaction, got %q", detail)
	}
}

// Eligibility rides on EVERY path out, including the refusals — the host whose
// reader most wants to know what it is capable of is the one that just said no.
func TestVPNBootstrapAlwaysCarriesEligibility(t *testing.T) {
	withTailscale(t, "")
	withTempState(t)

	cases := map[string]vpn.Eligibility{
		"refused": {CanEnroll: false, EnrollRefusal: "not Linux"},
		"enrols":  eligible(),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			withVerdict(t, e)
			withModuleRunner(t, nil, "")
			h := &Handler{Runner: newFakeRunner()}
			out, err := h.VPNBootstrap(context.Background(), bootstrapArgs(), nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			payload, ok := out["eligibility"].(map[string]any)
			if !ok {
				t.Fatalf("no eligibility in the reply: %#v", out)
			}
			if payload["can_enroll"] != e.CanEnroll {
				t.Fatalf("eligibility disagrees with the probe: %#v", payload)
			}
		})
	}
}

// A successful enrolment records the REQUEST in state.json — the same bargain
// the `vpn` command makes, so a remotely-triggered enrolment leaves the host
// able to answer `aw-remote-host vpn status` exactly like a hand-driven one.
func TestVPNBootstrapPersistsTheRequestedState(t *testing.T) {
	withVerdict(t, eligible())
	withModuleRunner(t, nil, "")
	withTailscale(t, "")
	path := withTempState(t)

	args := bootstrapArgs()
	args["hostname"] = "disposable-node"
	h := &Handler{Runner: newFakeRunner()}
	if _, err := h.VPNBootstrap(context.Background(), args, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	st, err := state.Load(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.VPN == nil || st.VPN.NodeName != "disposable-node" || st.VPN.LoginServer != testLoginServer {
		t.Fatalf("state was not recorded: %#v", st.VPN)
	}
	if st.VPN.EnrolledAt == "" {
		t.Fatal("EnrolledAt was not stamped")
	}
}

// The verb must not be gated behind the workspace runtime. A lean-linked
// laptop has no podman and is exactly the kind of machine most likely to be
// asked to join the mesh — same guarantee vpn_status and the firewall verbs
// carry.
func TestVPNBootstrapIsNotAWorkspaceLifecycleVerb(t *testing.T) {
	if workspaceLifecycleVerbs["vpn_bootstrap"] {
		t.Fatal("vpn_bootstrap must not need podman — a lean host is the common case here")
	}
}

// Dispatch reaches it by name, with args and emit intact. A verb the
// switchboard cannot route is a verb the control plane sees as "unknown verb",
// which reads as an out-of-date agent rather than as a wiring mistake.
func TestDispatchRoutesVPNBootstrap(t *testing.T) {
	withVerdict(t, vpn.Eligibility{CanEnroll: false, EnrollRefusal: "not Linux"})
	withModuleRunner(t, nil, "")
	withTailscale(t, "")

	h := &Handler{Runner: newFakeRunner()}
	got, err := h.Dispatch(context.Background(), "vpn_bootstrap", bootstrapArgs(), nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("unexpected reply type %T", got)
	}
	if out["refused"] != true {
		t.Fatalf("args did not reach the verb: %#v", out)
	}
}

func TestRedactKeyScrubsBothShapes(t *testing.T) {
	in := "--authkey=" + secretKey + " and a bare " + secretKey + " and --authkey abc123"
	got := redactKey(in, secretKey)
	if strings.Contains(got, secretKey) {
		t.Fatalf("key survived redaction: %q", got)
	}
	if strings.Contains(got, "abc123") {
		t.Fatalf("an --authkey argv fragment survived redaction: %q", got)
	}
}
