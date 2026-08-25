// The vpn_bootstrap verb — enrol THIS host in the tenant's mesh, triggered
// over the /link tunnel instead of by a human typing `aw-remote-host vpn`.
//
// It is the same module the CLI runs (bootstrap/vpn, opt-in), driven through
// the same environment contract, so there is exactly one implementation of
// "install tailscale and enrol this node" and this file only decides WHEN to
// run it and WHAT to say about the outcome.
//
// Three properties are load-bearing, and each one is a thing the control
// plane cannot check on this host's behalf:
//
//  1. REFUSAL IS A SUCCESSFUL REPLY. A host that cannot be enrolled answers
//     {"refused": true, "refusal": "<complete sentence>"} with a 'nil' error.
//     The sentence is the whole product of internal/vpn's probe and is meant
//     to be shown verbatim; turning it into a verb-level error would collapse
//     "this machine cannot do this, here is why" into the same shape as "the
//     host could not be asked", which is exactly the distinction the
//     Networking screen exists to keep (see VPNStatus's doc comment).
//
//  2. IDEMPOTENCE IS DECIDED HERE, BEFORE THE MODULE RUNS. bootstrap's own
//     detect->install->verify would already skip the install, but it would
//     still run two scripts and report a pass that reads identically to a
//     fresh enrolment. A second press of a button must be able to say "this
//     node was already enrolled" and prove it changed nothing, so the live
//     node is read first and the module is not invoked at all when it is
//     already up against the same login server.
//
//  3. THE PRE-AUTH KEY NEVER COMES BACK OUT. It arrives in args, goes into
//     the module's environment, and is scrubbed from every string this file
//     returns or emits — see redactKey. bootstrap/vpn/install.sh already
//     keeps it out of its own output on the happy path; redaction is here
//     for the paths nobody planned, like a `tailscale up` that fails and
//     prints its own argv.
//
// What this verb deliberately does NOT do: select an exit node, or touch this
// machine's default route. That is `vpn use-exit`, a separate deliberate
// command, and the reason the line is drawn in ink is in bootstrap/vpn/
// README.md — the /link tunnel this verb arrived on is the only remote
// management path a BYOD host has, so a bad default route takes down the
// means of fixing it. AW_VPN_ACCEPT_DNS is forced off for the same family of
// reason: accepting MagicDNS rewrites the resolver, which is the lockout
// failure mode arriving through DNS instead of through routing.
package ops

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// runVPNModules is bootstrap.Run over the vpn module, indirected so a test can
// exercise this verb's real decision-making — probe, idempotence, redaction,
// state — without installing tailscale on whatever machine runs `go test`.
var runVPNModules = bootstrap.Run

// vpnStatePath is state.DefaultPath, indirected for the same reason: a test
// must not write to the invoking user's real ~/.aw-remote-host/state.json.
var vpnStatePath = state.DefaultPath

// keyPattern matches a pre-auth key wherever it might surface in captured
// output — as a `--authkey=...` argv fragment, or as a bare headscale key,
// which is a long hex string. Both forms are replaced wholesale rather than
// truncated: a prefix of a credential is still a piece of a credential, and
// nothing downstream has a use for one.
var keyPattern = regexp.MustCompile(`(?i)(--authkey[= ]\S+|\b[0-9a-f]{40,}\b)`)

// redactKey removes the pre-auth key from a string bound for the control
// plane. The exact key is replaced first (the only certain match), then the
// shape-based pattern catches a key this call did not supply — an older key
// echoed out of tailscale's own state, say.
func redactKey(s, key string) string {
	if key != "" {
		s = strings.ReplaceAll(s, key, "[redacted]")
	}
	return keyPattern.ReplaceAllString(s, "[redacted]")
}

// tail keeps the last n bytes of module output for diagnostics. A failed
// install is worth reporting; the whole transcript of one is not, and the
// interesting part of a shell failure is always at the end.
func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// VPNBootstrap installs tailscale and enrols this host in the tenant's mesh.
//
// args:
//
//	login_server    (string, required) the tenant's headscale. Never defaulted
//	                and never hardcoded — one headscale per tenant, and two
//	                headscales do not federate.
//	authkey         (string) a headscale pre-auth key. Required for a first
//	                enrolment, ignored for a node already up against the same
//	                login server. CREDENTIAL — never returned, never emitted.
//	hostname        (string, optional) node name in the mesh.
//	advertise_exit  (bool, optional) offer this node as an exit gate.
//	                Offering is not using: it does not change this machine's
//	                own routing, and a headscale admin still has to approve
//	                the 0.0.0.0/0 route before any peer can select it.
//
// Every reply carries `eligibility` in the same shape vpn_status publishes it,
// on every path out — including the refusals — so a caller never has to make a
// second round trip to find out what this host is capable of.
func (h *Handler) VPNBootstrap(ctx context.Context, args map[string]any, emit Emit) (map[string]any, error) {
	if emit == nil {
		emit = noopEmit
	}
	loginServer := strings.TrimSuffix(strings.TrimSpace(stringArg(args, "login_server")), "/")
	authKey := strings.TrimSpace(stringArg(args, "authkey"))
	nodeHostname := strings.TrimSpace(stringArg(args, "hostname"))
	advertiseExit := boolArg(args, "advertise_exit", false)

	elig := probeEligibility()
	payload := eligibilityPayload(elig)

	if loginServer == "" {
		// A caller error, not a host refusal — the distinction matters because
		// the two have different fixes and only one of them is about this
		// machine. Returned as an error so it cannot be mistaken for the host
		// declining.
		return nil, fmt.Errorf("login_server is required: this verb never defaults or hardcodes a control plane, " +
			"because the architecture is one headscale per tenant and two headscales do not federate")
	}

	// The probe's verdict comes first and is final. Refusing here rather than
	// letting install.sh discover the same thing is what keeps a half-install
	// from ever happening: the script would refuse too, but only after it had
	// already added an apt repository and pulled a package.
	if !elig.CanEnroll {
		emit("warning", "vpn", "not enrolling — "+elig.EnrollRefusal)
		return vpnRefusal(payload, elig.EnrollRefusal), nil
	}
	if advertiseExit && !elig.CanAdvertiseExit {
		emit("warning", "vpn", "not enrolling — "+elig.ExitRefusal)
		return vpnRefusal(payload, elig.ExitRefusal), nil
	}

	// ── Idempotence ──────────────────────────────────────────────────────
	// Read the live node before touching anything. "Already enrolled against
	// this same control plane" is the one case that must change nothing at
	// all, and it is the common one: it is what a second button press is.
	if bin := lookupTailscale(); bin != "" {
		runner := tailscaleRunner{inner: h.runner(), bin: bin}
		if status, err := vpn.FetchStatus(ctx, runner); err == nil && status.Running() {
			prefs, prefsErr := vpn.FetchPrefs(ctx, runner)
			if prefsErr == nil && vpn.SameLoginServer(prefs.LoginServer, loginServer) {
				emit("info", "vpn", "already enrolled as "+status.NodeName+" — nothing to do")
				out := vpnOutcome(payload, true, false, status, prefs)
				out["reason"] = "this node is already enrolled against " + loginServer + "; nothing was changed"
				return out, nil
			}
		}
	}

	// ── Enrolment ────────────────────────────────────────────────────────
	extractDir, err := h.vpnExtractDir()
	if err != nil {
		return nil, err
	}
	if err := bootstrap.ExtractScripts(extractDir); err != nil {
		return nil, fmt.Errorf("extract bootstrap scripts: %w", err)
	}
	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return nil, err
	}

	env := []string{
		vpn.EnvLoginServer + "=" + loginServer,
		vpn.EnvAuthKey + "=" + authKey,
		vpn.EnvHostname + "=" + nodeHostname,
		vpn.EnvAdvertiseExit + "=" + boolEnvValue(advertiseExit),
		// Forced, not passed through. Phase 1's contract, and not the
		// control plane's to relax remotely — see this file's header.
		vpn.EnvAcceptDNS + "=0",
	}

	emit("info", "vpn", fmt.Sprintf("enrolling against %s (advertise-exit=%t)", loginServer, advertiseExit))

	// io.Discard, not the daemon's stdout: the module's transcript is the one
	// place a credential could plausibly appear unredacted, and this process's
	// log is not a place it can be taken back out of. The captured copy in
	// ModuleStatus.Output is redacted before anything is done with it, and
	// progress the caller can see travels over emit instead.
	statuses, runErr := runVPNModules(ctx, m.Only("vpn"), bootstrap.RunOptions{
		ExtractDir: extractDir,
		Env:        env,
		Stdout:     io.Discard,
		Stderr:     io.Discard,
	})
	if runErr != nil {
		detail := ""
		for _, st := range statuses {
			detail = tail(redactKey(st.Output, authKey), 800)
		}
		emit("error", "vpn", "enrolment failed")
		out := vpnRefusal(payload, "")
		delete(out, "refused")
		delete(out, "refusal")
		out["enrolled"] = false
		out["changed"] = false
		out["error"] = redactKey(runErr.Error(), authKey)
		out["detail"] = detail
		return out, nil
	}

	// Persist the REQUEST, not the outcome — the same bargain the `vpn`
	// command makes. What the mesh actually honours is re-read live below.
	name := nodeHostname
	if name == "" {
		name, _ = os.Hostname()
	}
	if statePath, err := vpnStatePath(); err == nil {
		if st, err := state.Load(statePath); err == nil {
			st.VPN = &state.VPNState{
				LoginServer:   loginServer,
				NodeName:      name,
				AdvertiseExit: advertiseExit,
				EnrolledAt:    time.Now().UTC().Format(time.RFC3339),
			}
			// A state write that fails does not un-enrol the node, so it is
			// reported and not raised: the machine really is on the mesh, and
			// saying otherwise would be the less true of the two answers.
			if err := state.Save(statePath, st); err != nil {
				emit("warning", "vpn", "enrolled, but could not persist vpn state: "+err.Error())
			}
		}
	}

	// Re-read the node rather than reporting what was asked for. An enrolment
	// that came back OK and a node that is actually up are two different
	// claims, and only the second one is worth putting on a screen.
	var status vpn.Status
	var prefs vpn.Prefs
	if bin := lookupTailscale(); bin != "" {
		runner := tailscaleRunner{inner: h.runner(), bin: bin}
		status, _ = vpn.FetchStatus(ctx, runner)
		prefs, _ = vpn.FetchPrefs(ctx, runner)
	}
	emit("info", "vpn", "enrolled as "+status.NodeName)
	return vpnOutcome(payload, false, true, status, prefs), nil
}

// vpnRefusal is the shape of "this host will not be enrolled, and here is the
// sentence explaining why". `enrolled` and `changed` are present and false on
// purpose: a caller reading one field must not have to know which of the
// several shapes it got back.
func vpnRefusal(eligibility map[string]any, reason string) map[string]any {
	return map[string]any{
		"eligibility": eligibility,
		"enrolled":    false,
		"changed":     false,
		"refused":     true,
		"refusal":     reason,
	}
}

// vpnOutcome renders an enrolled node — either one this call enrolled, or one
// that was already enrolled before it ran.
func vpnOutcome(eligibility map[string]any, already, changed bool, status vpn.Status, prefs vpn.Prefs) map[string]any {
	return map[string]any{
		"eligibility":      eligibility,
		"enrolled":         true,
		"already_enrolled": already,
		"changed":          changed,
		"refused":          false,
		"node_name":        status.NodeName,
		"backend_state":    status.BackendState,
		"mesh_ip":          primaryMeshIP(status.MeshIPs),
		"mesh_ips":         status.MeshIPs,
		"tailnet":          status.Tailnet,
		"login_server":     prefs.LoginServer,
		"advertises_exit":  prefs.AdvertisesExit,
		"offers_exit":      status.OffersExit,
		"accepts_dns":      prefs.AcceptsDNS,
		// Reported so a reader can see for themselves that enrolment did not
		// touch the default route — the guarantee this verb makes is worth
		// more when it is checkable than when it is only documented.
		"uses_exit_node": prefs.UsesExitNode,
	}
}

// vpnExtractDir is where the embedded module scripts get written before they
// run. Opts.ExtractDir is the one the daemon sets on registration and so the
// one every other bootstrap-driven verb uses; the fallback derives the same
// path the `vpn` command does, which matters for a Handler built outside the
// link loop (a test, or any future caller that never registered).
func (h *Handler) vpnExtractDir() (string, error) {
	if h.Opts.ExtractDir != "" {
		return h.Opts.ExtractDir, nil
	}
	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(credPath), "bootstrap-scripts"), nil
}

// boolEnvValue is the "1"/"0" convention the module's env vars read. Named
// apart from cmd/aw-remote-host's boolEnv, which is the same function in the
// other package.
func boolEnvValue(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
