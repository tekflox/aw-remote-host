package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/bootstrap"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/ops"
	"github.com/tekflox/aw-remote-host/internal/state"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// runVPN is the "vpn" command: enrol this machine in the tenant's mesh, and
// (phase 2) select or clear the exit gate its default route goes through.
//
// It is a separate command rather than a flag on bootstrap-workspace because
// the vpn module is opt-in (bootstrap.Module.Optional) — joining a network is
// a decision the machine's owner makes, not a side effect of provisioning a
// workspace. The two route-changing verbs are subcommands rather than flags
// on the enrolment for the same reason, one level down: enrolling is safe and
// selecting a gate is the step that can strand the machine, so they should not
// be a typo apart.
func runVPN(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "use-exit":
			return runVPNUseExit(args[1:])
		case "clear-exit":
			return runVPNClearExit(args[1:])
		}
	}
	return runVPNEnroll(args)
}

func runVPNEnroll(args []string) error {
	fs := flag.NewFlagSet("vpn", flag.ContinueOnError)
	loginServer := fs.String("login-server", "", "the tenant's headscale control plane, e.g. https://headscale.aw.tekflox.com (required)")
	authKey := fs.String("authkey", "", "a headscale pre-auth key — required for a first enrolment, ignored once this node is already up against the same login server")
	nodeHostname := fs.String("hostname", "", "node name in the mesh (default: this machine's hostname)")
	advertiseExit := fs.Bool("advertise-exit-node", false, "offer this node as an exit gate. Advertising does NOT change this machine's own routing, and a headscale admin still has to approve the route before any peer can use it")
	acceptDNS := fs.Bool("accept-dns", false, "accept MagicDNS. Off by default: it rewrites this host's resolver, so a misbehaving headscale would stop the machine resolving the control plane")
	plan := fs.Bool("plan", false, "print what would happen, including the eligibility verdict, without changing anything")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The probe runs first and unconditionally, including under --plan. A
	// refusal is the useful output of this command on most hosts.
	elig := vpn.Resolve(vpn.Probe())
	reportEligibility(elig)

	if *plan {
		if *loginServer == "" {
			fmt.Println("[plan] --login-server is required to enrol (no default: one headscale per tenant, never hardcoded)")
			return nil
		}
		fmt.Printf("[plan] would install tailscale via %s\n", elig.Installer)
		fmt.Printf("[plan] would run: tailscale up --login-server=%s --accept-routes=false --accept-dns=%t%s\n",
			*loginServer, *acceptDNS, exitFlagPlan(*advertiseExit, elig))
		fmt.Println("[plan] would NOT select an exit node and would NOT change this machine's default route (phase 2, deliberately out of scope)")
		return nil
	}

	if !elig.CanEnroll {
		return fmt.Errorf("this host cannot be enrolled — see the reason above")
	}
	if *loginServer == "" {
		return fmt.Errorf("--login-server is required: this module never defaults or hardcodes a control plane, because the architecture is one headscale per tenant and two headscales do not federate")
	}
	if *advertiseExit && !elig.CanAdvertiseExit {
		return fmt.Errorf("--advertise-exit-node was asked for but this host cannot serve as one — %s", elig.ExitRefusal)
	}

	credPath, err := link.DefaultCredentialsPath()
	if err != nil {
		return err
	}
	extractDir := extractDirFor(credPath)
	if err := bootstrap.ExtractScripts(extractDir); err != nil {
		return fmt.Errorf("extract bootstrap scripts: %w", err)
	}
	m, err := bootstrap.LoadEmbeddedManifest()
	if err != nil {
		return err
	}

	env := []string{
		vpn.EnvLoginServer + "=" + *loginServer,
		vpn.EnvAuthKey + "=" + *authKey,
		vpn.EnvHostname + "=" + *nodeHostname,
		vpn.EnvAdvertiseExit + "=" + boolEnv(*advertiseExit),
		vpn.EnvAcceptDNS + "=" + boolEnv(*acceptDNS),
	}
	ctx := context.Background()
	statuses, err := bootstrap.Run(ctx, m.Only("vpn"), bootstrap.RunOptions{ExtractDir: extractDir, Env: env})
	reportStatuses(statuses)
	if err != nil {
		return err
	}

	// Persist the REQUEST, not the outcome — same bargain as HostPower. What
	// the mesh actually honours is re-read live by `status`.
	statePath, err := state.DefaultPath()
	if err != nil {
		return err
	}
	st, err := state.Load(statePath)
	if err != nil {
		return err
	}
	name := *nodeHostname
	if name == "" {
		name, _ = os.Hostname()
	}
	st.VPN = &state.VPNState{
		LoginServer:   strings.TrimSuffix(*loginServer, "/"),
		NodeName:      name,
		AdvertiseExit: *advertiseExit,
		EnrolledAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := state.Save(statePath, st); err != nil {
		return fmt.Errorf("enrolled, but could not persist vpn state: %w", err)
	}

	reportVPNStatus(ctx, st)
	return nil
}

func boolEnv(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func exitFlagPlan(want bool, elig vpn.Eligibility) string {
	if !want {
		return ""
	}
	if !elig.CanAdvertiseExit {
		return " (--advertise-exit-node REFUSED on this host)"
	}
	return " --advertise-exit-node"
}

func reportEligibility(e vpn.Eligibility) {
	h := e.Host
	fmt.Printf("vpn: host is %s/%s%s, uid %d%s\n",
		h.OS, h.Arch, wslNote(h.WSL), h.UID, sudoNote(h))
	fmt.Printf("vpn: %s\n", e.Describe())
}

func wslNote(wsl bool) string {
	if wsl {
		return " (WSL2)"
	}
	return ""
}

func sudoNote(h vpn.Host) string {
	switch {
	case h.UID == 0:
		return " (root)"
	case h.PasswordlessSudo:
		return " (passwordless sudo)"
	default:
		return " (no root, no passwordless sudo)"
	}
}

// reportVPNStatus prints this node's live mesh membership.
//
// The peer path — direct vs relayed — is the part that earns its place here.
// Measured 2026-08-25: aw-mac and aw-surface-wsl sit on the same home network
// behind the same public IP and still talk via DERP(mad), because the Surface
// is WSL2 and therefore behind a second layer of NAT. A relay is a normal
// outcome, not a rare fallback, and without this line "it works, but every
// packet goes to Madrid and back" is invisible.
func reportVPNStatus(ctx context.Context, st *state.State) {
	elig := vpn.Resolve(vpn.Probe())

	if st.VPN == nil && elig.Host.TailscalePath == "" {
		// Not enrolled and no client installed: say what this host WOULD be
		// allowed to do, since that is the question the mesh UI will ask.
		fmt.Printf("vpn: not enrolled — %s\n", elig.Describe())
		return
	}
	if st.VPN != nil {
		fmt.Printf("vpn: enrolled as %q against %s%s\n",
			st.VPN.NodeName, st.VPN.LoginServer, enrolledAtNote(st.VPN.EnrolledAt))
	}

	status, err := vpn.FetchStatus(ctx, ops.DefaultRunner)
	if err != nil {
		fmt.Printf("vpn: could not read tailscale status: %v\n", err)
		return
	}
	if !status.Running() {
		fmt.Printf("vpn: node is NOT up (BackendState=%s)\n", status.BackendState)
		return
	}

	fmt.Printf("vpn: node %s (%s) %s on tailnet %s\n",
		status.NodeName, strings.Join(status.MeshIPs, ", "),
		onlineWord(status.Online), status.Tailnet)

	// Requested vs effective, the hostpower doctrine applied to exit nodes.
	// An advertised route that headscale has not approved leaves a node
	// sitting in a half-done state indefinitely, and nothing else says so.
	//
	// "Advertised" is read from the node's LIVE prefs rather than from the
	// stored request, because the module can also be driven straight from the
	// control plane, with nothing on this side writing state. Falling back to
	// state only when prefs cannot be read keeps the reporting honest either
	// way rather than silent on the path that skipped this binary.
	prefs, prefsErr := vpn.FetchPrefs(ctx, ops.DefaultRunner)
	advertised := prefs.AdvertisesExit
	if prefsErr != nil {
		advertised = st.VPN != nil && st.VPN.AdvertiseExit
	}
	switch {
	case status.OffersExit:
		fmt.Println("vpn: offers itself as an exit node (route advertised AND approved)")
	case advertised:
		fmt.Println("vpn: exit node ADVERTISED BUT NOT APPROVED — no peer can select this host until a headscale admin approves its 0.0.0.0/0 route")
	case st.VPN != nil && st.VPN.AdvertiseExit:
		// Asked for at enrolment, not advertised now: something reset it.
		fmt.Println("vpn: exit node was REQUESTED at enrolment but this node is not advertising one — re-run 'aw-remote-host vpn --advertise-exit-node'")
	}

	// Phase 2: which gate is in force, what the REAL egress IP is, what is
	// pinned outside the tunnel, and whether a revert is pending. Reported
	// unconditionally — including when nothing is selected — because the
	// dangerous states are the leftover ones, and a status that only speaks
	// up when it has good news is how they stay invisible.
	reportExitStatus(ctx, prefs, prefsErr, st)

	if prefsErr == nil && !SameOrEmpty(prefs.LoginServer, stateLoginServer(st)) {
		fmt.Printf("vpn: NOTE — this node answers to %s, but local state records %s\n",
			prefs.LoginServer, stateLoginServer(st))
	}

	if len(status.Peers) == 0 {
		fmt.Println("vpn: no peers")
		return
	}
	for _, p := range status.Peers {
		fmt.Printf("vpn:   peer %-20s %-15s %s%s\n",
			p.Name, firstIP(p.IPs), p.PathDescription(), offersExitNote(p.OffersExit))
	}
}

func stateLoginServer(st *state.State) string {
	if st.VPN == nil {
		return ""
	}
	return st.VPN.LoginServer
}

// SameOrEmpty is SameLoginServer with "nothing recorded locally" treated as
// agreement — a node enrolled by the control plane has no local state to
// disagree with, and flagging that as drift would cry wolf on the normal path.
func SameOrEmpty(live, stored string) bool {
	if stored == "" {
		return true
	}
	return vpn.SameLoginServer(live, stored)
}

func onlineWord(online bool) string {
	if online {
		return "online"
	}
	return "OFFLINE"
}

func enrolledAtNote(ts string) string {
	if ts == "" {
		return ""
	}
	return " (since " + ts + ")"
}

func firstIP(ips []string) string {
	if len(ips) == 0 {
		return "-"
	}
	return ips[0]
}

func offersExitNote(offers bool) string {
	if offers {
		return "  [offers exit node]"
	}
	return ""
}
