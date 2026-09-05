package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/ops"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// The external-tunnel half of the vpn command:
//
//	vpn external-up / external-down       dial a tunnel, and take it down
//	vpn external-route / external-unroute point ONE container at it, and off
//
// WHY BOTH A CLI AND A LINK VERB. The /link plane reaches these as
// vpn_external_up / vpn_external_down / vpn_external_route /
// vpn_external_unroute (internal/ops), and that is the path a control plane
// uses. The COMMAND LINE is the path the workspace itself uses: it drives this
// through the exec bridge, which runs a command, not a link verb. Neither is a
// convenience wrapper on the other and both have to exist — a feature that
// only has the verb is unreachable from the workspace, and one that only has
// the command is invisible to the control plane.
//
// The SEQUENCE lives in internal/vpn (externalup.go, externalroute.go), never
// here, for the same reason use-exit's does: two copies of a sequence that
// changes routing would drift, and the copy that drifted would be the one
// nobody was watching.

// runVPNExternalUp is `vpn external-up`.
//
// The contract the workspace core calls is exactly:
//
//	aw-remote-host vpn external-up --profile-json <path> [--table N]
//	    [--iface wg0] [--deadman-s 120] [--json]
//
// --profile-json points at a 0600 JSON file holding STRUCTURED FIELDS ONLY.
// There is no flag, and no field, that can carry PostUp/PostDown/PreUp/
// PreDown/Table/FwMark, and none may ever be added: wg-quick runs PostUp as
// root, so the .conf this tool runs is synthesized from typed fields rather
// than accepted as text. See internal/vpn/externalup.go's header.
func runVPNExternalUp(args []string) error {
	fs := flag.NewFlagSet("vpn external-up", flag.ContinueOnError)
	profilePath := fs.String("profile-json", "", "path to a 0600 JSON file holding the VPN profile as STRUCTURED FIELDS (required). A wg-quick config as text is never accepted — wg-quick runs PostUp as root, so the config this tool runs is synthesized from typed fields")
	iface := fs.String("iface", "", "interface to bring up (default: the profile's own, then wg0)")
	table := fs.Int("table", 0, "routing table to build the tunnel's default in (default 200 — the same table `vpn external-route` points a container at)")
	deadmanS := fs.Int("deadman-s", 0, "seconds before an unconfirmed dial tears itself down and flushes the table (default 120)")
	confirmS := fs.Int("confirm-s", 0, "seconds to keep trying to confirm the tunnel before giving up and reverting (default 45)")
	asJSON := fs.Bool("json", false, "print one machine-readable object on stdout and nothing else")
	plan := fs.Bool("plan", false, "resolve everything, print it, and change NOTHING")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*profilePath) == "" {
		return fmt.Errorf("--profile-json is required: it names a 0600 JSON file holding the profile as structured fields (type, iface, private_key, address, dns, mtu, peer)")
	}

	profile, warning, err := vpn.LoadExternalProfile(*profilePath)
	if err != nil {
		return err
	}

	spec := vpn.ExternalUpSpec{
		Profile:        profile,
		Iface:          *iface,
		Table:          *table,
		Deadman:        secondsFlag(*deadmanS),
		ConfirmTimeout: secondsFlag(*confirmS),
		Runner:         externalRunner(),
	}
	ctx := context.Background()

	if *plan {
		resolved, err := vpn.PlanExternalUp(ctx, spec)
		if err != nil {
			return err
		}
		if *asJSON {
			if err := printJSON(map[string]any{"planned": resolved.Refusal == "", "refused": resolved.Refusal != "", "refusal": resolved.Refusal, "plan": resolved, "warning": warning}); err != nil {
				return err
			}
		} else {
			printExternalUpPlan(*resolved, warning)
		}
		// A refusal exits NON-ZERO on both renderings. The object is printed
		// either way — a caller that parses stdout still gets the sentence —
		// but "this host cannot do this" must not look like success to a shell
		// that only checks the exit code, which is what the workspace's exec
		// bridge does.
		if resolved.Refusal != "" {
			return fmt.Errorf("%s", resolved.Refusal)
		}
		return nil
	}

	if warning != "" && !*asJSON {
		printProgress("warning", warning)
	}
	res, runErr := vpn.ExternalUp(ctx, spec, jsonAwareProgress(*asJSON))
	if *asJSON {
		payload := res.Payload()
		if warning != "" {
			payload["warning"] = warning
		}
		if runErr != nil {
			payload["refused"] = strings.Contains(runErr.Error(), vpn.ErrScopeRefused.Error())
			if payload["reason"] == "" {
				payload["reason"] = runErr.Error()
			}
			if payload["refused"] == true {
				payload["refusal"] = payload["reason"]
			}
		}
		if err := printJSON(payload); err != nil {
			return err
		}
	}
	return runErr
}

// runVPNExternalDown is `vpn external-down`.
//
// It undoes what was RECORDED, not what a fresh resolve would produce — see
// vpn.ExternalDown. --iface/--table are a fallback for a tunnel this tool lost
// track of, and the reply says which of the two happened.
func runVPNExternalDown(args []string) error {
	fs := flag.NewFlagSet("vpn external-down", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface to take down IF nothing is recorded (default wg0). Ignored when a dial is on record")
	table := fs.Int("table", 0, "routing table to clear IF nothing is recorded (default 200). Ignored when a dial is on record")
	asJSON := fs.Bool("json", false, "print one machine-readable object on stdout and nothing else")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, runErr := vpn.ExternalDown(context.Background(), vpn.ExternalUpSpec{
		Runner: externalRunner(),
		Iface:  *iface,
		Table:  *table,
	}, jsonAwareProgress(*asJSON))
	if *asJSON {
		payload := res.Payload()
		if runErr != nil && payload["reason"] == "" {
			payload["reason"] = runErr.Error()
		}
		if err := printJSON(payload); err != nil {
			return err
		}
	}
	return runErr
}

// runVPNExternalRoute is `vpn external-route <container>` — a thin wrapper
// over the engine that has been in internal/vpn/externalroute.go since
// 2026-09-02 and until now had no command line at all, only the link verb.
//
// That gap is why this exists: the workspace drives this host through the exec
// bridge, which runs commands, so an engine reachable only as a link verb was
// unreachable from the thing that needs it.
func runVPNExternalRoute(args []string) error {
	fs := flag.NewFlagSet("vpn external-route", flag.ContinueOnError)
	controlPlane := fs.String("control-plane", defaultControlPlane, "control plane base URL — its addresses are held outside the tunnel")
	table := fs.Int("table", 0, "routing table carrying the tunnel's default (default 200)")
	priority := fs.Int("priority", 0, "ip rule priority (default 5399)")
	expectEgress := fs.String("expect-egress", "", "the public IP the tunnel should present. Given, confirmation is an exact match; omitted, confirmation is that the container's address CHANGED and this host's did not")
	deadmanS := fs.Int("deadman-s", 0, "seconds before an unconfirmed route reverts itself (default 120)")
	confirmS := fs.Int("confirm-s", 0, "seconds to keep trying to confirm (default 45)")
	asJSON := fs.Bool("json", false, "print one machine-readable object on stdout and nothing else")
	plan := fs.Bool("plan", false, "resolve everything, print it, and change NOTHING")

	// The container is lifted out before flag parsing, for the reason
	// runVPNUseExit spells out: Go's flag package stops at the first non-flag
	// argument, so `external-route aw-workspace --plan` would parse zero flags
	// and silently treat --plan as a positional — which is exactly how a human
	// types it, and on a command that changes routing "the safety flag was
	// ignored" is not an acceptable way to find that out.
	wanted, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if wanted == "" && fs.NArg() == 1 {
		wanted = fs.Arg(0)
	}
	if wanted == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: aw-remote-host vpn external-route <container> [flags] — <container> is a name or id as THIS host's runtime knows it")
	}

	spec := vpn.ExternalRouteSpec{
		Container:      wanted,
		Runner:         externalRunner(),
		Table:          *table,
		Priority:       *priority,
		ExpectEgress:   *expectEgress,
		Deadman:        secondsFlag(*deadmanS),
		ConfirmTimeout: secondsFlag(*confirmS),
		ControlPlane:   *controlPlane,
	}
	ctx := context.Background()

	if *plan {
		resolved, err := vpn.PlanExternalRoute(ctx, spec)
		if err != nil {
			return err
		}
		if *asJSON {
			if err := printJSON(map[string]any{"planned": resolved.Refusal == "", "refused": resolved.Refusal != "", "refusal": resolved.Refusal, "plan": resolved}); err != nil {
				return err
			}
			if resolved.Refusal != "" {
				return fmt.Errorf("%s", resolved.Refusal)
			}
			return nil
		}
		if resolved.Refusal != "" {
			fmt.Printf("vpn: REFUSED — %s\n", resolved.Refusal)
			return fmt.Errorf("%s", resolved.Refusal)
		}
		fmt.Printf("vpn: would route %s (%s/32) out through %s via table %d at priority %d\n",
			resolved.Container, resolved.SourceIP, resolved.TunnelDev, resolved.Table, resolved.Priority)
		for _, ex := range resolved.Exclusions {
			fmt.Printf("vpn:   %s stays OUTSIDE the tunnel\n", ex)
		}
		fmt.Println("vpn: this MACHINE's own public IP would NOT change. That is asserted, not hoped for: a host whose address moved is a failed apply that reverts.")
		return nil
	}

	res, runErr := vpn.ExternalRoute(ctx, spec, jsonAwareProgress(*asJSON))
	if *asJSON {
		payload := externalRouteJSON(res)
		if runErr != nil {
			payload["refused"] = strings.Contains(runErr.Error(), vpn.ErrScopeRefused.Error())
			if payload["reason"] == "" {
				payload["reason"] = runErr.Error()
			}
		}
		if err := printJSON(payload); err != nil {
			return err
		}
	}
	return runErr
}

// runVPNExternalUnroute is `vpn external-unroute`. It takes no container
// argument on purpose — it undoes what was RECORDED, not what a fresh resolve
// would produce, because the container's address is runtime IPAM and moves
// whenever it is recreated.
func runVPNExternalUnroute(args []string) error {
	fs := flag.NewFlagSet("vpn external-unroute", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print one machine-readable object on stdout and nothing else")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, runErr := vpn.ExternalUnroute(context.Background(), vpn.ExternalRouteSpec{Runner: externalRunner()}, jsonAwareProgress(*asJSON))
	if *asJSON {
		payload := externalRouteJSON(res)
		if runErr != nil && payload["reason"] == "" {
			payload["reason"] = runErr.Error()
		}
		if err := printJSON(payload); err != nil {
			return err
		}
	}
	return runErr
}

// externalRunner is the privileged shellout both external paths need, and it
// is the same bargain the `vpn_external_route` verb makes: `sudo -n` never
// prompts, so a host with neither root nor a NOPASSWD entry fails immediately
// and loudly instead of hanging on a password prompt nobody is watching.
// Never PrivilegedRunner's zero value — its Inner is nil and panics.
func externalRunner() vpn.Runner {
	host := vpn.Probe()
	return vpn.PrivilegedRunner{Inner: ops.DefaultRunner, Sudo: host.OS != "darwin" && host.UID != 0}
}

// jsonAwareProgress silences the human narration under --json.
//
// The contract is that --json prints ONE object on stdout and the workspace
// parses it; a narration line interleaved with it would make that parse fail
// on exactly the runs that had the most to say. Under --json the narration is
// not lost, it is in the object's own fields.
func jsonAwareProgress(asJSON bool) vpn.Progress {
	if asJSON {
		return nil
	}
	return printProgress
}

func printJSON(payload map[string]any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// externalRouteJSON is the CLI's rendering of an ExternalRouteResult. It
// mirrors internal/ops' externalRoutePayload field for field on purpose: the
// workspace parses whichever surface it reached, and the two must not disagree
// about what a field is called.
func externalRouteJSON(res vpn.ExternalRouteResult) map[string]any {
	return map[string]any{
		"container":        res.Plan.Container,
		"source_ip":        res.Plan.SourceIP,
		"table":            res.Plan.Table,
		"priority":         res.Plan.Priority,
		"tunnel_dev":       res.Plan.TunnelDev,
		"exclusions":       res.Plan.Exclusions,
		"host_before":      res.HostBefore,
		"host_after":       res.HostAfter,
		"host_held":        res.HostHeld,
		"host_moved":       res.HostMoved,
		"container_before": res.ContainerBefore,
		"container_after":  res.ContainerAfter,
		"confirmed":        res.Confirmed,
		"reverted":         res.Reverted,
		"reason":           res.Reason,

		"deadman_expires_at":  res.DeadmanExpiresAt,
		"deadman_still_armed": res.DeadmanStillArmed,
	}
}

// secondsFlag turns the --deadman-s / --confirm-s integers into durations. 0
// stays 0 so internal/vpn's own defaults apply, rather than this file having a
// second copy of them that could drift.
func secondsFlag(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func printExternalUpPlan(p vpn.ExternalUpPlan, warning string) {
	if warning != "" {
		printProgress("warning", warning)
	}
	if p.Refusal != "" {
		fmt.Printf("vpn: REFUSED — %s\n", p.Refusal)
		fmt.Println("vpn: what follows is a read-only preview; applying it on this host is not possible.")
	}
	fmt.Printf("vpn: would dial %s on %s, building table %d\n", p.Endpoint, p.Iface, p.Table)
	if p.AlreadyUp {
		fmt.Println("vpn: this exact profile is ALREADY up in that table — a re-run would converge and change nothing")
	}
	fmt.Printf("vpn: would write a synthesized config to %s (0600), with Table = off so wg-quick installs no routes of its own\n", p.ConfPath)
	fmt.Println("vpn: table would be built in THIS ORDER — connected routes first, endpoint pin, default LAST:")
	for _, c := range p.Connected {
		fmt.Printf("vpn:   %-20s dev %s   (discovered from this host's main table, never hardcoded)\n", c.Prefix, c.Dev)
	}
	if p.EndpointIP != "" {
		fmt.Printf("vpn:   %-20s via %s dev %s onlink   (the tunnel endpoint, so its own packets cannot route into it)\n", p.EndpointIP+"/32", p.MainGateway, p.MainDev)
	}
	fmt.Printf("vpn:   %-20s dev %s\n", "default", p.Iface)
	if len(p.DNS) > 0 {
		fmt.Printf("vpn: the profile's resolvers (%s) would be RECORDED and NOT written into the config — wg-quick's DNS= rewrites the whole host's resolver\n", strings.Join(p.DNS, ", "))
	}
	fmt.Println("vpn: would arm a dead-man's switch BEFORE the first route change, reverting with `wg-quick down` plus a flush of that table if this run does not confirm the tunnel")
	fmt.Println("vpn: this MACHINE's own public IP would NOT change. That is asserted before and after, and a host whose address moved is a failed apply that reverts.")
}

// vpnExternalUsage is printed by the top-level usage; kept next to the flags
// it describes so the two cannot drift. Trimmed of newlines only, never
// TrimSpace: the leading indent on the first line is what lines it up with the
// command list it is spliced into.
var vpnExternalUsage = strings.Trim(`
  vpn external-up       DIAL an external WireGuard tunnel on this host. The
                        config is SYNTHESIZED from the structured fields in
                        --profile-json and never accepted as text, because
                        wg-quick runs PostUp as root. Table = off; this tool
                        builds the tunnel's table itself, connected routes
                        FIRST and the default LAST, so a container pointed at
                        that table never loses its sibling containers. Arms a
                        dead-man's switch before the first route change and
                        stands it down only once the tunnel has handshaked.
                        THIS MACHINE'S OWN PUBLIC IP DOES NOT CHANGE — asserted
                        before and after. Re-running for the same profile
                        converges instead of re-applying.
      --profile-json    path to a 0600 JSON file of typed fields (required)
      --iface           interface to bring up (default: profile's, then wg0)
      --table           routing table to build (default 200)
      --deadman-s       unconfirmed dials tear down after this (default 120)
      --confirm-s       how long to wait for a handshake (default 45)
      --json            print one machine-readable object and nothing else
      --plan            resolve and print everything, change nothing

  vpn external-down     Take the RECORDED tunnel back down and remove the
                        routes that dial installed. --iface/--table are a
                        fallback used only when nothing is recorded.

  vpn external-route <container>
                        Point ONE container's egress at a tunnel this host
                        already terminates, with a /32 rule, a dead-man's
                        switch and a confirmation of both halves. Refuses
                        anything wider than a single host address.
      --expect-egress   the public IP the tunnel should present (exact match)
      --table/--priority/--deadman-s/--confirm-s/--json/--plan

  vpn external-unroute  Remove the recorded rule and its exclusions.
`, "\n")
