package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// An OpenVPN profile is refused by PlanExternalUp before it looks up a single
// binary or makes a single shellout, which is what makes it the one profile
// these tests can plan with on any machine: nothing here touches the routing,
// the interfaces or the state of whatever runs `go test`.
const openVPNProfileJSON = `{
  "type": "openvpn",
  "iface": "tun0",
  "private_key": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
  "address": ["10.5.0.2/32"],
  "peer": {
    "public_key": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
    "endpoint": "1.2.3.4:1194",
    "allowed_ips": ["0.0.0.0/0"]
  }
}`

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// The exit code is the contract. The workspace drives this host through the
// exec bridge, which runs a command and reads its status — so a host that
// REFUSES must not look like a host that succeeded. The JSON object is still
// printed on stdout either way; what must not happen is a zero exit next to a
// "refused": true.
//
// Regression: the first cut of the --json plan path returned printJSON's own
// (nil) error and exited 0 while printing a refusal.
func TestExternalUpPlanExitsNonZeroOnARefusal(t *testing.T) {
	path := writeProfile(t, openVPNProfileJSON)
	for _, args := range [][]string{
		{"--profile-json", path, "--plan"},
		{"--profile-json", path, "--plan", "--json"},
	} {
		err := runVPNExternalUp(args)
		if err == nil {
			t.Fatalf("a refused plan exited 0 for %v", args)
		}
		if !strings.Contains(err.Error(), "OpenVPN") {
			t.Fatalf("the refusal did not survive to the exit status: %v", err)
		}
	}
}

// The flag names ARE the contract the workspace core calls:
//
//	aw-remote-host vpn external-up --profile-json <path> [--table N]
//	    [--iface wg0] [--deadman-s 120] [--json]
//
// Renaming one silently breaks a caller that lives in a different repo, so the
// spelling is asserted rather than assumed.
func TestExternalUpAcceptsTheFlagsTheWorkspaceCalls(t *testing.T) {
	path := writeProfile(t, openVPNProfileJSON)
	err := runVPNExternalUp([]string{
		"--profile-json", path, "--table", "200", "--iface", "wg0",
		"--deadman-s", "120", "--confirm-s", "45", "--json", "--plan",
	})
	// The refusal is expected — an unknown flag would fail differently, and
	// that difference is the assertion.
	if err == nil || !strings.Contains(err.Error(), "OpenVPN") {
		t.Fatalf("a documented flag was not accepted: %v", err)
	}
}

// --profile-json is required and the error has to say what the file holds:
// this command never takes a wg-quick config as text, and an operator who
// reaches for one needs to be told why rather than told "missing flag".
func TestExternalUpRequiresAProfilePath(t *testing.T) {
	err := runVPNExternalUp(nil)
	if err == nil || !strings.Contains(err.Error(), "--profile-json") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "structured fields") {
		t.Fatalf("the error does not say what the file holds: %v", err)
	}
}

// A profile that smuggles an executable directive is refused by the CLI too,
// and it is refused by the SAME parser the link verb uses — this path must not
// grow a second, laxer decode.
func TestExternalUpRefusesASmuggledDirectiveFromTheCommandLine(t *testing.T) {
	path := writeProfile(t, strings.Replace(openVPNProfileJSON,
		`"type": "openvpn",`, `"type": "openvpn", "post_up": "id > /tmp/pwned",`, 1))
	err := runVPNExternalUp([]string{"--profile-json", path, "--plan"})
	if err == nil {
		t.Fatal("a profile carrying post_up was accepted from the command line")
	}
	if strings.Contains(err.Error(), "OpenVPN") {
		t.Fatalf("the profile was parsed before its unknown key was noticed: %v", err)
	}
}

// The external-tunnel subcommands have to be reachable from `vpn <sub>`. One
// that exists as a function but is not in runVPN's switch is a feature the
// workspace cannot call, which is indistinguishable from one never written.
func TestExternalSubcommandsAreRoutedFromVPN(t *testing.T) {
	path := writeProfile(t, openVPNProfileJSON)
	err := runVPN([]string{"external-up", "--profile-json", path, "--plan"})
	if err == nil || !strings.Contains(err.Error(), "OpenVPN") {
		t.Fatalf("`vpn external-up` is not routed: %v", err)
	}
	// external-route's own routing, checked on the argument error it gives
	// with no container — reaching that message means the subcommand was
	// dispatched rather than swallowed by the enrolment path.
	err = runVPN([]string{"external-route"})
	if err == nil || !strings.Contains(err.Error(), "vpn external-route <container>") {
		t.Fatalf("`vpn external-route` is not routed: %v", err)
	}
}

// The usage block and the flags it describes live in the same file so they
// cannot drift; this is the assertion that they did not.
func TestUsageDocumentsEveryExternalSubcommand(t *testing.T) {
	for _, want := range []string{
		"vpn external-up", "vpn external-down",
		"vpn external-route", "vpn external-unroute",
		"--profile-json", "--deadman-s", "--json",
	} {
		if !strings.Contains(vpnExternalUsage, want) {
			t.Fatalf("usage does not mention %q", want)
		}
	}
}

// `vpn external-status --json` is the exact command the workspace core calls.
// It must be routed, take --json, and — unlike external-up — exit 0 even when
// the answer is "nothing is up", because that is a true answer to this
// question rather than a failure to answer it.
func TestExternalStatusIsRoutedAndSucceedsOnAnIdleHost(t *testing.T) {
	if err := runVPN([]string{"external-status", "--json", "--skip-egress"}); err != nil {
		t.Fatalf("`vpn external-status --json` failed on a host with no tunnel: %v", err)
	}
	if err := runVPNExternalStatus([]string{"--skip-egress"}); err != nil {
		t.Fatalf("the human rendering failed: %v", err)
	}
}

// The CLI's JSON and the link verb's payload are two hand-built maps of the
// same struct. The workspace parses whichever surface it reached, so they must
// not disagree about what a field is called — asserted here rather than hoped
// for.
func TestStatusJSONCarriesEveryContractedKey(t *testing.T) {
	blob, err := json.Marshal(externalStatusJSON(vpn.ExternalStatusReport{Iface: "wg0", Table: 200}))
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
			t.Fatalf("the CLI's --json is missing the contracted key %q: %s", key, blob)
		}
	}
	if decoded["container"] != nil || decoded["since"] != nil {
		t.Fatalf("unset fields must be null, not empty strings: %s", blob)
	}
}
