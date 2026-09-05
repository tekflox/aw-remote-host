// Bringing an external WireGuard tunnel UP on this host, and taking it back
// down — the DIALLER.
//
// externalroute.go points ONE container at a tunnel that is already up.
// deadman.go undoes a switch nobody saw made. Neither of them has ever brought
// a tunnel up, and that was the whole gap: on this deployment the tunnel the
// containers were meant to leave through had to already exist, put there by
// something else. This file is that missing half, and it is a SIBLING of
// ExternalRoute rather than a caller of it — dialling and routing are
// separately reversible, and an operator reading a run log has to be able to
// tell which of the two happened.
//
// THE CONFIG IS SYNTHESIZED FROM TYPED FIELDS, NEVER ACCEPTED AS TEXT.
// wg-quick runs PostUp/PostDown as root, so a .conf accepted as a blob is a
// remote root shell wearing a VPN profile's clothes. ExternalProfile therefore
// has NO field that can carry PostUp, PostDown, PreUp, PreDown, Table, FwMark
// or SaveConfig; unknown JSON keys are REJECTED rather than ignored, every
// value is parsed into its own type before it is rendered, and the rendered
// text is asserted against a denylist before it reaches disk. That is a
// structural closure rather than a filter: a config assembled from a private
// key, an address list and a peer cannot smuggle a command, whatever the
// caller sends.
//
// THE INVARIANTS, each one a way this takes a production deployment off the
// network, and each one measured rather than feared:
//
//  1. THE TABLE CARRIES THE CONNECTED ROUTES BEFORE THE DEFAULT. The rule
//     externalroute.go installs — `ip rule from <container>/32 lookup N` —
//     matches ALL of that container's egress, including its traffic to sibling
//     containers. A table holding only `default dev wg0` therefore takes
//     Postgres, Redis and every agent runner away from the container it was
//     supposed to help. Measured 2026-09-05: the workspace container is
//     10.89.0.4 and its peers are all on 10.89.0.0/24 dev podman1, with
//     172.18.0.0/16 dev eth0 alongside. The precedent is already in this
//     codebase — repos/aw-stack/scripts/vpn-hub-entrypoint.sh:224-227 installs
//     a route per local bridge next to its default — and that same script's
//     header records that HARDCODING a bridge name is what put wg-quick into a
//     619-restart crash loop leaking 3,714 iptables rules. So the connected
//     routes are DISCOVERED from the live main table on every apply, the way
//     its discover_bridge does, never named in this file; and a discovery that
//     comes back empty is a refusal, because installing the default alone is
//     precisely the catastrophic case.
//
//  2. `Table = off` IN THE SYNTHESIZED CONFIG. wg-quick's own route
//     installation is the one thing that must not happen here: it would put an
//     0.0.0.0/0 into the MAIN table and move the host. The table is built
//     explicitly, below, and nowhere else.
//
//  3. THE ENDPOINT IS PINNED /32 THROUGH THE HOST'S REAL GATEWAY BEFORE THE
//     TUNNEL DEFAULT EXISTS, or a routed container's packets to the endpoint
//     route into the tunnel that carries them. It is spelled by
//     ExternalRoutePlan.excludeArgs — the same code, not a copy — because that
//     is where `onlink` lives, and onlink is not cargo cult: this deployment's
//     Hetzner-style layout answers `Error: Nexthop has invalid gateway.`
//     without it, and the exclusion then silently never installs.
//
//  4. THE DEAD-MAN'S SWITCH IS ARMED BEFORE THE FIRST ROUTE CHANGE and stood
//     down only once the tunnel is confirmed up. Its revert tears the tunnel
//     down AND flushes the table, in POSIX sh with absolute paths, and — as
//     deadman.go's own comment demands — it never calls this binary.
//
//  5. THE HOST'S OWN PUBLIC IP MUST NOT CHANGE. Asserted before and after,
//     exactly as ExternalRoute asserts it. A host whose address moved is a
//     failed apply that reverts, whatever the tunnel is doing.
package vpn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tekflox/aw-remote-host/internal/homedir"
	"github.com/tekflox/aw-remote-host/internal/state"
)

// DefaultExternalIface is the interface name used when neither the caller nor
// the profile names one. wg0 is what every provider's exported profile calls
// it and what table 200's default has always pointed at here.
const DefaultExternalIface = "wg0"

// lookupExternalBinary resolves the tools this file shells out to, as absolute
// paths, at plan time.
//
// Absolute and resolved EARLY for the reason ArmSpec.TailscalePath spells out:
// the dead-man's revert runs in a shell with whatever PATH it inherits, on a
// machine that has just lost its default route, and that is the worst possible
// moment to discover a binary is not where it was assumed to be. Indirected so
// a test does not depend on whether the machine running `go test` happens to
// have wireguard-tools installed.
var lookupExternalBinary = exec.LookPath

// ExternalProfile is a VPN profile as STRUCTURED FIELDS. It is the whole
// security model of this file: there is deliberately no field that can carry
// PostUp, PostDown, PreUp, PreDown, Table, FwMark or SaveConfig, and none may
// ever be added — see the file header.
type ExternalProfile struct {
	// Type is "wireguard" or "openvpn". Only wireguard is implemented; see
	// PlanExternalUp for the refusal openvpn gets and why it is a refusal
	// rather than a half-build.
	Type string `json:"type"`
	// Iface is the interface name to bring up. Optional; the caller's --iface
	// wins over it and DefaultExternalIface backs both.
	Iface string `json:"iface,omitempty"`
	// PrivateKey is this side's WireGuard key, base64 of 32 bytes. It is
	// written to the synthesized config and NEVER anywhere else — not to a
	// log, not to a progress line, not to the JSON reply, not to state.json.
	PrivateKey string `json:"private_key"`
	// Address is this side's tunnel address(es), as CIDRs.
	Address []string `json:"address"`
	// DNS is the provider's resolver list. It is validated and reported, and
	// deliberately NOT rendered into the config — see synthesizeWireGuard.
	DNS []string `json:"dns,omitempty"`
	// MTU is optional; 0 means "let wg-quick decide".
	MTU  int            `json:"mtu,omitempty"`
	Peer ExternalWGPeer `json:"peer"`
}

// ExternalWGPeer is the far side of the tunnel.
type ExternalWGPeer struct {
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	// Endpoint is host:port. The host half may be a name; it is resolved at
	// plan time because the /32 pin needs an address, not a name.
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

var ifaceNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)

// endpointHostPattern is deliberately narrower than DNS allows. Everything
// accepted here is safe inside an `Endpoint = ` line and safe as an argument;
// a name this rejects is a name nobody dials a VPN on.
var endpointHostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// ParseExternalProfile decodes a profile and refuses anything it does not
// understand.
//
// DisallowUnknownFields is the load-bearing line. Ignoring an unknown key
// would mean a caller could send `"post_up": "..."` today, see it accepted,
// and a future field of that name would then be honoured — the exact way a
// closed hole reopens. An unknown key is an error with the key named in it.
func ParseExternalProfile(raw []byte) (ExternalProfile, error) {
	var p ExternalProfile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return ExternalProfile{}, fmt.Errorf("the VPN profile could not be read as the structured form this tool accepts (%w) — it takes typed fields, never a wg-quick config as text, because wg-quick runs PostUp as root", err)
	}
	if dec.More() {
		return ExternalProfile{}, fmt.Errorf("the VPN profile file carries more than one JSON document, and this tool dials exactly one tunnel")
	}
	if err := p.validate(); err != nil {
		return ExternalProfile{}, err
	}
	return p, nil
}

// LoadExternalProfile reads and parses a profile file.
//
// The file's mode is REPORTED rather than enforced. It holds a private key and
// the contract is that the caller writes it 0600, but a tool that refuses to
// dial because a control plane wrote 0644 fails in the direction that leaves
// the operator with no VPN and no explanation; saying so loudly and dialling
// anyway keeps the fact visible without making it fatal.
func LoadExternalProfile(path string) (ExternalProfile, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ExternalProfile{}, "", fmt.Errorf("could not read the VPN profile at %s: %w", path, err)
	}
	var warn string
	if fi, statErr := os.Stat(path); statErr == nil && fi.Mode().Perm()&0o077 != 0 {
		warn = fmt.Sprintf("the VPN profile at %s is mode %04o — it holds a private key and should be 0600", path, fi.Mode().Perm())
	}
	p, err := ParseExternalProfile(raw)
	return p, warn, err
}

func (p ExternalProfile) validate() error {
	switch p.Type {
	case "wireguard", "openvpn":
	case "":
		return fmt.Errorf(`the VPN profile has no "type" — this tool needs to be told whether it is dialling wireguard or openvpn, and will not guess`)
	default:
		return fmt.Errorf("the VPN profile type %q is not one this tool knows how to dial (wireguard, openvpn)", p.Type)
	}
	// openvpn is validated no further here: PlanExternalUp refuses it with a
	// complete sentence, and rejecting it on a missing WireGuard key would
	// report the wrong reason.
	if p.Type == "openvpn" {
		return nil
	}

	if p.Iface != "" && !ifaceNamePattern.MatchString(p.Iface) {
		return fmt.Errorf("the interface name %q is not usable: it becomes a filename and a kernel interface, so it must start with a letter, be at most 15 characters, and contain only letters, digits, '.', '_' or '-'", p.Iface)
	}
	if err := validWireGuardKey(p.PrivateKey); err != nil {
		return fmt.Errorf("private_key: %w", err)
	}
	if len(p.Address) == 0 {
		return fmt.Errorf("the VPN profile carries no address for this side of the tunnel, so the interface would come up with no source address and nothing could leave through it")
	}
	for _, a := range p.Address {
		if err := validCIDR(a); err != nil {
			return fmt.Errorf("address %q: %w", a, err)
		}
	}
	for _, d := range p.DNS {
		if ip := net.ParseIP(strings.TrimSpace(d)); ip == nil {
			return fmt.Errorf("dns %q is not an IP address", d)
		}
	}
	if p.MTU != 0 && (p.MTU < 1280 || p.MTU > 9000) {
		return fmt.Errorf("mtu %d is outside the range a WireGuard interface can carry (1280-9000, or 0 to let wg-quick choose)", p.MTU)
	}
	if err := validWireGuardKey(p.Peer.PublicKey); err != nil {
		return fmt.Errorf("peer.public_key: %w", err)
	}
	if strings.TrimSpace(p.Peer.PresharedKey) != "" {
		if err := validWireGuardKey(p.Peer.PresharedKey); err != nil {
			return fmt.Errorf("peer.preshared_key: %w", err)
		}
	}
	if _, _, err := splitEndpoint(p.Peer.Endpoint); err != nil {
		return fmt.Errorf("peer.endpoint: %w", err)
	}
	if len(p.Peer.AllowedIPs) == 0 {
		return fmt.Errorf("the VPN profile's peer carries no allowed_ips, so the tunnel would accept and send nothing")
	}
	for _, a := range p.Peer.AllowedIPs {
		if err := validCIDR(a); err != nil {
			return fmt.Errorf("peer.allowed_ips %q: %w", a, err)
		}
	}
	if p.Peer.PersistentKeepalive < 0 || p.Peer.PersistentKeepalive > 65535 {
		return fmt.Errorf("peer.persistent_keepalive %d is out of range (0-65535)", p.Peer.PersistentKeepalive)
	}
	return nil
}

// validWireGuardKey accepts exactly what `wg` accepts: standard base64 of 32
// raw bytes. Parsing it rather than pattern-matching it is what guarantees the
// value cannot carry a newline into the rendered config.
func validWireGuardKey(k string) error {
	k = strings.TrimSpace(k)
	if k == "" {
		return fmt.Errorf("missing")
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return fmt.Errorf("is not valid base64")
	}
	if len(raw) != 32 {
		return fmt.Errorf("decodes to %d bytes, and a WireGuard key is 32", len(raw))
	}
	return nil
}

func validCIDR(s string) error {
	if _, _, err := net.ParseCIDR(strings.TrimSpace(s)); err != nil {
		return fmt.Errorf("is not a CIDR")
	}
	return nil
}

// splitEndpoint returns the host and port halves of an `Endpoint`, refusing
// anything that would not be safe to render or to resolve.
func splitEndpoint(endpoint string) (host, port string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", fmt.Errorf("missing — a tunnel with no endpoint has nothing to dial")
	}
	host, port, err = net.SplitHostPort(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("%q is not host:port", endpoint)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("%q does not carry a usable port", endpoint)
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, port, nil
	}
	if !endpointHostPattern.MatchString(host) {
		return "", "", fmt.Errorf("%q is neither an IP address nor a plain hostname", host)
	}
	return host, port, nil
}

// Fingerprint is a stable hash of the whole profile, used to tell "the same
// tunnel, asked for twice" from "a different tunnel". A hash, not the fields:
// it is safe to store in state.json and print in a reply, which the private
// key it covers is not.
func (p ExternalProfile) Fingerprint() string {
	canonical, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// --- config synthesis --------------------------------------------------------

// forbiddenConfigKeys are the wg-quick directives that execute a command or
// install a route. None of them can be reached from ExternalProfile — there is
// no field for them — and this list exists so that the ASSERTION below is
// checkable rather than a claim in a comment.
var forbiddenConfigKeys = []string{
	"PostUp", "PostDown", "PreUp", "PreDown", "SaveConfig", "FwMark",
}

// synthesizeWireGuard renders the config this tool will actually run.
//
// `Table = off` (invariant 2) is the one line that is not optional: without it
// wg-quick installs its own routes, including a 0.0.0.0/0 that would move THIS
// MACHINE. Every route this feature needs is built explicitly afterwards, in
// the tunnel's own table, in an order that matters.
//
// DNS is deliberately NOT rendered even though the profile carries it, and
// this is a decision rather than an omission. wg-quick's `DNS =` is not scoped
// to the tunnel: it shells out to resolvconf/resolvectl and rewrites the
// resolver of the WHOLE HOST — here, the netns that 130 containers egress
// through. That is the same lockout the rest of this module keeps warning
// about, arriving through DNS instead of routing, and it fights
// planExternalExclusions directly, whose entire job is to pin the resolvers
// that already work OUTSIDE the tunnel. It also simply fails on a host with
// neither resolvconf nor systemd-resolved, taking `wg-quick up` down with it.
// The addresses are validated, recorded and reported so the layer that owns
// resolver policy can act on them; they are not smuggled into a global.
func synthesizeWireGuard(p ExternalProfile, iface string) (string, error) {
	var b strings.Builder
	b.WriteString("# Synthesized by aw-remote-host from a structured VPN profile.\n")
	b.WriteString("# Generated file — edits are lost on the next `vpn external-up`.\n")
	b.WriteString("# Table = off is deliberate: this tool builds the routing table itself.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", strings.TrimSpace(p.PrivateKey))
	fmt.Fprintf(&b, "Address = %s\n", joinTrimmed(p.Address))
	if p.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", p.MTU)
	}
	b.WriteString("Table = off\n")
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", strings.TrimSpace(p.Peer.PublicKey))
	if psk := strings.TrimSpace(p.Peer.PresharedKey); psk != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", joinTrimmed(p.Peer.AllowedIPs))
	fmt.Fprintf(&b, "Endpoint = %s\n", strings.TrimSpace(p.Peer.Endpoint))
	if p.Peer.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Peer.PersistentKeepalive)
	}
	conf := b.String()
	if err := assertNoExecutableDirective(conf); err != nil {
		return "", err
	}
	return conf, nil
}

func joinTrimmed(in []string) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimSpace(s))
	}
	return strings.Join(out, ", ")
}

// assertNoExecutableDirective is the belt to the typed fields' braces.
//
// The fields cannot express a PostUp and every value is parsed into its own
// type before it is rendered, so this can only fire if someone later adds a
// field that can. Failing here — before the file is written, before wg-quick
// is invoked — is how that change gets caught by a test instead of by a root
// shell in production.
func assertNoExecutableDirective(conf string) error {
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
		for _, bad := range forbiddenConfigKeys {
			if strings.EqualFold(key, bad) {
				return fmt.Errorf("refusing to write a WireGuard config containing %s: wg-quick runs it as root, and nothing a caller sends may ever reach that line", bad)
			}
		}
		if strings.EqualFold(key, "Table") && !strings.EqualFold(trimmed, "Table = off") {
			return fmt.Errorf("refusing to write a WireGuard config whose Table is anything but off (%q): wg-quick would install its own routes and move this machine", trimmed)
		}
	}
	return nil
}

// ExternalTunnelDir is where synthesized configs live: 0700, under this tool's
// own state directory, never /etc/wireguard. A private directory keeps the
// generated file away from anything that scans for profiles to auto-start.
func ExternalTunnelDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "vpn"), nil
}

// ExternalTunnelConfPath is the absolute path of one interface's synthesized
// config. wg-quick takes a path with a '/' in it and derives the interface
// name from the basename, which is why this is <iface>.conf and not anything
// else.
func ExternalTunnelConfPath(iface string) (string, error) {
	dir, err := ExternalTunnelDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, iface+".conf"), nil
}

func writeExternalConf(path, conf string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	// 0600 and written whole. It carries a private key.
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// --- plan --------------------------------------------------------------------

// ConnectedRoute is one directly-attached network, discovered from the live
// main table. Never named in this file — see invariant 1.
type ConnectedRoute struct {
	Prefix string `json:"prefix"`
	Dev    string `json:"dev"`
}

// ExternalUpSpec is one request to dial an external tunnel on this host.
type ExternalUpSpec struct {
	Profile ExternalProfile
	// Iface overrides the profile's own. Empty falls back to the profile,
	// then to DefaultExternalIface.
	Iface string
	// Table is the routing table this tunnel's default is built in. Defaults
	// to ExternalRouteTable, so that a dial and the vpn_external_route that
	// follows it agree without anyone having to pass the same number twice.
	Table int
	// Deadman is how long an unconfirmed dial has before it tears itself down.
	Deadman time.Duration
	// ConfirmTimeout is how long to wait for a handshake. Clamped inside
	// Deadman, same as ExternalRouteSpec's.
	ConfirmTimeout time.Duration
	// Runner is how every shellout is made. Required and never defaulted —
	// same field, same reason, as ExternalRouteSpec.Runner.
	Runner Runner
	// Runtime lets a caller that already detected the container engine skip
	// the probe.
	Runtime ContainerRuntime
}

func (s ExternalUpSpec) withDefaults() ExternalUpSpec {
	if s.Iface == "" {
		s.Iface = s.Profile.Iface
	}
	if s.Iface == "" {
		s.Iface = DefaultExternalIface
	}
	if s.Table == 0 {
		s.Table = ExternalRouteTable
	}
	if s.Deadman <= 0 {
		s.Deadman = DefaultDeadmanTimeout
	}
	if s.ConfirmTimeout <= 0 {
		s.ConfirmTimeout = DefaultConfirmTimeout
	}
	if s.ConfirmTimeout >= s.Deadman {
		s.ConfirmTimeout = s.Deadman - 15*time.Second
		if s.ConfirmTimeout < 5*time.Second {
			s.ConfirmTimeout = 5 * time.Second
		}
	}
	return s
}

// ExternalUpPlan is everything resolved before anything is changed. Producing
// one is read-only, which is what makes --plan an honest preview rather than a
// second code path that might disagree.
//
// It carries NO key material, by construction: this struct is serialized into
// the reply the workspace parses and into the narration a human reads.
type ExternalUpPlan struct {
	Type          string           `json:"type"`
	Iface         string           `json:"iface"`
	Table         int              `json:"table"`
	ConfPath      string           `json:"conf_path"`
	Endpoint      string           `json:"endpoint"`
	EndpointIP    string           `json:"endpoint_ip"`
	PeerPublicKey string           `json:"peer_public_key"`
	DNS           []string         `json:"dns,omitempty"`
	MainGateway   string           `json:"main_gateway"`
	MainDev       string           `json:"main_dev"`
	Connected     []ConnectedRoute `json:"connected_routes"`
	Runtime       string           `json:"runtime,omitempty"`
	ProfileSHA256 string           `json:"profile_sha256"`
	// AlreadyUp is set when this exact profile is recorded, the interface
	// carries its peer and the table already holds the default — see
	// invariant 6, and assume the invocation may be delivered twice.
	AlreadyUp bool   `json:"already_up"`
	Refusal   string `json:"refusal,omitempty"`

	// wgQuickPath / ipPath / wgPath are resolved absolute at plan time so the
	// dead-man's revert can name them without depending on PATH — see
	// ArmSpec.TailscalePath for the incident that discipline comes from.
	wgQuickPath string
	ipPath      string
	wgPath      string
}

// pinPlan is an ExternalRoutePlan carrying exactly the three fields
// excludeArgs and routeInstalled read.
//
// This is reuse rather than resemblance, and deliberately so: the endpoint pin
// has to be spelled by THE SAME code that spells vpn_external_route's
// exclusions, down to the `onlink`, or the two paths would drift and one of
// them would silently stop installing.
func (p ExternalUpPlan) pinPlan() ExternalRoutePlan {
	return ExternalRoutePlan{Table: p.Table, MainGateway: p.MainGateway, MainDev: p.MainDev}
}

func (p ExternalUpPlan) endpointPrefix() string { return p.EndpointIP + "/32" }

// tableArgs is every `ip route` this plan writes into the tunnel's table, IN
// THE ORDER IT MUST WRITE THEM: the connected routes first, then the endpoint
// pin, and the DEFAULT LAST.
//
// The order is the invariant, not a preference. Between installing a default
// and installing the connected routes there is a window in which a container
// matched by the rule can reach the internet and NOT its own siblings —
// Postgres, Redis, every agent runner — and that window is exactly the outage
// this ordering exists to make impossible. Returning the whole sequence from
// one function is what lets a test assert it without running anything.
func (p ExternalUpPlan) tableArgs(verb string) [][]string {
	var out [][]string
	for _, c := range p.Connected {
		out = append(out, []string{"route", verb, c.Prefix, "dev", c.Dev, "table", strconv.Itoa(p.Table)})
	}
	out = append(out, p.pinPlan().excludeArgs(pinVerb(verb), p.endpointPrefix()))
	out = append(out, []string{"route", verb, "default", "dev", p.Iface, "table", strconv.Itoa(p.Table)})
	return out
}

// pinVerb maps this file's verbs onto excludeArgs', which only knows add and
// del — `add` is what carries the onlink. The idempotence `replace` would have
// given us is provided by the routeInstalled guard in applyExternalUp instead.
func pinVerb(verb string) string {
	if verb == "del" {
		return "del"
	}
	return "add"
}

// PlanExternalUp resolves everything and refuses anything this host cannot
// safely be asked to do, changing nothing.
//
// Ordered by how early a refusal can be known, so a host that was never a
// candidate never gets as far as pulling an image.
func PlanExternalUp(ctx context.Context, spec ExternalUpSpec) (*ExternalUpPlan, error) {
	spec = spec.withDefaults()
	plan := &ExternalUpPlan{
		Type:          spec.Profile.Type,
		Iface:         spec.Iface,
		Table:         spec.Table,
		Endpoint:      strings.TrimSpace(spec.Profile.Peer.Endpoint),
		PeerPublicKey: strings.TrimSpace(spec.Profile.Peer.PublicKey),
		DNS:           spec.Profile.DNS,
		ProfileSHA256: spec.Profile.Fingerprint(),
	}
	runner := spec.Runner
	if runner == nil {
		return nil, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	// OpenVPN, honestly. The binary is in the image, but a .ovpn creates tun0
	// with server-pushed routes and DNS that fight the policy rules unless the
	// client is driven with --route-nopull, and half of that is worse than
	// none of it: it would come up, look dialled, and move routing this file
	// does not control. WireGuard/NordLynx is the product's default path.
	if spec.Profile.Type == "openvpn" {
		plan.Refusal = "this tool does not dial OpenVPN profiles yet. The openvpn binary is present, but a .ovpn brings up tun0 with routes and resolvers pushed by the server, which would install routing this tool does not control and cannot revert — so it is a refusal rather than a half-dialled tunnel. Use the provider's WireGuard/NordLynx profile, which is the supported path."
		return plan, nil
	}
	if spec.Profile.Type != "wireguard" {
		plan.Refusal = fmt.Sprintf("this tool cannot dial a profile of type %q", spec.Profile.Type)
		return plan, nil
	}

	// The binaries first, because without them nothing below can happen and
	// the honest failure is "this host cannot do this at all". Absolute paths,
	// resolved here, for the dead-man's script.
	for _, bin := range []struct {
		name string
		into *string
	}{{"ip", &plan.ipPath}, {"wg", &plan.wgPath}, {"wg-quick", &plan.wgQuickPath}} {
		path, err := lookupExternalBinary(bin.name)
		if err != nil || path == "" {
			plan.Refusal = fmt.Sprintf("this host has no usable `%s` command, so it cannot bring a WireGuard tunnel up (the aw-remote-host image carries iproute2 and wireguard-tools; a host missing them was never rebuilt)", bin.name)
			return plan, nil
		}
		*bin.into = path
	}

	confPath, err := ExternalTunnelConfPath(spec.Iface)
	if err != nil {
		return nil, err
	}
	plan.ConfPath = confPath

	// The endpoint has to be an ADDRESS by the time the pin is written; a name
	// cannot be routed. Resolved here, before anything changes, because after
	// the tunnel is up the resolver may be the thing that broke.
	host, _, err := splitEndpoint(spec.Profile.Peer.Endpoint)
	if err != nil {
		plan.Refusal = fmt.Sprintf("the tunnel endpoint is unusable: %v", err)
		return plan, nil
	}
	endpointIP, err := resolveEndpointIPv4(ctx, host)
	if err != nil {
		plan.Refusal = fmt.Sprintf("the tunnel endpoint %q could not be resolved to an IPv4 address (%v), and without one its /32 cannot be pinned outside the tunnel — which would send the tunnel's own packets into itself", host, err)
		return plan, nil
	}
	plan.EndpointIP = endpointIP

	gw, mdev, err := mainDefault(ctx, runner)
	if err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	plan.MainGateway, plan.MainDev = gw, mdev

	// INVARIANT 1. Discovered, never named. An empty discovery is a refusal:
	// a table holding only `default dev wg0` is exactly the shape that takes
	// the routed container away from Postgres, Redis and every sibling.
	connected, err := discoverConnectedRoutes(ctx, runner, spec.Iface)
	if err != nil {
		plan.Refusal = err.Error()
		return plan, nil
	}
	if len(connected) == 0 {
		plan.Refusal = fmt.Sprintf("no directly-attached network could be discovered in this host's main routing table, so table %d would end up holding a default route and nothing else. A container pointed at that table loses every sibling container — Postgres, Redis, the agent runners — while appearing to have working internet, so this is a refusal rather than a partial build", spec.Table)
		return plan, nil
	}
	plan.Connected = connected

	// INVARIANT 7. The egress confirmation that follows a dial starts a
	// throwaway container, i.e. needs a registry pull at exactly the moment a
	// half-up tunnel can prevent one. The runtime is resolved here and the
	// image is pulled in ExternalUp BEFORE the switch is armed.
	rt := spec.Runtime
	if !rt.Present() {
		detected, derr := DetectContainerRuntime(ctx, runner)
		if derr != nil || !detected.Present() {
			plan.Refusal = NoContainerRuntimeRefusal
			return plan, nil
		}
		rt = detected
	}
	plan.Runtime = rt.Name

	plan.AlreadyUp = externalTunnelAlreadyUp(ctx, runner, *plan)
	return plan, nil
}

// resolveEndpointIPv4 turns the endpoint's host half into a single IPv4.
// Indirected through the default resolver rather than a shellout so it works
// identically on every host this binary ships to.
func resolveEndpointIPv4(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("%s is IPv6, and this path pins a v4 /32", host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address")
}

// discoverConnectedRoutes reads the directly-attached networks out of the live
// main table — the ones with a device and no gateway.
//
// This is vpn-hub-entrypoint.sh's discover_bridge discipline and not its
// literals. That script's header records what the literals cost: a hardcoded
// bridge name silently became a different bridge across a cutover and put
// wg-quick into a 619-restart crash loop that leaked 3,714 iptables rules. So
// nothing here names a bridge, a subnet or an interface; it reads what the
// kernel says is attached, every single apply.
//
// `default` is skipped (that is the route being replaced), so is anything
// routed `via` a gateway (not connected), and so is the tunnel's own device
// (its route belongs to the tunnel, not to the local fabric).
func discoverConnectedRoutes(ctx context.Context, r Runner, tunnelIface string) ([]ConnectedRoute, error) {
	out, err := r.Run(ctx, "ip", "-o", "-4", "route", "show", "table", "main")
	if err != nil {
		return nil, fmt.Errorf("could not read this host's main routing table, so the networks that must stay reachable alongside the tunnel could not be discovered: %w", err)
	}
	var routes []ConnectedRoute
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), `\`))
		if len(f) < 3 {
			continue
		}
		prefix := f[0]
		if prefix == "default" {
			continue
		}
		if _, _, perr := net.ParseCIDR(prefix); perr != nil {
			// `blackhole`, `unreachable`, `local`, a bare host address — none
			// of them describe an attached network.
			continue
		}
		var dev string
		via := false
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "dev":
				dev = f[i+1]
			case "via":
				via = true
			}
		}
		if via || dev == "" || dev == tunnelIface || seen[prefix] {
			continue
		}
		seen[prefix] = true
		routes = append(routes, ConnectedRoute{Prefix: prefix, Dev: dev})
	}
	return routes, nil
}

// externalTunnelAlreadyUp answers invariant 6: is this exact tunnel already
// dialled, right now?
//
// All three halves have to agree — the recorded fingerprint, the live
// interface carrying the recorded peer, and the table carrying the default. A
// record alone is not enough (the interface may have died), and a live
// interface alone is not enough (it may be a different profile's). Anything
// short of all three converges by re-applying, which is safe because every
// write below is idempotent.
func externalTunnelAlreadyUp(ctx context.Context, r Runner, plan ExternalUpPlan) bool {
	rec, err := loadExternalTunnelState()
	if err != nil || rec == nil {
		return false
	}
	if rec.ProfileSHA256 != plan.ProfileSHA256 || rec.Iface != plan.Iface || rec.Table != plan.Table {
		return false
	}
	if !tunnelPeerPresent(ctx, r, plan) {
		return false
	}
	ok, err := defaultInTable(ctx, r, plan)
	return err == nil && ok
}

func tunnelPeerPresent(ctx context.Context, r Runner, plan ExternalUpPlan) bool {
	out, err := r.Run(ctx, "wg", "show", plan.Iface, "peers")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == plan.PeerPublicKey {
			return true
		}
	}
	return false
}

// defaultInTable reports whether the tunnel's default is in its table, and
// pointing at the tunnel — a default via something else is somebody else's.
func defaultInTable(ctx context.Context, r Runner, plan ExternalUpPlan) (bool, error) {
	out, err := r.Run(ctx, "ip", "route", "show", "table", strconv.Itoa(plan.Table))
	if err != nil {
		return false, fmt.Errorf("routing table %d could not be read: %w", plan.Table, err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "dev" && f[i+1] == plan.Iface {
				return true, nil
			}
		}
	}
	return false, nil
}

// --- result -------------------------------------------------------------------

// ExternalUpResult is what one dial measured, whether it worked or not.
type ExternalUpResult struct {
	Plan ExternalUpPlan `json:"plan"`

	HostBefore string `json:"host_before,omitempty"`
	HostAfter  string `json:"host_after,omitempty"`
	HostHeld   bool   `json:"host_held"`
	HostMoved  bool   `json:"host_moved"`

	// HandshakeAt is the peer's latest handshake, unix seconds. Zero means the
	// tunnel never completed one, which is the difference between an interface
	// that exists and a tunnel that works.
	HandshakeAt int64 `json:"handshake_at"`

	Confirmed bool   `json:"confirmed"`
	Reverted  bool   `json:"reverted"`
	AlreadyUp bool   `json:"already_up"`
	Reason    string `json:"reason,omitempty"`
	Warning   string `json:"warning,omitempty"`

	DeadmanExpiresAt  string `json:"deadman_expires_at,omitempty"`
	DeadmanStillArmed bool   `json:"deadman_still_armed"`
}

// Payload is the machine-readable reply, shared by the `vpn_external_up` verb
// and by the CLI's --json.
//
// One shape from one function on purpose: the workspace parses whichever
// surface it reached, and two hand-written maps would drift the first time a
// field was added to one of them. It carries no key material — the plan it
// embeds cannot hold any (see ExternalUpPlan) and nothing is added here.
func (r ExternalUpResult) Payload() map[string]any {
	return map[string]any{
		"type":             r.Plan.Type,
		"iface":            r.Plan.Iface,
		"table":            r.Plan.Table,
		"conf_path":        r.Plan.ConfPath,
		"endpoint":         r.Plan.Endpoint,
		"endpoint_ip":      r.Plan.EndpointIP,
		"peer_public_key":  r.Plan.PeerPublicKey,
		"dns":              r.Plan.DNS,
		"connected_routes": r.Plan.Connected,
		"profile_sha256":   r.Plan.ProfileSHA256,
		"host_before":      r.HostBefore,
		"host_after":       r.HostAfter,
		"host_held":        r.HostHeld,
		"host_moved":       r.HostMoved,
		"handshake_at":     r.HandshakeAt,
		"confirmed":        r.Confirmed,
		"reverted":         r.Reverted,
		"already_up":       r.AlreadyUp,
		"reason":           r.Reason,
		"warning":          r.Warning,

		"deadman_expires_at":  r.DeadmanExpiresAt,
		"deadman_still_armed": r.DeadmanStillArmed,
	}
}

// --- apply --------------------------------------------------------------------

// ExternalUp dials the tunnel and tears it back down if it cannot prove it
// works.
//
// The sequence is deliberately the same shape as ExternalRoute's, in the same
// order, for the same reasons: measure the host, pre-pull what the
// confirmation needs, arm the dead-man's switch, change routing, confirm BOTH
// halves, revert anything unconfirmed. The result is returned alongside any
// error rather than instead of it — a failed dial that has already reverted is
// a normal, safe outcome and the caller still wants the evidence.
func ExternalUp(ctx context.Context, spec ExternalUpSpec, progress Progress) (ExternalUpResult, error) {
	spec = spec.withDefaults()
	runner := spec.Runner
	if runner == nil {
		return ExternalUpResult{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	plan, err := PlanExternalUp(ctx, spec)
	if err != nil {
		return ExternalUpResult{}, err
	}
	res := ExternalUpResult{Plan: *plan}
	if plan.Refusal != "" {
		progress.emit("error", plan.Refusal)
		res.Reason = plan.Refusal
		return res, fmt.Errorf("%w: %s", ErrScopeRefused, plan.Refusal)
	}

	// INVARIANT 6. Assume this invocation may be delivered twice — one
	// exec_start has been observed producing two POSTs — so the second one has
	// to converge and say so, not re-arm a switch and re-apply a tunnel that
	// is already carrying traffic.
	if plan.AlreadyUp {
		res.AlreadyUp, res.Confirmed = true, true
		res.HandshakeAt = latestHandshake(ctx, runner, *plan)
		progress.emit("info", "tunnel %s is ALREADY up for this exact profile (%s), in table %d — nothing to change", plan.Iface, shortFingerprint(plan.ProfileSHA256), plan.Table)
		return res, nil
	}

	progress.emit("info", "dialling %s: %s via peer %s, table %d", plan.Iface, plan.Endpoint, shortFingerprint(plan.PeerPublicKey), plan.Table)
	progress.emit("info", "the synthesized config sets Table = off — every route below is built explicitly, and none of them touch the main table")
	for _, c := range plan.Connected {
		progress.emit("info", "  %s stays reachable via %s INSIDE table %d — discovered from this host's own main table, never hardcoded", c.Prefix, c.Dev, plan.Table)
	}
	progress.emit("info", "  %s (the tunnel endpoint) is pinned to %s dev %s so the tunnel's own traffic cannot route into itself", plan.endpointPrefix(), plan.MainGateway, plan.MainDev)
	if len(plan.DNS) > 0 {
		progress.emit("info", "the profile's resolvers (%s) are recorded and NOT written into the config: wg-quick's DNS= rewrites the whole host's resolver, which is the same lockout arriving through DNS instead of routing", strings.Join(plan.DNS, ", "))
	}

	// The host's baseline is not optional: it is what the confirmation asserts
	// held, and without it there is no way to prove afterwards that this
	// machine was left alone.
	host, err := PublicIP(ctx)
	if err != nil {
		return res, fmt.Errorf("could not measure this host's own public IP before the change, so there would be no way to prove afterwards that the machine's egress did not move — refusing to touch anything: %w", err)
	}
	res.HostBefore = host.IP
	progress.emit("info", "host egress before (must NOT change): %s", host.IP)

	// INVARIANT 7, and it happens HERE — before the switch is armed and before
	// any routing moves. The egress confirmation that follows a dial starts a
	// throwaway container, so it needs a registry pull at exactly the moment a
	// half-up tunnel is most likely to prevent one.
	if err := prePullProbeImage(ctx, runner, plan.Runtime, progress); err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("%w: %s", ErrScopeRefused, err.Error())
	}

	conf, err := synthesizeWireGuard(spec.Profile, plan.Iface)
	if err != nil {
		return res, err
	}
	if err := writeExternalConf(plan.ConfPath, conf); err != nil {
		return res, err
	}
	progress.emit("info", "wrote a synthesized config to %s (0600) — assembled from typed fields, so it cannot carry a PostUp", plan.ConfPath)

	// ARM FIRST (invariant 4). Everything below this line can fail, hang or be
	// killed, and the host still comes back.
	armed, err := Arm(ArmSpec{
		After:           spec.Deadman,
		ExitNode:        fmt.Sprintf("external tunnel %s (%s)", plan.Iface, plan.Endpoint),
		ExclusionRevert: externalUpRevertScript(runner, *plan),
	})
	if err != nil {
		return res, fmt.Errorf("refusing to bring the tunnel up because the dead-man's switch could not be armed: %w", err)
	}
	res.DeadmanExpiresAt = armed.ExpiresAt
	progress.emit("info", "dead-man's switch ARMED (pid %d) — this tunnel tears itself down and table %d is flushed at %s unless this run confirms it", armed.PID, plan.Table, armed.ExpiresAt)

	if err := applyExternalUp(ctx, runner, *plan); err != nil {
		res.Reverted, res.DeadmanStillArmed = revertExternalUpAfterFailure(ctx, runner, *plan, progress)
		return res, err
	}

	progress.emit("info", "tunnel up — confirming BOTH halves (up to %s): that the peer handshakes, and that this machine's egress did not move...", spec.ConfirmTimeout)
	confirm := confirmExternalUp(ctx, runner, *plan, res.HostBefore, spec.ConfirmTimeout, progress)
	res.HostAfter, res.HostHeld, res.HostMoved = confirm.hostAfter, confirm.hostHeld, confirm.hostMoved
	res.HandshakeAt, res.Confirmed, res.Reason = confirm.handshakeAt, confirm.ok, confirm.reason

	if !confirm.ok {
		if confirm.hostMoved {
			progress.emit("error", "REVERTING — THIS MACHINE'S OWN EGRESS MOVED. That is a failed apply regardless of what the tunnel is doing, and it is the exact failure this path was built to make impossible.")
		}
		progress.emit("warning", "REVERTING — a tunnel that cannot be confirmed is the failure this sequence exists to prevent, not a partial success.")
		if err := revertExternalUp(ctx, runner, *plan, progress); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("error", "the revert itself FAILED (%v). The dead-man's switch is still armed and fires at %s; leaving it armed on purpose.", err, armed.ExpiresAt)
			return res, fmt.Errorf("the tunnel could not be confirmed and the revert failed: %s", confirm.reason)
		}
		res.Reverted = true
		if _, err := Disarm(); err != nil {
			res.DeadmanStillArmed = true
			progress.emit("warning", "the tunnel was torn down but the dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
		}
		return res, fmt.Errorf("the tunnel was NOT confirmed and has been torn back down: %s", confirm.reason)
	}

	if _, err := Disarm(); err != nil {
		res.DeadmanStillArmed = true
		return res, fmt.Errorf("the tunnel was confirmed, but the dead-man's switch could not be stood down (%w) — it will tear this tunnel down at %s", err, armed.ExpiresAt)
	}
	progress.emit("info", "tunnel confirmed (handshake at %d) with the host held at %s; dead-man's switch stood down.", res.HandshakeAt, res.HostAfter)

	// Persisted LAST and only on success, so that ExternalDown never undoes a
	// dial that did not survive its own confirmation.
	return res, saveExternalTunnelState(*plan)
}

// prePullProbeImage is invariant 7. The pull is a REFUSAL when it fails rather
// than a warning: a dial whose confirmation cannot run is a dial nothing will
// be able to prove, and finding that out after the routing has moved is the
// whole failure mode this file is defending against.
func prePullProbeImage(ctx context.Context, r Runner, runtime string, progress Progress) error {
	if runtime == "" {
		return fmt.Errorf("%s", NoContainerRuntimeRefusal)
	}
	if _, err := r.Run(ctx, runtime, "pull", ContainerProbeImage); err != nil {
		return fmt.Errorf("the egress probe image %s could not be pulled with %s (%v). It is pulled BEFORE anything is changed on purpose: confirming a tunnel starts a throwaway container, so a pull deferred until after the routing moved would be attempted at exactly the moment a half-up tunnel can prevent it. Refusing to dial a tunnel whose result could not then be confirmed", ContainerProbeImage, runtime, err)
	}
	progress.emit("info", "pre-pulled %s — the egress probe needs it AFTER the routing moves, which is the worst moment to need a registry", ContainerProbeImage)
	return nil
}

// applyExternalUp brings the interface up and builds the table, in the order
// tableArgs fixes: connected routes, endpoint pin, default LAST.
//
// Every write is idempotent. `ip route replace` is naturally so (the precedent
// is vpn-hub-entrypoint.sh:224-227); the endpoint pin is an `ip route add` —
// because that is the verb that carries excludeArgs' onlink — guarded by the
// same routeInstalled read vpn_external_route uses.
func applyExternalUp(ctx context.Context, r Runner, plan ExternalUpPlan) error {
	// `wg-quick up` on an interface that already exists fails; converging to
	// the requested config means taking it down first. Failure is ignored on
	// purpose — the overwhelmingly common case is that there is nothing there.
	if tunnelDevicePresent(ctx, r, plan) {
		if _, err := r.Run(ctx, "wg-quick", "down", plan.ConfPath); err != nil {
			return fmt.Errorf("interface %s already exists and could not be taken down before re-dialling it: %w", plan.Iface, err)
		}
	}
	if _, err := r.Run(ctx, "wg-quick", "up", plan.ConfPath); err != nil {
		return fmt.Errorf("could not bring the tunnel up with wg-quick: %w", err)
	}

	pin := plan.pinPlan()
	for _, args := range plan.tableArgs("replace") {
		// The pin is the only add-verb entry, and the only one that needs a
		// presence check to stay idempotent.
		if len(args) > 1 && args[1] == "add" {
			if ok, err := routeInstalled(ctx, r, pin, plan.endpointPrefix()); err == nil && ok {
				continue
			}
		}
		if _, err := r.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("could not write `ip %s`, so table %d is incomplete and must not be used: %w", strings.Join(args, " "), plan.Table, err)
		}
	}
	return nil
}

func tunnelDevicePresent(ctx context.Context, r Runner, plan ExternalUpPlan) bool {
	out, err := r.Run(ctx, "wg", "show", "interfaces")
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(out) {
		if f == plan.Iface {
			return true
		}
	}
	return false
}

// revertExternalUp takes the tunnel back down and removes exactly what this
// plan wrote.
//
// The DEFAULT comes out FIRST, and the order is the mirror of the apply's for
// the same reason: if removing the connected routes then fails, the container
// is already off the tunnel rather than on it with half its local fabric gone.
func revertExternalUp(ctx context.Context, r Runner, plan ExternalUpPlan, progress Progress) error {
	var firstErr error
	dels := plan.tableArgs("del")
	// tableArgs is ordered for the apply; the revert walks it backwards, which
	// puts the default first and the connected routes last.
	for i := len(dels) - 1; i >= 0; i-- {
		if _, err := r.Run(ctx, "ip", dels[i]...); err != nil && firstErr == nil {
			// A route that is already gone is not a failure — `wg-quick down`
			// takes the tunnel's own with it — so this is recorded and the
			// walk continues rather than stopping at the first one.
			firstErr = fmt.Errorf("could not remove `ip %s` from table %d: %w", strings.Join(dels[i], " "), plan.Table, err)
		}
	}
	if _, err := r.Run(ctx, "wg-quick", "down", plan.ConfPath); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("could not take the tunnel %s down: %w", plan.Iface, err)
	}
	if firstErr == nil {
		progress.emit("info", "tunnel %s is down and table %d no longer carries its default", plan.Iface, plan.Table)
	}
	return firstErr
}

func revertExternalUpAfterFailure(ctx context.Context, r Runner, plan ExternalUpPlan, progress Progress) (reverted, stillArmed bool) {
	if err := revertExternalUp(ctx, r, plan, progress); err != nil {
		progress.emit("error", "cleanup after a failed dial did not complete (%v) — leaving the dead-man's switch armed on purpose", err)
		return false, true
	}
	if _, err := Disarm(); err != nil {
		return true, true
	}
	return true, false
}

// externalUpRevertScript is the shell the dead-man's switch runs (invariant 4).
//
// Same contract as externalRevertScript beside it: POSIX sh, every path
// already absolute, every privilege prefix already applied, and NO reference
// to this binary — a self-referential revert dies with any update, rename or
// partial write of the very tool that armed it.
//
// It flushes the table rather than walking the routes it installed. That is
// the deliberate difference from ExternalDown: this script runs on a machine
// whose network has just gone, where it can read nothing and enumerate
// nothing, so the crude, total undo is the only one that can be trusted. The
// tunnel goes down first, so the flush is removing routes whose device has
// already disappeared.
func externalUpRevertScript(r Runner, plan ExternalUpPlan) string {
	prefix := ""
	if p, ok := r.(PrivilegedRunner); ok {
		prefix = strings.TrimSuffix(p.CommandPrefix("x"), "x")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s down %s || true\n", prefix, plan.wgQuickPath, plan.ConfPath)
	fmt.Fprintf(&b, "%s%s route del default dev %s table %d || true\n", prefix, plan.ipPath, plan.Iface, plan.Table)
	fmt.Fprintf(&b, "%s%s route flush table %d || true", prefix, plan.ipPath, plan.Table)
	return b.String()
}

// --- confirmation --------------------------------------------------------------

type externalUpConfirmation struct {
	hostAfter   string
	hostHeld    bool
	hostMoved   bool
	handshakeAt int64
	ok          bool
	reason      string
}

// confirmExternalUp keeps trying until the window runs out, because a fresh
// tunnel takes a few seconds to complete its first handshake.
func confirmExternalUp(ctx context.Context, r Runner, plan ExternalUpPlan, hostBefore string, window time.Duration, progress Progress) externalUpConfirmation {
	deadline := time.Now().Add(window)
	var last externalUpConfirmation
	for attempt := 1; ; attempt++ {
		last = confirmExternalUpOnce(ctx, r, plan, hostBefore)
		if last.ok || last.hostMoved || time.Now().After(deadline) {
			return last
		}
		progress.emit("info", "  attempt %d: %s — retrying", attempt, last.reason)
		select {
		case <-ctx.Done():
			return last
		case <-time.After(3 * time.Second):
		}
	}
}

// confirmExternalUpOnce asserts, in order: this machine did not move, the
// interface carries the peer, the table is complete, and the peer has actually
// handshaked.
//
// The handshake is the difference between an interface that exists and a
// tunnel that works, and it is why "wg-quick returned 0" is not a
// confirmation. Note the honest limitation: WireGuard only initiates a
// handshake when it has something to send or when a persistent keepalive
// fires, so a profile with persistent_keepalive: 0 and no traffic can sit
// here until the window expires and be torn back down. That reports a tunnel
// as unconfirmed, which is the safe direction, and providers' own profiles
// (NordLynx included) set a keepalive.
func confirmExternalUpOnce(ctx context.Context, r Runner, plan ExternalUpPlan, hostBefore string) externalUpConfirmation {
	var c externalUpConfirmation

	// The host's address is checked FIRST and a move short-circuits the rest:
	// a tunnel that looks right is meaningless if the machine came with it.
	host, err := PublicIP(ctx)
	if err != nil {
		c.reason = fmt.Sprintf("this host's own public IP could not be re-measured (%v), so it cannot be proven the machine stayed put", err)
		return c
	}
	c.hostAfter = host.IP
	c.hostHeld = host.IP == hostBefore
	c.hostMoved = !c.hostHeld
	if c.hostMoved {
		c.reason = fmt.Sprintf("THIS MACHINE's egress moved from %s to %s", hostBefore, host.IP)
		return c
	}

	if !tunnelPeerPresent(ctx, r, plan) {
		c.reason = fmt.Sprintf("interface %s does not carry the configured peer", plan.Iface)
		return c
	}
	ok, err := defaultInTable(ctx, r, plan)
	if err != nil {
		c.reason = err.Error()
		return c
	}
	if !ok {
		c.reason = fmt.Sprintf("table %d does not carry a default route out of %s", plan.Table, plan.Iface)
		return c
	}

	c.handshakeAt = latestHandshake(ctx, r, plan)
	if c.handshakeAt == 0 {
		c.reason = fmt.Sprintf("the peer on %s has never completed a handshake, so the interface exists but the tunnel does not carry traffic", plan.Iface)
		return c
	}
	c.ok = true
	return c
}

// latestHandshake reads the peer's last handshake as unix seconds, 0 when
// there has never been one. Zero is a real answer and never rendered as an
// age — the same rule mergeHandshake follows on the read side.
func latestHandshake(ctx context.Context, r Runner, plan ExternalUpPlan) int64 {
	out, err := r.Run(ctx, "wg", "show", plan.Iface, "latest-handshakes")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != plan.PeerPublicKey {
			continue
		}
		ts, convErr := strconv.ParseInt(f[1], 10, 64)
		if convErr != nil {
			return 0
		}
		return ts
	}
	return 0
}

// shortFingerprint is what a narration line may say about a key or a hash.
// Never the value itself — these lines end up in run logs a control plane
// stores.
func shortFingerprint(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// --- down ----------------------------------------------------------------------

// ExternalDown takes the tunnel back down.
//
// It undoes what was RECORDED, not what a fresh resolve would produce — the
// same reasoning VPNExternalUnroute's docstring gives, and it matters more
// here: the connected routes are discovered from a live table, so re-deriving
// them after the tunnel is up would compute a set that was never installed and
// leave the real one behind.
//
// Deliberately NOT gated by any of PlanExternalUp's refusals, for the same
// reason ClearExit and ExternalUnroute are not: this is the way OFF the
// tunnel, and an undo that refuses is one that fails exactly when it is most
// needed.
//
// The --iface/--table a caller passes are a FALLBACK used only when nothing is
// recorded, so that a tunnel this tool lost track of can still be torn down by
// hand. The reply says which of the two happened.
func ExternalDown(ctx context.Context, spec ExternalUpSpec, progress Progress) (ExternalUpResult, error) {
	spec = spec.withDefaults()
	runner := spec.Runner
	if runner == nil {
		return ExternalUpResult{}, fmt.Errorf("no command runner was supplied, and this package cannot build one: the caller has to pass ops.DefaultRunner wrapped in a PrivilegedRunner")
	}

	plan, err := loadExternalTunnelPlan()
	if err != nil {
		return ExternalUpResult{}, err
	}
	if plan == nil {
		fallback, ferr := fallbackDownPlan(spec)
		if ferr != nil {
			return ExternalUpResult{}, ferr
		}
		progress.emit("warning", "no external tunnel is recorded on this host; tearing down %s / table %d as asked, which removes only the default route and the interface — anything else in that table was not put there by a recorded dial and is left alone", fallback.Iface, fallback.Table)
		res := ExternalUpResult{Plan: *fallback, Warning: "no tunnel was recorded; this teardown used the interface and table given on the command line"}
		if _, err := runner.Run(ctx, "ip", "route", "del", "default", "dev", fallback.Iface, "table", strconv.Itoa(fallback.Table)); err != nil {
			progress.emit("info", "table %d carried no default out of %s (nothing to remove)", fallback.Table, fallback.Iface)
		}
		if _, err := runner.Run(ctx, "wg-quick", "down", fallback.ConfPath); err != nil {
			progress.emit("info", "no interface %s was up (nothing to take down)", fallback.Iface)
		}
		res.Reverted = true
		return res, nil
	}

	res := ExternalUpResult{Plan: *plan}
	if err := revertExternalUp(ctx, runner, *plan, progress); err != nil {
		return res, err
	}
	res.Reverted = true
	if _, err := Disarm(); err != nil {
		progress.emit("warning", "the tunnel was taken down but a dead-man's switch could not be stood down (%v). It will fire harmlessly.", err)
	}
	if err := clearExternalTunnelState(); err != nil {
		return res, err
	}
	if host, err := PublicIP(ctx); err == nil {
		res.HostAfter = host.IP
	}
	progress.emit("info", "external tunnel removed — this host's egress is %s", res.HostAfter)
	return res, nil
}

func fallbackDownPlan(spec ExternalUpSpec) (*ExternalUpPlan, error) {
	confPath, err := ExternalTunnelConfPath(spec.Iface)
	if err != nil {
		return nil, err
	}
	return &ExternalUpPlan{Iface: spec.Iface, Table: spec.Table, ConfPath: confPath}, nil
}

// --- state ---------------------------------------------------------------------

// saveExternalTunnelState records the dial. NO KEY MATERIAL: the fingerprint
// is a hash, and the peer's public key is public by definition. The private
// key lives in exactly one place, the 0600 config, and is never copied.
func saveExternalTunnelState(plan ExternalUpPlan) error {
	connected := make([]state.ConnectedRouteState, 0, len(plan.Connected))
	for _, c := range plan.Connected {
		connected = append(connected, state.ConnectedRouteState{Prefix: c.Prefix, Dev: c.Dev})
	}
	return mutateExternalRouteState(func(v *state.VPNState) {
		v.ExternalTunnel = &state.ExternalTunnelState{
			Type:          plan.Type,
			Iface:         plan.Iface,
			Table:         plan.Table,
			ConfPath:      plan.ConfPath,
			Endpoint:      plan.Endpoint,
			EndpointIP:    plan.EndpointIP,
			PeerPublicKey: plan.PeerPublicKey,
			MainGateway:   plan.MainGateway,
			MainDev:       plan.MainDev,
			Connected:     connected,
			ProfileSHA256: plan.ProfileSHA256,
			DialedAt:      time.Now().UTC().Format(time.RFC3339),
		}
	})
}

func clearExternalTunnelState() error {
	return mutateExternalRouteState(func(v *state.VPNState) { v.ExternalTunnel = nil })
}

func loadExternalTunnelState() (*state.ExternalTunnelState, error) {
	path, err := state.DefaultPath()
	if err != nil {
		return nil, nil
	}
	st, err := state.Load(path)
	if err != nil || st.VPN == nil || st.VPN.ExternalTunnel == nil {
		return nil, nil
	}
	return st.VPN.ExternalTunnel, nil
}

// loadExternalTunnelPlan rebuilds the plan a recorded dial installed, so the
// teardown removes the same routes the apply wrote, spelled the same way.
//
// The absolute binary paths are re-resolved rather than stored: a path that
// was right when the tunnel was dialled can be wrong after a package upgrade,
// and this is the one path that must not fail for the want of a lookup.
func loadExternalTunnelPlan() (*ExternalUpPlan, error) {
	rec, err := loadExternalTunnelState()
	if err != nil || rec == nil {
		return nil, err
	}
	connected := make([]ConnectedRoute, 0, len(rec.Connected))
	for _, c := range rec.Connected {
		connected = append(connected, ConnectedRoute{Prefix: c.Prefix, Dev: c.Dev})
	}
	plan := &ExternalUpPlan{
		Type:          rec.Type,
		Iface:         rec.Iface,
		Table:         rec.Table,
		ConfPath:      rec.ConfPath,
		Endpoint:      rec.Endpoint,
		EndpointIP:    rec.EndpointIP,
		PeerPublicKey: rec.PeerPublicKey,
		MainGateway:   rec.MainGateway,
		MainDev:       rec.MainDev,
		Connected:     connected,
		ProfileSHA256: rec.ProfileSHA256,
	}
	plan.ipPath, _ = lookupExternalBinary("ip")
	plan.wgQuickPath, _ = lookupExternalBinary("wg-quick")
	plan.wgPath, _ = lookupExternalBinary("wg")
	return plan, nil
}
