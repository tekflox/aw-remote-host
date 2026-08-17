// Package hostpower is this machine's opt-in to giving app containers
// elevated device access — and the probe that decides whether the opt-in can
// actually be honoured.
//
// The workspace runs app containers as unprivileged siblings on this host's
// podman, with no devices and no added capabilities. That is the right default
// and stays the default. But a whole class of app cannot exist under it:
// anything running a *guest* rather than a process. A Windows VM without
// /dev/kvm falls back to software emulation and is unusably slow; without
// /dev/net/tun the guest has no NIC at all. Neither can be faked from
// userspace, so before this existed the only way to run one was to abandon the
// app framework entirely and hand-write a compose service.
//
// The design point is that a REQUEST is not a GRANT. `--host-power=all` on a
// Mac cannot produce /dev/kvm, and rootless podman cannot pass through a
// device the invoking user cannot open. So this package probes what the host
// can really deliver and reports the *effective* set, which is what gets
// exported to the workspace as AW_HOST_POWER and what the aw-console badge
// shows. The difference between requested and effective is the interesting
// number: it is the case where someone believes they enabled KVM and did not.
//
// Mirrors src/apps/hostpower.py in aw-workspace — same grant names, same
// meaning of "all". The two are separate implementations on purpose (Go here
// probes the host; Python there enforces the app's side), but the NAMES are a
// wire contract and must not drift.
package hostpower

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// AllKeyword expands to every granular grant — and pointedly not to
// Privileged. "Every device my host can offer" and "dissolve the container
// boundary" are different decisions with different blast radii; a convenience
// keyword must not make the second one on the user's behalf.
const AllKeyword = "all"

// EnvVar is the variable the workspace container reads the effective set from.
const EnvVar = "AW_HOST_POWER"

// Grant is one named unit of elevated access.
type Grant struct {
	Name string
	// Devices are passed to `podman run --device`. All of them must be
	// present for the grant to be offered — a partial binder set is not a
	// working Android guest, it is a confusing one.
	Devices []string
	// Caps are Linux capabilities added on top. A device node alone is often
	// not enough: /dev/net/tun opens fine without NET_ADMIN and then fails to
	// configure the interface.
	Caps []string
	Desc string
}

// Granular is what AllKeyword expands to, in display order.
var Granular = []string{"kvm", "tun", "fuse", "binder"}

// Privileged is the blunt one. It has to be typed by name; nothing expands to it.
const Privileged = "privileged"

var catalog = map[string]Grant{
	"kvm": {
		Name:    "kvm",
		Devices: []string{"/dev/kvm"},
		Desc:    "hardware virtualisation — a QEMU/KVM guest (aw-app-windows)",
	},
	"tun": {
		Name:    "tun",
		Devices: []string{"/dev/net/tun"},
		Caps:    []string{"NET_ADMIN"},
		Desc:    "TAP/TUN networking — a guest VM's or a VPN's own virtual NIC",
	},
	"fuse": {
		Name:    "fuse",
		Devices: []string{"/dev/fuse"},
		Caps:    []string{"SYS_ADMIN"},
		Desc:    "FUSE mounts — nested container storage, AppImages",
	},
	"binder": {
		Name:    "binder",
		Devices: []string{"/dev/binder", "/dev/hwbinder", "/dev/vndbinder"},
		Desc:    "Android binder IPC — a redroid/Android guest",
	},
	Privileged: {
		Name: Privileged,
		Desc: "full --privileged: every device and capability, no isolation",
	},
}

// order is the stable display order: granular grants first, privileged last.
// The set ends up in a status line, an env var and a console badge; one that
// reorders itself between runs reads as a change that did not happen.
var order = append(append([]string{}, Granular...), Privileged)

// Known returns every grant name, in display order.
func Known() []string { return append([]string{}, order...) }

// Describe renders a grant set for a status line or a log.
func Describe(grants []string) string {
	if len(grants) == 0 {
		return "standard (no elevated host access)"
	}
	if contains(grants, Privileged) {
		others := without(grants, Privileged)
		if len(others) > 0 {
			return fmt.Sprintf("PRIVILEGED (+%s) — no container isolation",
				strings.Join(others, ", "))
		}
		return "PRIVILEGED — no container isolation"
	}
	return strings.Join(grants, ", ")
}

// Parse normalises a user-supplied list: splits on commas, expands "all",
// dedupes, and orders deterministically. An unknown name is an error rather
// than a silent drop — a typo'd `--host-power=kmv` that quietly granted
// nothing would look exactly like the feature not working.
func Parse(raw string) ([]string, error) {
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if name == AllKeyword {
			for _, g := range Granular {
				seen[g] = true
			}
			continue
		}
		if _, ok := catalog[name]; !ok {
			return nil, fmt.Errorf(
				"unknown host power grant %q — known: %s, %s",
				name, AllKeyword, strings.Join(order, ", "))
		}
		seen[name] = true
	}
	return ordered(seen), nil
}

// Format renders a grant set back to the comma-separated wire format.
func Format(grants []string) string { return strings.Join(grants, ",") }

// Probe reports whether this host can actually deliver one grant, and why not
// when it cannot. The reason is the whole value here: "no /dev/kvm on darwin"
// and "/dev/kvm exists but this user cannot open it" need different fixes
// (nested virt vs. adding the user to the kvm group), and a bare false sends
// people to debug the wrong one.
func Probe(name string) (bool, string) {
	grant, ok := catalog[name]
	if !ok {
		return false, fmt.Sprintf("unknown grant %q", name)
	}
	// --privileged needs no device to exist; it is a flag on the run call.
	// Whether it is WISE is a separate question, which the confirmation
	// prompt in the CLI asks and this function deliberately does not.
	if name == Privileged {
		return true, ""
	}
	for _, dev := range grant.Devices {
		info, err := os.Stat(dev)
		if err != nil {
			return false, fmt.Sprintf("%s is not present on this host", dev)
		}
		if info.Mode()&os.ModeDevice == 0 {
			return false, fmt.Sprintf("%s exists but is not a device node", dev)
		}
		// Openability, not just existence: on a rootless host the device can
		// be there and still be unusable because the invoking user is not in
		// the owning group. Passing it through anyway produces a container
		// that starts and then fails at the point of use.
		f, err := os.OpenFile(dev, os.O_RDWR, 0)
		if err != nil {
			return false, fmt.Sprintf(
				"%s exists but this user cannot open it (%v) — check group membership",
				dev, err)
		}
		_ = f.Close()
	}
	return true, ""
}

// Resolution is the outcome of reconciling what was asked for with what this
// host can do.
type Resolution struct {
	Requested []string
	Effective []string
	// Refused maps a requested-but-undeliverable grant to the probe's reason.
	Refused map[string]string
}

// Denied is true when the host could not deliver everything requested.
func (r Resolution) Denied() bool { return len(r.Refused) > 0 }

// Resolve probes each requested grant and splits the request into what this
// host will actually deliver and what it will not.
//
// A refusal is NOT an error here: `--host-power=all` on a machine with no
// binder devices should grant kvm+tun+fuse and say so, not fail outright. The
// caller decides how loud to be — the CLI warns, and the console badge shows
// the delta. What must never happen is the request being reported back as if
// it had been honoured.
func Resolve(requested []string) Resolution {
	res := Resolution{
		Requested: append([]string{}, requested...),
		Refused:   map[string]string{},
	}
	seen := map[string]bool{}
	for _, name := range requested {
		ok, reason := Probe(name)
		if ok {
			seen[name] = true
			continue
		}
		res.Refused[name] = reason
	}
	res.Effective = ordered(seen)
	return res
}

// PodmanArgs renders a grant set as `podman run` arguments.
//
// Used for the workspace container itself, when a host opts to elevate it
// directly. App containers do NOT come through here: they are created by the
// workspace over the podman socket, so their flags are built on the Python
// side from the same grant names (src/apps/hostpower.py's docker_kwargs).
func PodmanArgs(grants []string) []string {
	if len(grants) == 0 {
		return nil
	}
	// Privileged already implies every device and capability. Also listing
	// them would make `podman inspect` read as a tighter grant than reality.
	if contains(grants, Privileged) {
		return []string{"--privileged"}
	}
	var args []string
	var caps []string
	for _, name := range grants {
		grant := catalog[name]
		for _, dev := range grant.Devices {
			args = append(args, "--device", dev)
		}
		for _, c := range grant.Caps {
			if !contains(caps, c) {
				caps = append(caps, c)
			}
		}
	}
	for _, c := range caps {
		args = append(args, "--cap-add", c)
	}
	return args
}

// Help renders the catalog for `--help` output.
func Help() string {
	var b strings.Builder
	for _, name := range order {
		fmt.Fprintf(&b, "  %-11s %s\n", name, catalog[name].Desc)
	}
	fmt.Fprintf(&b, "  %-11s every grant above EXCEPT %s\n", AllKeyword, Privileged)
	return b.String()
}

func ordered(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for _, name := range order {
		if set[name] {
			out = append(out, name)
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func without(list []string, drop string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != drop {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return indexOf(order, out[i]) < indexOf(order, out[j])
	})
	return out
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return len(list)
}
