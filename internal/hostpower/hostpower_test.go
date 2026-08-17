package hostpower

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseExpandsAll(t *testing.T) {
	got, err := Parse("all")
	if err != nil {
		t.Fatalf("Parse(all): %v", err)
	}
	if Format(got) != Format(Granular) {
		t.Fatalf("all = %v, want %v", got, Granular)
	}
}

// "Every device my host can offer" and "dissolve the container boundary" are
// different decisions. A convenience keyword must not make the second one.
func TestAllExcludesPrivileged(t *testing.T) {
	got, _ := Parse("all")
	if contains(got, Privileged) {
		t.Fatalf("all must not expand to %s: %v", Privileged, got)
	}
	if _, ok := catalog[Privileged]; !ok {
		t.Fatal("privileged should still be requestable by name")
	}
}

func TestParseAllPlusPrivileged(t *testing.T) {
	got, err := Parse("all,privileged")
	if err != nil {
		t.Fatal(err)
	}
	if Format(got) != "kvm,tun,fuse,binder,privileged" {
		t.Fatalf("got %q", Format(got))
	}
}

// The set lands in a status line, an env var and a console badge. One that
// reorders itself between runs reads as a change that did not happen.
func TestParseOrderIsStable(t *testing.T) {
	a, _ := Parse("tun,kvm")
	b, _ := Parse("kvm,tun")
	if Format(a) != Format(b) || Format(a) != "kvm,tun" {
		t.Fatalf("%q vs %q", Format(a), Format(b))
	}
}

func TestParseDedupes(t *testing.T) {
	got, _ := Parse("kvm,kvm,all")
	if Format(got) != Format(Granular) {
		t.Fatalf("got %q", Format(got))
	}
}

func TestParseEmpty(t *testing.T) {
	for _, raw := range []string{"", "  ", ",,"} {
		got, err := Parse(raw)
		if err != nil || len(got) != 0 {
			t.Fatalf("Parse(%q) = %v, %v", raw, got, err)
		}
	}
}

// A typo'd --host-power=kmv that quietly granted nothing would look exactly
// like the whole feature not working.
func TestParseUnknownIsAnError(t *testing.T) {
	_, err := Parse("kvm,kmv")
	if err == nil {
		t.Fatal("want an error for an unknown grant")
	}
	if !strings.Contains(err.Error(), "kmv") || !strings.Contains(err.Error(), "known:") {
		t.Fatalf("error should name the typo and the known set: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	if !strings.Contains(Describe(nil), "standard") {
		t.Fatal("empty set should read as standard")
	}
	if Describe([]string{"kvm", "tun"}) != "kvm, tun" {
		t.Fatalf("got %q", Describe([]string{"kvm", "tun"}))
	}
	if !strings.Contains(Describe([]string{Privileged}), "PRIVILEGED") {
		t.Fatal("privileged should be shouted")
	}
	got := Describe([]string{"kvm", Privileged})
	if !strings.Contains(got, "PRIVILEGED") || !strings.Contains(got, "kvm") {
		t.Fatalf("got %q", got)
	}
}

func TestPodmanArgs(t *testing.T) {
	if PodmanArgs(nil) != nil {
		t.Fatal("no grants should add no args")
	}
	got := Format(PodmanArgs([]string{"kvm", "tun"}))
	want := "--device,/dev/kvm,--device,/dev/net/tun,--cap-add,NET_ADMIN"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// --privileged already implies every device and capability; also listing them
// makes `podman inspect` read as a tighter grant than what is in force.
func TestPodmanArgsPrivilegedShortCircuits(t *testing.T) {
	got := PodmanArgs([]string{"kvm", "tun", Privileged})
	if len(got) != 1 || got[0] != "--privileged" {
		t.Fatalf("got %v", got)
	}
}

func TestPodmanArgsMergesCapsWithoutDuplicates(t *testing.T) {
	got := PodmanArgs([]string{"tun", "fuse"})
	seen := map[string]int{}
	for _, a := range got {
		seen[a]++
	}
	if seen["--cap-add"] != 2 {
		t.Fatalf("want one --cap-add per distinct cap, got %v", got)
	}
}

func TestProbeUnknownGrant(t *testing.T) {
	ok, reason := Probe("gpu")
	if ok || reason == "" {
		t.Fatalf("want a refusal with a reason, got %v %q", ok, reason)
	}
}

// Whether --privileged is WISE is the confirmation prompt's question, not the
// probe's — there is no device for it to look for.
func TestProbePrivilegedNeedsNoDevice(t *testing.T) {
	if ok, _ := Probe(Privileged); !ok {
		t.Fatal("privileged should always probe true")
	}
}

// The reason matters more than the boolean: "not present" and "present but
// you cannot open it" need different fixes (nested virt vs. group membership).
func TestProbeMissingDeviceSaysSo(t *testing.T) {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/binder"); err == nil {
			t.Skip("this host actually has binder devices")
		}
	}
	ok, reason := Probe("binder")
	if ok {
		t.Skip("host provides binder")
	}
	if !strings.Contains(reason, "/dev/binder") || !strings.Contains(reason, "not present") {
		t.Fatalf("reason should name the device and the problem: %q", reason)
	}
}

func TestProbeRejectsANonDeviceFile(t *testing.T) {
	// A plain file where a device node is expected is what a bind-mount
	// mistake or a hand-created placeholder leaves behind.
	dir := t.TempDir()
	fake := filepath.Join(dir, "kvm")
	if err := os.WriteFile(fake, []byte("not a device"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := catalog["kvm"]
	catalog["kvm"] = Grant{Name: "kvm", Devices: []string{fake}}
	defer func() { catalog["kvm"] = saved }()

	ok, reason := Probe("kvm")
	if ok || !strings.Contains(reason, "not a device node") {
		t.Fatalf("got %v %q", ok, reason)
	}
}

// `--host-power=all` on a machine with no binder devices must grant the rest
// and SAY what it dropped — not fail outright, and not report success.
func TestResolveSplitsRequestedFromEffective(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "missing")
	saved := catalog["binder"]
	catalog["binder"] = Grant{Name: "binder", Devices: []string{fake}}
	defer func() { catalog["binder"] = saved }()

	res := Resolve([]string{"binder", Privileged})
	if !res.Denied() {
		t.Fatal("want Denied() when a grant could not be delivered")
	}
	if contains(res.Effective, "binder") {
		t.Fatalf("binder must not be effective: %v", res.Effective)
	}
	if !contains(res.Effective, Privileged) {
		t.Fatalf("the deliverable grant should survive: %v", res.Effective)
	}
	if res.Refused["binder"] == "" {
		t.Fatal("a refusal needs a reason")
	}
}

func TestResolveEverythingDeliverable(t *testing.T) {
	res := Resolve([]string{Privileged})
	if res.Denied() {
		t.Fatalf("unexpected refusals: %v", res.Refused)
	}
	if Format(res.Effective) != Privileged {
		t.Fatalf("got %q", Format(res.Effective))
	}
}

func TestResolveEmpty(t *testing.T) {
	res := Resolve(nil)
	if res.Denied() || len(res.Effective) != 0 {
		t.Fatalf("got %+v", res)
	}
}

// The grant NAMES are a wire contract with aw-workspace's src/apps/hostpower.py
// (AW_HOST_POWER crosses the boundary). A rename on one side silently stops
// matching on the other.
func TestCatalogNamesMatchTheWireContract(t *testing.T) {
	want := []string{"kvm", "tun", "fuse", "binder", "privileged"}
	if len(catalog) != len(want) {
		t.Fatalf("catalog has %d grants, wire contract has %d", len(catalog), len(want))
	}
	for _, name := range want {
		if _, ok := catalog[name]; !ok {
			t.Fatalf("missing grant %q — aw-workspace expects it", name)
		}
	}
}

func TestHelpListsEveryGrantAndAll(t *testing.T) {
	help := Help()
	for _, name := range Known() {
		if !strings.Contains(help, name) {
			t.Fatalf("--help omits %q", name)
		}
	}
	if !strings.Contains(help, AllKeyword) {
		t.Fatal("--help omits the all keyword")
	}
}
