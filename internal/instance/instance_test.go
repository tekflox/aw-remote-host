package instance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/instance"
	"github.com/tekflox/aw-remote-host/internal/link"
	"github.com/tekflox/aw-remote-host/internal/rlog"
	"github.com/tekflox/aw-remote-host/internal/state"

	"github.com/tekflox/aw-remote-host/internal/firewall"
	"github.com/tekflox/aw-remote-host/internal/updater"
	"github.com/tekflox/aw-remote-host/internal/vpn"
)

// TestTwoInstancesInOneProcess is the test the design of this package exists
// to make possible, and it is deliberately not shaped like
// homedir_test.go:TestDirPrefersHOME.
//
// That test points $HOME at a t.TempDir() and asserts the resolved path sits
// under it. It passes no matter how badly instances are wired — including
// when they are not wired at all — because a single HOME override moves
// EVERY path at once, which is exactly the broken workaround this feature
// replaces. A green homedir_test.go is not evidence about instances.
//
// So this resolves BOTH instances in ONE process, through the real helpers
// the CLI calls, and asserts the two halves of the contract at the same
// time:
//
//   - PER-IDENTITY paths must all differ. If even one of them is shared,
//     two tenant accounts silently overlap on a subset of state, which is
//     harder to diagnose than the total leak this replaces — partial
//     threading is worse than none.
//   - PER-MACHINE paths must be byte-identical. If one of them moves, the
//     host ends up with two firewall managers, two VPN dead-man switches or
//     two self-updaters, each believing it owns the machine.
func TestTwoInstancesInOneProcess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows
	t.Cleanup(func() { instance.SetActive("") })

	perIdentity := func(t *testing.T, name string) map[string]string {
		t.Helper()
		instance.SetActive(name)
		out := map[string]string{}
		for label, fn := range map[string]func() (string, error){
			"credentials.json": link.DefaultCredentialsPath,
			"state.json":       state.DefaultPath,
			"client.log":       rlog.LogPath,
			"instance dir":     instance.ActiveDir,
		} {
			p, err := fn()
			if err != nil {
				t.Fatalf("%s for instance %q: %v", label, name, err)
			}
			out[label] = p
		}
		return out
	}

	perMachine := func(t *testing.T, name string) map[string]string {
		t.Helper()
		instance.SetActive(name)
		out := map[string]string{}
		for label, fn := range map[string]func() (string, error){
			"firewall.json":     firewall.StatePath,
			"vpn-deadman.json":  vpn.DeadmanPath,
			"vpn-deadman.log":   vpn.DeadmanLogPath,
			"vpn-selfheal.log":  vpn.SelfHealLogPath,
			"self-update dir":   updater.Dir,
			"self-update state": updater.PendingPath,
			"machine dir":       instance.MachineDir,
		} {
			p, err := fn()
			if err != nil {
				t.Fatalf("%s for instance %q: %v", label, name, err)
			}
			out[label] = p
		}
		return out
	}

	identA, identB := perIdentity(t, "alpha"), perIdentity(t, "bravo")
	machA, machB := perMachine(t, "alpha"), perMachine(t, "bravo")

	for label, a := range identA {
		b := identB[label]
		if a == b {
			t.Errorf("PER-IDENTITY %s is SHARED between two instances (%s) — two accounts would overwrite each other's state", label, a)
		}
		if !strings.Contains(a, filepath.Join("instances", "alpha")) {
			t.Errorf("PER-IDENTITY %s for instance alpha is not under instances/alpha: %s", label, a)
		}
		if !strings.Contains(b, filepath.Join("instances", "bravo")) {
			t.Errorf("PER-IDENTITY %s for instance bravo is not under instances/bravo: %s", label, b)
		}
	}

	for label, a := range machA {
		if b := machB[label]; a != b {
			t.Errorf("PER-MACHINE %s DIFFERS between instances (%s vs %s) — this host would run two of whatever owns it", label, a, b)
		}
		if strings.Contains(a, "instances") {
			t.Errorf("PER-MACHINE %s was moved under instances/: %s", label, a)
		}
	}
}

// TestDefaultInstancePathsAreUnchanged is the upgrade-safety half, and the
// highest-stakes assertion in this package: every BYOD host in the field is
// an unnamed instance, so if any of these moved, an upgrade would leave that
// host's credentials, state and service definition stranded at paths nothing
// reads any more.
//
// The expected values are spelled out literally rather than derived from the
// package under test, because a test that recomputes them from instance.Dir() would
// agree with any change this package made to them.
func TestDefaultInstancePathsAreUnchanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Cleanup(func() { instance.SetActive("") })

	instance.SetActive("")
	root := filepath.Join(home, ".aw-remote-host")

	cases := []struct {
		label string
		fn    func() (string, error)
		want  string
	}{
		{"credentials.json", link.DefaultCredentialsPath, filepath.Join(root, "credentials.json")},
		{"state.json", state.DefaultPath, filepath.Join(root, "state.json")},
		{"client.log", rlog.LogPath, filepath.Join(root, "client.log")},
		{"firewall.json", firewall.StatePath, filepath.Join(root, "firewall.json")},
		{"vpn-deadman.json", vpn.DeadmanPath, filepath.Join(root, "vpn-deadman.json")},
		{"vpn-deadman.log", vpn.DeadmanLogPath, filepath.Join(root, "vpn-deadman.log")},
		{"vpn-selfheal.log", vpn.SelfHealLogPath, filepath.Join(root, "vpn-selfheal.log")},
		{"self-update", updater.Dir, filepath.Join(root, "self-update")},
	}
	for _, c := range cases {
		got, err := c.fn()
		if err != nil {
			t.Fatalf("%s: %v", c.label, err)
		}
		if got != c.want {
			t.Errorf("default instance %s moved: got %s, want %s — this orphans every host already linked", c.label, got, c.want)
		}
	}
}

// TestDefaultNameNormalizesToTheDefaultInstance covers the escape hatch the
// second-link refusal offers: `--instance default` has to mean the flat,
// original layout and must never create a directory called "default".
func TestDefaultNameNormalizesToTheDefaultInstance(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	root, err := instance.MachineDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"default", "  default  ", "DEFAULT", ""} {
		got, err := instance.Dir(in)
		if err != nil {
			t.Fatalf("instance.Dir(%q): %v", in, err)
		}
		if got != root {
			t.Errorf("instance.Dir(%q) = %s, want the flat machine dir %s", in, got, root)
		}
	}
}

func TestValidateRejectsNamesThatWouldEscapeOrBreakAUnitName(t *testing.T) {
	// Each of these is legal somewhere and illegal somewhere else — a path
	// component, a systemd unit name and a launchd label do not agree — so
	// they are refused at the one place a user types them.
	for _, bad := range []string{
		"../escape", "a/b", `a\b`, ".hidden", "-leading", "_leading",
		"has space", "dots.are.labels", strings.Repeat("x", 65),
	} {
		if err := instance.Validate(bad); err == nil {
			t.Errorf("instance.Validate(%q) accepted a name it should refuse", bad)
		}
	}
	for _, ok := range []string{"work", "acme-2", "a", "A1_b-c", strings.Repeat("x", 64)} {
		if err := instance.Validate(ok); err != nil {
			t.Errorf("instance.Validate(%q) refused a usable name: %v", ok, err)
		}
	}
}

func TestListReportsOnlyNamedInstances(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	got, err := instance.List()
	if err != nil || len(got) != 0 {
		t.Fatalf("instance.List() on a machine with no named instances = %v, %v; want empty", got, err)
	}

	root, err := instance.MachineDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"bravo", "alpha"} {
		if err := os.MkdirAll(filepath.Join(root, "instances", n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A stray FILE under instances/ is not an instance — it must not be
	// reported to an operator as another tenant identity on their machine.
	if err := os.WriteFile(filepath.Join(root, "instances", "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err = instance.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "alpha" || got[1] != "bravo" {
		t.Errorf("instance.List() = %v, want [alpha bravo]", got)
	}
}
