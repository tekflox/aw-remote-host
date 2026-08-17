package main

import (
	"flag"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/hostpower"
	"github.com/tekflox/aw-remote-host/internal/state"
)

func parseArgs(t *testing.T, args ...string) ([]string, bool, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	raw := fs.String("host-power", "", "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return parseHostPowerFlag(fs, *raw)
}

// Omitting the flag must leave a stored grant alone. Collapsing "not given"
// into "empty list" would make every plain re-run — and every
// `--with-workspace` added later — silently disarm a host that an installed
// app depends on.
func TestFlagOmittedDoesNotChangeAnything(t *testing.T) {
	grants, changed, err := parseArgs(t)
	if err != nil || changed || grants != nil {
		t.Fatalf("got %v %v %v", grants, changed, err)
	}
}

// Revoking has to be possible, and has to be explicit.
func TestFlagNoneRevokes(t *testing.T) {
	for _, arg := range []string{"--host-power=none", "--host-power=NONE", "--host-power="} {
		grants, changed, err := parseArgs(t, arg)
		if err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		if !changed {
			t.Fatalf("%s should count as a change", arg)
		}
		if len(grants) != 0 {
			t.Fatalf("%s should revoke, got %v", arg, grants)
		}
	}
}

func TestFlagParsesAndExpands(t *testing.T) {
	grants, changed, err := parseArgs(t, "--host-power=all")
	if err != nil || !changed {
		t.Fatalf("got %v %v", changed, err)
	}
	if hostpower.Format(grants) != hostpower.Format(hostpower.Granular) {
		t.Fatalf("got %q", hostpower.Format(grants))
	}
}

// A typo must abort before anything touches the disk — a quietly-granted
// nothing looks exactly like the feature not working.
func TestFlagTypoIsAnError(t *testing.T) {
	_, changed, err := parseArgs(t, "--host-power=kmv")
	if err == nil {
		t.Fatal("want an error")
	}
	if changed {
		t.Fatal("a failed parse must not report a change")
	}
}

func TestStateRoundTripsHostPower(t *testing.T) {
	path := t.TempDir() + "/state.json"
	if err := state.Save(path, &state.State{HostPower: []string{"kvm", "tun"}}); err != nil {
		t.Fatal(err)
	}
	got, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if hostpower.Format(got.HostPower) != "kvm,tun" {
		t.Fatalf("got %v", got.HostPower)
	}
}

// The stored value is the REQUEST. Freezing the probe result instead would
// mean a host that later gains /dev/kvm keeps reporting it as unavailable
// until someone remembers to re-run the flag.
func TestStoredValueIsTheRequestNotTheProbeResult(t *testing.T) {
	path := t.TempDir() + "/state.json"
	requested := []string{"kvm", "tun", "fuse", "binder"}
	if err := state.Save(path, &state.State{HostPower: requested}); err != nil {
		t.Fatal(err)
	}
	got, _ := state.Load(path)
	if len(got.HostPower) != len(requested) {
		t.Fatalf("the full request should persist even if this host can deliver "+
			"only part of it: got %v", got.HostPower)
	}
}

func TestResolveHostPowerEmptyIsEmpty(t *testing.T) {
	env, err := resolveHostPower(nil)
	if err != nil || env != "" {
		t.Fatalf("got %q %v", env, err)
	}
}

// Every grant undeliverable is a hard error: the operator explicitly asked
// for elevation and got none of it, so proceeding silently would hand back a
// workspace that looks configured and is not.
func TestResolveHostPowerFailsWhenNothingIsDeliverable(t *testing.T) {
	if _, err := resolveHostPower([]string{"binder"}); err != nil {
		if testing.Short() {
			t.Skip()
		}
		return // expected on a host without binder devices
	}
	t.Skip("this host provides binder devices")
}

// Privileged always probes true, so it always yields a non-empty env value —
// the branch above must not fire for it.
func TestResolveHostPowerPrivilegedSucceeds(t *testing.T) {
	env, err := resolveHostPower([]string{hostpower.Privileged})
	if err != nil {
		t.Fatal(err)
	}
	if env != hostpower.Privileged {
		t.Fatalf("got %q", env)
	}
}
