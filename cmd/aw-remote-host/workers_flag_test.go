package main

import (
	"flag"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/state"
)

func parseWorkersArgs(t *testing.T, args ...string) (int, bool, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	raw := fs.String("workers", "", "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return parseWorkersFlag(fs, *raw)
}

// Omitting the flag must leave a previously stored worker count alone —
// same rationale as the host-power flag: a plain re-run must never silently
// reset an already-configured value back to the default.
func TestWorkersFlagOmittedDoesNotChangeAnything(t *testing.T) {
	n, changed, err := parseWorkersArgs(t)
	if err != nil || changed || n != 0 {
		t.Fatalf("got %v %v %v", n, changed, err)
	}
}

func TestWorkersFlagParsesPositiveInt(t *testing.T) {
	n, changed, err := parseWorkersArgs(t, "--workers=4")
	if err != nil || !changed || n != 4 {
		t.Fatalf("got %v %v %v", n, changed, err)
	}
}

// A typo or a nonsensical value must abort before anything touches the
// disk — same "fail loud, not silently" shape as the host-power flag.
func TestWorkersFlagRejectsNonPositiveOrGarbage(t *testing.T) {
	for _, arg := range []string{"--workers=0", "--workers=-1", "--workers=abc", "--workers="} {
		n, changed, err := parseWorkersArgs(t, arg)
		if err == nil {
			t.Fatalf("%s: want an error, got n=%v changed=%v", arg, n, changed)
		}
		if changed {
			t.Fatalf("%s: a failed parse must not report a change", arg)
		}
	}
}

func TestStateRoundTripsWorkers(t *testing.T) {
	path := t.TempDir() + "/state.json"
	if err := state.Save(path, &state.State{Workers: 5}); err != nil {
		t.Fatal(err)
	}
	got, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Workers != 5 {
		t.Fatalf("got %v", got.Workers)
	}
}
