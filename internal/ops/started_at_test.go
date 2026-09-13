package ops

import (
	"testing"
	"time"
)

// uptime_s came back null on EVERY host — measured across four workspaces on
// 2026-09-13, healthy ones included. The field had never carried a value.
//
// parseStartedAt only tried RFC3339Nano, which is what the podman API
// returns. The Go TEMPLATE this code actually uses returns something else:
// podman renders {{.State.StartedAt}} with time.Time's String(), giving
// "2026-09-13 08:20:02.004424754 +0000 UTC" — space instead of T, no Z, and a
// trailing zone name.
//
// Nothing noticed for months because a null uptime reads as "not up yet"
// rather than as a parser that never matched.
func TestParseStartedAtAcceptsWhatPodmanActuallyPrints(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"podman template (String()) — the one that was failing",
			"2026-09-13 08:20:02.004424754 +0000 UTC"},
		{"podman template, whole seconds",
			"2026-09-13 08:20:02 +0000 UTC"},
		{"RFC3339Nano — what the API returns",
			"2026-09-13T08:20:02.004424754Z"},
		{"RFC3339Nano with an offset",
			"2026-09-13T05:20:02.004424754-03:00"},
		{"surrounded by whitespace, as a template can emit",
			"  2026-09-13 08:20:02.004424754 +0000 UTC\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseStartedAt(c.raw)
			if err != nil {
				t.Fatalf("parseStartedAt(%q) = error %v — this is the bug", c.raw, err)
			}
			if got < 0 {
				t.Errorf("negative uptime %d", got)
			}
		})
	}
}

func TestParseStartedAtStillRejectsGarbage(t *testing.T) {
	// Accepting more formats must not mean accepting anything: a value that
	// cannot be a time has to stay an error, or uptime_s starts reporting 0
	// for a host whose state could not be read at all.
	for _, raw := range []string{"", "not a time", "0", "-", "1789287602"} {
		if _, err := parseStartedAt(raw); err == nil {
			t.Errorf("parseStartedAt(%q) accepted garbage", raw)
		}
	}
}

func TestParseStartedAtNeverReturnsNegative(t *testing.T) {
	// Clock skew between the host and this process is real; a container that
	// claims to have started in the future must read as 0, not as a negative
	// uptime the UI would render as nonsense.
	future := time.Now().Add(2 * time.Hour).Format("2006-01-02 15:04:05.999999999 -0700 MST")
	got, err := parseStartedAt(future)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("a future StartedAt must clamp to 0, got %d", got)
	}
}

func TestParseStartedAtComputesRealElapsedTime(t *testing.T) {
	// The point of the field. A parse that succeeds but returns 0 for a
	// container started an hour ago would be just as useless as the null.
	hourAgo := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05.999999999 -0700 MST")
	got, err := parseStartedAt(hourAgo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got < 3500 || got > 3700 {
		t.Errorf("expected ~3600s, got %d", got)
	}
}
