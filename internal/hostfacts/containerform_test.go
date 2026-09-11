package hostfacts

import "testing"

// The two wrong answers cost different things, and both are silent:
// a false positive sends the control plane hunting a container to recreate
// that does not exist; a false negative leaves the host on the old image with
// the update button still reporting success. That is why detection is an
// explicit stamp and never a heuristic — these tests pin that it stays one.
func TestContainerFormRequiresTheExplicitStamp(t *testing.T) {
	t.Setenv("AW_REMOTE_HOST_FORM", "")
	t.Setenv("AW_REMOTE_HOST_CONTAINER_ID", "")
	if isContainer, id := ContainerForm(); isContainer || id != "" {
		t.Fatalf("unstamped host must not claim the container form: got (%v, %q)", isContainer, id)
	}

	// Anything other than the exact value is not the container form either —
	// a half-set or misspelled var must not be read as a yes.
	for _, v := range []string{"1", "true", "docker", "Container", "container "} {
		t.Setenv("AW_REMOTE_HOST_FORM", v)
		if isContainer, _ := ContainerForm(); isContainer {
			t.Fatalf("AW_REMOTE_HOST_FORM=%q must not be read as the container form", v)
		}
	}
}

func TestContainerFormIDIsValidatedNotTrusted(t *testing.T) {
	t.Setenv("AW_REMOTE_HOST_FORM", "container")

	// An explicit id wins outright: it is the operator telling us directly.
	t.Setenv("AW_REMOTE_HOST_CONTAINER_ID", "deadbeefcafe")
	if isContainer, id := ContainerForm(); !isContainer || id != "deadbeefcafe" {
		t.Fatalf("explicit container id must win: got (%v, %q)", isContainer, id)
	}

	// Without one the hostname is used — but only when it actually LOOKS like
	// a container id. A pinned custom hostname must yield an empty id so the
	// control plane falls back to the configured name, rather than being
	// handed a string that is not an id and failing to inspect it.
	t.Setenv("AW_REMOTE_HOST_CONTAINER_ID", "")
	t.Setenv("HOSTNAME", "")
	isContainer, id := ContainerForm()
	if !isContainer {
		t.Fatal("stamped host must report the container form even when the id is unknown")
	}
	if id != "" && !containerIDPattern.MatchString(id) {
		t.Fatalf("a hostname that is not a container id must not be reported as one: %q", id)
	}
}

func TestContainerIDPatternShape(t *testing.T) {
	for _, ok := range []string{"d9e290c18382", "000000000000", "abcdef123456"} {
		if !containerIDPattern.MatchString(ok) {
			t.Fatalf("%q is a docker short id and must match", ok)
		}
	}
	// Too short, too long, uppercase hex and a real hostname are all things a
	// host can genuinely be called; none of them is a container id.
	for _, bad := range []string{"d9e290c1838", "d9e290c183827", "D9E290C18382", "aw-remote-host", "Mac.Home", ""} {
		if containerIDPattern.MatchString(bad) {
			t.Fatalf("%q must not be mistaken for a container id", bad)
		}
	}
}
