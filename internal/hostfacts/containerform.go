package hostfacts

import (
	"os"
	"regexp"
)

// containerIDPattern is what Docker writes into a container's hostname when
// the operator did not pin one: the first 12 hex chars of the container id.
var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ContainerForm reports whether this daemon is the PACKAGED CONTAINER form of
// aw-remote-host, and which container it is.
//
// WHY THE CONTROL PLANE NEEDS TO KNOW. "update" means two different things
// depending on the shape of the host. On a BYOD Mac or VM it means replacing
// the binary, which is what ops.SelfUpdate does and what the button has always
// done. Inside the container image that binary lives in the container's own
// writable layer, so replacing it updates the host only until the next
// recreate — the image, the thing that actually ships podman, tailscale, git
// and the bootstrap scripts, stays on whatever version it was built at. That
// gap is documented in aw-backend's hosted_driver.update_remote_host and was
// exactly the state this host was found in on 2026-09-11: binary reporting
// v0.1.101, image still the v0.1.100 one it was created from.
//
// Closing it requires recreating the container, which this process cannot do:
// it holds no docker socket (by design — it hosts agent sandboxes, and handing
// it the metal's socket would make every one of them root-equivalent on the
// host), and a process cannot outlive the `rm` of the container it runs in.
// Only something OUTSIDE can, so this fact is reported to the control plane
// and aw-backend does the recreate through the least-privilege docker proxy
// it already uses for its docker placement driver.
//
// Detection is an EXPLICIT env var stamped by the Dockerfile, never a
// heuristic like probing for /.dockerenv. A false positive here sends the
// control plane looking for a container to recreate that does not exist; a
// false negative silently leaves the host on the old image with the button
// still reporting success. The image knows what it is — nothing else has to
// guess.
//
// The id comes from the hostname, which Docker sets to the container's short
// id. That is only true when nobody pinned a custom hostname, so it is
// VALIDATED against the shape of a container id rather than trusted: a host
// with a custom hostname reports an empty id, and the control plane falls back
// to addressing the container by its configured name instead of acting on a
// string that is not an id at all.
func ContainerForm() (bool, string) {
	if os.Getenv("AW_REMOTE_HOST_FORM") != "container" {
		return false, ""
	}
	if id := os.Getenv("AW_REMOTE_HOST_CONTAINER_ID"); id != "" {
		return true, id
	}
	hostname, err := os.Hostname()
	if err != nil || !containerIDPattern.MatchString(hostname) {
		return true, ""
	}
	return true, hostname
}
