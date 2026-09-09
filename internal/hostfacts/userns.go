// Package hostfacts measures properties of the machine this daemon runs on
// that the control plane cannot infer from anything else it already knows.
package hostfacts

import (
	"os"
	"strings"
)

// identityUIDMap is what /proc/self/uid_map reads in the INITIAL user
// namespace: container-uid 0 maps to host-uid 0 for the whole uid space.
// Any other content means the process is inside a nested, remapped user
// namespace.
const identityUIDMap = "0 0 4294967295"

// uidMapPath is a variable so tests can point it at a fixture.
var uidMapPath = "/proc/self/uid_map"

// UIDMap returns the first line of /proc/self/uid_map, whitespace-normalised
// ("0     1000000      65536" -> "0 1000000 65536"), or "" when it cannot be
// read — non-Linux hosts have no such file, and "" is how the caller says
// "not measured" rather than guessing.
func UIDMap() string {
	raw, err := os.ReadFile(uidMapPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			return strings.Join(fields, " ")
		}
	}
	return ""
}

// UsernsContained reports whether this process runs in a REMAPPED user
// namespace, and whether that could be measured at all.
//
// This exists because `elevated` (euid 0) cannot answer the question the
// console badge built on it appears to answer. A container-root remapped by
// a nested userns is euid 0 inside the container and an unprivileged subuid
// on the metal — so it reports elevated=true in exactly the same way a
// genuinely host-root, UNCONTAINED daemon does. The badge therefore reads
// identically for the safe shape and the dangerous one, and there is no way
// to look at a fleet and tell which hosts are contained.
//
// A non-identity uid_map is positive proof of a nested user namespace, and a
// nested user namespace is what makes host-scoped capabilities (CAP_NET_ADMIN,
// CAP_SYS_MODULE) stop at the namespace boundary: the kernel evaluates those
// against init_user_ns, not against the namespace the process holds them in.
//
// ok=false means "could not measure" (no /proc/self/uid_map — every
// non-Linux host), which the control plane must store as NULL rather than
// as false. "Not measured" and "measured, not contained" are different
// facts and only one of them is a finding.
func UsernsContained() (contained bool, ok bool) {
	m := UIDMap()
	if m == "" {
		return false, false
	}
	return m != identityUIDMap, true
}
