package firewall

import "strings"

// defaultPrivilegedReason is what firewall_status/firewall_apply hand back
// as privileged_reason when a probe classifies this host as unprivileged —
// worded per the Product Owner's 2026-08-24 refinement on Card B: the UI
// (Card D) shows this verbatim to explain why a given host can't manage its
// own firewall, so it has to be a complete sentence, not a code.
const defaultPrivilegedReason = "aw-remote-host is not running as root and no NOPASSWD sudoers entry exists for iptables/nft — see this repo's README for the privileged-install prerequisite."

// classifyPrivilege turns a read-only probe command's own output/error into
// a privileged verdict. Deliberately NOT os.Getuid()==0 alone (Card B
// instructions) — capabilities and a sudoers NOPASSWD drop-in both grant
// real access without EUID 0, so the only trustworthy signal is whether the
// command itself was allowed to run.
func classifyPrivilege(out string, err error) (privileged bool, reason string) {
	if err == nil {
		return true, ""
	}
	msg := strings.ToLower(out + " " + err.Error())
	if strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "eperm") {
		return false, defaultPrivilegedReason
	}
	// Some other failure (binary races, an unexpected kernel module state,
	// etc.) — can't positively confirm privilege, so default to false rather
	// than guess true, but surface the real error instead of the generic
	// sudoers message so it's actually diagnosable.
	return false, "could not determine firewall privilege: " + strings.TrimSpace(err.Error())
}

// splitLines turns a command's multi-line stdout into a clean []string for
// State.Chain, dropping empty trailing lines.
func splitLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
